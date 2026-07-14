using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Claims;
using System.Security.Principal;
using Smb.Auth;
using Smb.Auth.Kerberos;
using Smb.Protocol.Enums;

namespace Smb.Auth.Sspi;

/// <summary>
/// <b>Turnkey Kerberos for Windows (docs/ENTERPRISE_HARDENING_ROADMAP.md, B1).</b> An
/// <see cref="IKerberosTicketValidator"/> backed by SSPI: it acquires an inbound server credential for the
/// <i>Kerberos</i> (or <i>Negotiate</i>) package once, then validates each AP-REQ with
/// <c>AcceptSecurityContext</c>, extracting the ticket <b>session key</b>
/// (<c>SECPKG_ATTR_SESSION_KEY</c> — the source of the SMB signing/encryption keys) and the caller's
/// identity (SID + group SIDs + UPN) from the resulting access token. Register it with the composite
/// <see cref="SpnegoNegotiator"/> (preferred over NTLM) via <see cref="SspiKerberos.CreateNegotiator"/>.
/// <para>
/// <b>Requirements:</b> a domain-joined host whose machine account (or the account under which the server
/// runs) owns the SMB service SPN (<c>cifs/host</c> / <c>HOST/host</c>). No secrets are handled in
/// managed code — ticket decryption stays inside LSA.
/// </para>
/// <para>
/// <b>Known limitation (v1):</b> the mutual-authentication <c>AP-REP</c> is not surfaced
/// (<see cref="KerberosValidationResult.ApRep"/> is left <c>null</c>, which the contract permits) — the
/// session key and identity are the parts SMB needs; a client that required mutual auth still completes.
/// This class is <b>Windows-only</b>; constructing it elsewhere throws
/// <see cref="PlatformNotSupportedException"/>.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SspiKerberosTicketValidator : IKerberosTicketValidator, IDisposable
{
    /// <summary>The <i>Negotiate</i> package accepts both Kerberos and (as a fallback) NTLM AP tokens.</summary>
    public const string NegotiatePackage = "Negotiate";

    /// <summary>The <i>Kerberos</i> package accepts Kerberos only — the strict choice for AD-only estates.</summary>
    public const string KerberosPackage = "Kerberos";

    private readonly object _gate = new();
    private SspiNative.SECURITY_HANDLE _credential;
    private bool _disposed;

    /// <summary>
    /// Acquires the inbound server credential for <paramref name="package"/> (default
    /// <see cref="KerberosPackage"/>). <paramref name="principal"/> pins a specific SPN/account; <c>null</c>
    /// uses the process's default (the machine account / the account the server runs as).
    /// </summary>
    public SspiKerberosTicketValidator(string package = KerberosPackage, string? principal = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("SspiKerberosTicketValidator requires Windows (SSPI).");
        ArgumentException.ThrowIfNullOrEmpty(package);

        int status = SspiNative.AcquireCredentialsHandle(
            principal, package, SspiNative.SECPKG_CRED_INBOUND,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref _credential, out _);
        if (status != SspiNative.SEC_E_OK)
            throw new SspiException($"AcquireCredentialsHandle('{package}') failed.", status);
    }

    /// <inheritdoc/>
    public KerberosValidationResult Validate(ReadOnlySpan<byte> apReq)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("SspiKerberosTicketValidator requires Windows (SSPI).");
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (apReq.IsEmpty)
            return KerberosValidationResult.Failed(NtStatus.InvalidParameter);

        // SSPI expects the GSS-API-framed mech token; the mechanism handed us the bare AP-REQ, so re-wrap it.
        byte[] gssToken = KerberosGssToken.WrapApReq(apReq);
        return AcceptSecurityContext(gssToken);
    }

    private KerberosValidationResult AcceptSecurityContext(byte[] gssToken)
    {
        var inputBuffer = new SspiNative.SecBuffer { cbBuffer = gssToken.Length, BufferType = SspiNative.SECBUFFER_TOKEN };
        var outputBuffer = new SspiNative.SecBuffer { BufferType = SspiNative.SECBUFFER_TOKEN };
        SspiNative.SECURITY_HANDLE context = default;
        bool contextEstablished = false;
        GCHandle pinnedToken = default;
        IntPtr pInput = IntPtr.Zero;
        IntPtr pOutput = IntPtr.Zero;
        try
        {
            pinnedToken = GCHandle.Alloc(gssToken, GCHandleType.Pinned);
            inputBuffer.pvBuffer = pinnedToken.AddrOfPinnedObject();

            pInput = Marshal.AllocHGlobal(Marshal.SizeOf<SspiNative.SecBuffer>());
            Marshal.StructureToPtr(inputBuffer, pInput, fDeleteOld: false);
            var inputDesc = new SspiNative.SecBufferDesc { ulVersion = SspiNative.SECBUFFER_VERSION, cBuffers = 1, pBuffers = pInput };

            pOutput = Marshal.AllocHGlobal(Marshal.SizeOf<SspiNative.SecBuffer>());
            Marshal.StructureToPtr(outputBuffer, pOutput, fDeleteOld: false);
            var outputDesc = new SspiNative.SecBufferDesc { ulVersion = SspiNative.SECBUFFER_VERSION, cBuffers = 1, pBuffers = pOutput };

            const uint contextReq =
                SspiNative.ASC_REQ_ALLOCATE_MEMORY | SspiNative.ASC_REQ_MUTUAL_AUTH |
                SspiNative.ASC_REQ_INTEGRITY | SspiNative.ASC_REQ_CONFIDENTIALITY |
                SspiNative.ASC_REQ_REPLAY_DETECT | SspiNative.ASC_REQ_SEQUENCE_DETECT;

            int status;
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                status = SspiNative.AcceptSecurityContext(
                    ref _credential, IntPtr.Zero, ref inputDesc, contextReq, SspiNative.SECURITY_NATIVE_DREP,
                    ref context, ref outputDesc, out _, out _);
            }
            contextEstablished = context.IsSet;

            // Free the SSPI-allocated output token (the AP-REP; not surfaced in v1).
            SspiNative.SecBuffer producedOut = Marshal.PtrToStructure<SspiNative.SecBuffer>(pOutput);
            if (producedOut.pvBuffer != IntPtr.Zero)
                SspiNative.FreeContextBuffer(producedOut.pvBuffer);

            if (status != SspiNative.SEC_E_OK)
                return KerberosValidationResult.Failed(MapStatus(status));

            byte[] sessionKey = ExtractSessionKey(ref context);
            SecurityIdentity identity = ExtractIdentity(ref context);
            return KerberosValidationResult.Succeeded(sessionKey, identity, apRep: null);
        }
        catch (SspiException)
        {
            return KerberosValidationResult.Failed(NtStatus.LogonFailure);
        }
        finally
        {
            if (contextEstablished) SspiNative.DeleteSecurityContext(ref context);
            if (pInput != IntPtr.Zero) Marshal.FreeHGlobal(pInput);
            if (pOutput != IntPtr.Zero) Marshal.FreeHGlobal(pOutput);
            if (pinnedToken.IsAllocated) pinnedToken.Free();
        }
    }

    private static byte[] ExtractSessionKey(ref SspiNative.SECURITY_HANDLE context)
    {
        var sk = new SspiNative.SecPkgContext_SessionKey();
        int status = SspiNative.QueryContextAttributes(ref context, SspiNative.SECPKG_ATTR_SESSION_KEY, ref sk);
        if (status != SspiNative.SEC_E_OK || sk.SessionKey == IntPtr.Zero || sk.SessionKeyLength == 0)
            throw new SspiException("QueryContextAttributes(SECPKG_ATTR_SESSION_KEY) failed.", status);
        try
        {
            var key = new byte[sk.SessionKeyLength];
            Marshal.Copy(sk.SessionKey, key, 0, key.Length);
            return key;
        }
        finally
        {
            SspiNative.FreeContextBuffer(sk.SessionKey);
        }
    }

    private static SecurityIdentity ExtractIdentity(ref SspiNative.SECURITY_HANDLE context)
    {
        int status = SspiNative.QuerySecurityContextToken(ref context, out IntPtr token);
        if (status != SspiNative.SEC_E_OK || token == IntPtr.Zero)
            throw new SspiException("QuerySecurityContextToken failed.", status);
        try
        {
            // WindowsIdentity(IntPtr) duplicates the token internally, so we close ours in the finally.
            using var windowsIdentity = new WindowsIdentity(token);
            (string domain, string user) = SplitAccount(windowsIdentity.Name);

            var groups = new List<string>();
            if (windowsIdentity.Groups is { } groupCollection)
                foreach (IdentityReference group in groupCollection)
                    groups.Add(group.Value);

            return new SecurityIdentity
            {
                DomainName = domain,
                UserName = user,
                UserPrincipalName = windowsIdentity.FindFirst(ClaimTypes.Upn)?.Value,
                UserSid = windowsIdentity.User?.Value,
                GroupSids = groups,
            };
        }
        finally
        {
            SspiNative.CloseHandle(token);
        }
    }

    /// <summary>Splits <c>DOMAIN\user</c> into its parts; an unqualified name yields an empty domain.</summary>
    private static (string Domain, string User) SplitAccount(string? accountName)
    {
        if (string.IsNullOrEmpty(accountName)) return (string.Empty, string.Empty);
        int slash = accountName.IndexOf('\\');
        return slash < 0
            ? (string.Empty, accountName)
            : (accountName[..slash], accountName[(slash + 1)..]);
    }

    private static NtStatus MapStatus(int sspiStatus) => (uint)sspiStatus switch
    {
        0x80090308 => NtStatus.InvalidParameter, // SEC_E_INVALID_TOKEN
        0x8009030C => NtStatus.LogonFailure,      // SEC_E_LOGON_DENIED
        0x80090302 => NtStatus.NotSupported,      // SEC_E_UNSUPPORTED_FUNCTION
        0x8009030D => NtStatus.LogonFailure,      // SEC_E_NO_CREDENTIALS
        _ => NtStatus.LogonFailure,
    };

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            if (_credential.IsSet && OperatingSystem.IsWindows())
                SspiNative.FreeCredentialsHandle(ref _credential);
        }
    }
}

/// <summary>Raised when an SSPI call returns a non-success status; carries the raw SSPI code.</summary>
public sealed class SspiException(string message, int statusCode) : Exception($"{message} (0x{statusCode:X8})")
{
    /// <summary>The raw SSPI return code (SEC_E_*).</summary>
    public int StatusCode { get; } = statusCode;
}
