using Smb.Protocol.Enums;

namespace Smb.Auth.Kerberos;

/// <summary>
/// Outcome of validating a Kerberos AP-REQ (M2.1). On success it carries the ticket's session key
/// (used as the SMB GSS session key, Context §8.3), the resolved <see cref="SecurityIdentity"/>
/// (from the PAC / directory) and, optionally, a raw AP-REP for mutual authentication.
/// </summary>
public sealed class KerberosValidationResult
{
    public required NtStatus Status { get; init; }

    /// <summary>Ticket session (sub-)key — the source of the SMB signing/encryption keys. Only on success.</summary>
    public byte[]? SessionKey { get; init; }

    /// <summary>Authenticated identity (UPN, SID, group SIDs from the PAC). Only on success.</summary>
    public SecurityIdentity? Identity { get; init; }

    /// <summary>
    /// Raw KRB_AP_REP for mutual authentication (without the GSS-API framing — the mechanism adds it).
    /// Leave <c>null</c> when the client did not request mutual auth or the platform does not surface it.
    /// </summary>
    public byte[]? ApRep { get; init; }

    public bool IsSuccess => Status == NtStatus.Success;

    public static KerberosValidationResult Succeeded(byte[] sessionKey, SecurityIdentity identity, byte[]? apRep = null)
        => new() { Status = NtStatus.Success, SessionKey = sessionKey, Identity = identity, ApRep = apRep };

    public static KerberosValidationResult Failed(NtStatus status = NtStatus.LogonFailure)
        => new() { Status = status };
}

/// <summary>
/// <b>Kerberos extension seam (M2.1).</b> Validates a Kerberos AP-REQ and returns the session key and
/// identity. This is the single place a library user plugs in real Kerberos: the framework's
/// <see cref="KerberosServerMechanism"/> handles the GSS/SPNEGO token framing and the SMB integration,
/// while ticket decryption, authenticator verification and PAC extraction live behind this interface.
/// Typical implementations:
/// <list type="bullet">
/// <item>Windows: wrap SSPI (<c>AcceptSecurityContext</c> with the <i>Kerberos</i> package) and read the
/// session key via <c>QueryContextAttributes(SECPKG_ATTR_SESSION_KEY)</c>.</item>
/// <item>Linux: wrap MIT/Heimdal GSSAPI (<c>gss_accept_sec_context</c>) with a keytab.</item>
/// <item>Tests / custom KDCs: implement directly or use <see cref="DelegatingKerberosTicketValidator"/>.</item>
/// </list>
/// The AP-REQ passed in is the mechanism token <i>without</i> the outer GSS-API wrapper (that framing is
/// stripped by <see cref="KerberosServerMechanism"/>).
/// </summary>
public interface IKerberosTicketValidator
{
    /// <summary>Validates the AP-REQ (ticket + authenticator) and resolves the caller's identity.</summary>
    KerberosValidationResult Validate(ReadOnlySpan<byte> apReq);
}

/// <summary>
/// Adapts a plain function to <see cref="IKerberosTicketValidator"/> — convenient for wiring a lambda,
/// a closure over an SSPI/GSSAPI call, or a test double without declaring a class.
/// </summary>
public sealed class DelegatingKerberosTicketValidator : IKerberosTicketValidator
{
    /// <summary>Validation callback (a <see cref="ReadOnlySpan{T}"/> cannot be captured, so it is a parameter).</summary>
    public delegate KerberosValidationResult ValidateCallback(ReadOnlySpan<byte> apReq);

    private readonly ValidateCallback _validate;

    public DelegatingKerberosTicketValidator(ValidateCallback validate)
        => _validate = validate ?? throw new ArgumentNullException(nameof(validate));

    public KerberosValidationResult Validate(ReadOnlySpan<byte> apReq) => _validate(apReq);
}
