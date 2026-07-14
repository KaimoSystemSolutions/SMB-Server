using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Smb.Auth.Sspi;

/// <summary>
/// P/Invoke surface for the Windows SSPI functions used by <see cref="SspiKerberosTicketValidator"/>
/// (secur32.dll — MS-SPNG / SSPI). Kept internal; all call sites are Windows-guarded.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class SspiNative
{
    // Credential use.
    public const int SECPKG_CRED_INBOUND = 0x00000001;

    // Target data representation.
    public const uint SECURITY_NATIVE_DREP = 0x00000010;

    // AcceptSecurityContext context requirements.
    public const uint ASC_REQ_REPLAY_DETECT = 0x00000004;
    public const uint ASC_REQ_SEQUENCE_DETECT = 0x00000008;
    public const uint ASC_REQ_CONFIDENTIALITY = 0x00000010;
    public const uint ASC_REQ_ALLOCATE_MEMORY = 0x00000100;
    public const uint ASC_REQ_INTEGRITY = 0x00020000;
    public const uint ASC_REQ_MUTUAL_AUTH = 0x00000002;

    // SecBuffer types / versions.
    public const int SECBUFFER_VERSION = 0;
    public const int SECBUFFER_TOKEN = 2;

    // QueryContextAttributes attribute ids.
    public const uint SECPKG_ATTR_SESSION_KEY = 9;

    // Return codes.
    public const int SEC_E_OK = 0x00000000;
    public const int SEC_I_CONTINUE_NEEDED = 0x00090312;
    public const int SEC_I_COMPLETE_NEEDED = 0x00090313;
    public const int SEC_I_COMPLETE_AND_CONTINUE = 0x00090314;

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_HANDLE
    {
        public IntPtr dwLower;
        public IntPtr dwUpper;
        public readonly bool IsSet => dwLower != IntPtr.Zero || dwUpper != IntPtr.Zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_INTEGER
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBuffer
    {
        public int cbBuffer;
        public int BufferType;
        public IntPtr pvBuffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBufferDesc
    {
        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_SessionKey
    {
        public uint SessionKeyLength;
        public IntPtr SessionKey;
    }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    public static extern int AcquireCredentialsHandle(
        string? pszPrincipal, string pszPackage, int fCredentialUse,
        IntPtr pvLogonID, IntPtr pAuthData, IntPtr pGetKeyFn, IntPtr pvGetKeyArgument,
        ref SECURITY_HANDLE phCredential, out SECURITY_INTEGER ptsExpiry);

    [DllImport("secur32.dll", SetLastError = false)]
    public static extern int AcceptSecurityContext(
        ref SECURITY_HANDLE phCredential, IntPtr phContext,
        ref SecBufferDesc pInput, uint fContextReq, uint TargetDataRep,
        ref SECURITY_HANDLE phNewContext, ref SecBufferDesc pOutput,
        out uint pfContextAttr, out SECURITY_INTEGER ptsExpiry);

    [DllImport("secur32.dll", SetLastError = false)]
    public static extern int QueryContextAttributes(
        ref SECURITY_HANDLE phContext, uint ulAttribute, ref SecPkgContext_SessionKey pBuffer);

    [DllImport("secur32.dll", SetLastError = false)]
    public static extern int QuerySecurityContextToken(ref SECURITY_HANDLE phContext, out IntPtr phToken);

    [DllImport("secur32.dll", SetLastError = false)]
    public static extern int DeleteSecurityContext(ref SECURITY_HANDLE phContext);

    [DllImport("secur32.dll", SetLastError = false)]
    public static extern int FreeCredentialsHandle(ref SECURITY_HANDLE phCredential);

    [DllImport("secur32.dll", SetLastError = false)]
    public static extern int FreeContextBuffer(IntPtr pvContextBuffer);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);
}
