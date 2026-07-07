namespace Smb.Protocol.Security;

/// <summary>
/// Access-mask bits for files/directories (MS-SMB2 §2.2.13.1.1 / MS-DTYP §2.4.3). Combined into the
/// <c>AccessMask</c> of an ACE and the <c>DesiredAccess</c> of a CREATE.
/// </summary>
public static class AccessMask
{
    public const uint FileReadData = 0x00000001;
    public const uint FileWriteData = 0x00000002;
    public const uint FileAppendData = 0x00000004;
    public const uint FileReadEa = 0x00000008;
    public const uint FileWriteEa = 0x00000010;
    public const uint FileExecute = 0x00000020;
    public const uint FileDeleteChild = 0x00000040;
    public const uint FileReadAttributes = 0x00000080;
    public const uint FileWriteAttributes = 0x00000100;

    public const uint Delete = 0x00010000;
    public const uint ReadControl = 0x00020000;
    public const uint WriteDac = 0x00040000;
    public const uint WriteOwner = 0x00080000;
    public const uint Synchronize = 0x00100000;

    public const uint MaximumAllowed = 0x02000000;

    public const uint GenericAll = 0x10000000;
    public const uint GenericExecute = 0x20000000;
    public const uint GenericWrite = 0x40000000;
    public const uint GenericRead = 0x80000000;

    /// <summary>Any bit that lets a caller modify file content (write or append).</summary>
    public const uint WriteAccess = FileWriteData | FileAppendData;
}
