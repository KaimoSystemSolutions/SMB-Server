namespace Smb.Server.Authorization;

/// <summary>
/// NT access mask bits (Context §13.1, MS-DTYP ACCESS_MASK). Used as the granted access mask
/// (MaximalAccess) at TREE_CONNECT/CREATE — clients respect this mask.
/// </summary>
[Flags]
public enum SmbAccessMask : uint
{
    None = 0x00000000,

    FileReadData = 0x00000001,
    FileWriteData = 0x00000002,
    FileAppendData = 0x00000004,
    FileReadEa = 0x00000008,
    FileWriteEa = 0x00000010,
    FileExecute = 0x00000020,
    FileDeleteChild = 0x00000040,
    FileReadAttributes = 0x00000080,
    FileWriteAttributes = 0x00000100,

    Delete = 0x00010000,
    ReadControl = 0x00020000,
    WriteDac = 0x00040000,
    WriteOwner = 0x00080000,
    Synchronize = 0x00100000,

    MaximumAllowed = 0x02000000,
    GenericAll = 0x10000000,
    GenericExecute = 0x20000000,
    GenericWrite = 0x40000000,
    GenericRead = 0x80000000,

    /// <summary>Full access (FILE_ALL_ACCESS = 0x001F01FF).</summary>
    FullAccess =
        FileReadData | FileWriteData | FileAppendData | FileReadEa | FileWriteEa |
        FileExecute | FileDeleteChild | FileReadAttributes | FileWriteAttributes |
        Delete | ReadControl | WriteDac | WriteOwner | Synchronize,

    /// <summary>Read-only access (read + attributes + execute + ReadControl + Synchronize).</summary>
    ReadOnly =
        FileReadData | FileReadEa | FileReadAttributes | FileExecute |
        ReadControl | Synchronize,

    /// <summary>Read and write (no delete/no ACL modification).</summary>
    ReadWrite =
        FileReadData | FileWriteData | FileAppendData | FileReadEa | FileWriteEa |
        FileReadAttributes | FileWriteAttributes | FileExecute | ReadControl | Synchronize,
}
