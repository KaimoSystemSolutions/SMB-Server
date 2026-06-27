using Smb.Protocol.Enums;

namespace Smb.FileSystem;

/// <summary>Share type (Context §12, MS-SMB2 §2.2.10).</summary>
public enum ShareType : byte
{
    Disk = 0x01,
    Pipe = 0x02,  // IPC$
    Print = 0x03,
}

/// <summary>NTFS file attributes (Context §16, MS-FSCC §2.6).</summary>
[Flags]
public enum SmbFileAttributes : uint
{
    None = 0x00000000,
    ReadOnly = 0x00000001,
    Hidden = 0x00000002,
    System = 0x00000004,
    Directory = 0x00000010,
    Archive = 0x00000020,
    Normal = 0x00000080,
    Temporary = 0x00000100,
    Sparse = 0x00000200,
    ReparsePoint = 0x00000400,
    Compressed = 0x00000800,
    Offline = 0x00001000,
    NotContentIndexed = 0x00002000,
    Encrypted = 0x00004000,
}

/// <summary>Metadata of a file/directory entry (for CREATE/QUERY_INFO/QUERY_DIRECTORY).</summary>
public sealed class FileEntryInfo
{
    public required string Name { get; init; }
    public SmbFileAttributes Attributes { get; init; }
    public long EndOfFile { get; init; }
    public long AllocationSize { get; init; }

    /// <summary>FILETIME values (100-ns since 1601-01-01 UTC, Context §17).</summary>
    public long CreationTime { get; init; }
    public long LastAccessTime { get; init; }
    public long LastWriteTime { get; init; }
    public long ChangeTime { get; init; }

    public bool IsDirectory => Attributes.HasFlag(SmbFileAttributes.Directory);
}

/// <summary>Result of a backend operation: NTSTATUS + optional payload.</summary>
public readonly struct FileStoreResult<T>
{
    public NtStatus Status { get; }
    public T? Value { get; }
    public bool IsSuccess => Status == NtStatus.Success;

    private FileStoreResult(NtStatus status, T? value)
    {
        Status = status;
        Value = value;
    }

    public static FileStoreResult<T> Ok(T value) => new(NtStatus.Success, value);
    public static FileStoreResult<T> Fail(NtStatus status) => new(status, default);
}
