using Smb.Protocol.Enums;

namespace Smb.FileSystem;

/// <summary>
/// Backend handle of an open file/directory (corresponds to <c>Open.LocalOpen</c>, Context §19).
/// Its lifecycle is tied to the SMB <c>Open</c>.
/// </summary>
public interface IFileHandle : IDisposable
{
    string Path { get; }
    bool IsDirectory { get; }
    FileEntryInfo GetInfo();

    /// <summary>
    /// Real path in the underlying file system — for CHANGE_NOTIFY watchers, OS locks, etc. that
    /// need a real path. <c>null</c> if the backend has none (virtual/in-memory).
    /// </summary>
    string? PhysicalPath => null;
}

/// <summary>
/// NTFS-semantic file backend behind a share (Context §2, §13). Returns NT status codes; a concrete
/// backend (local FS, virtual, …) maps its semantics onto this. Paths are share-relative,
/// '\\'-separated, without a leading backslash.
/// </summary>
public interface IFileStore
{
    /// <summary>Opens/creates per CreateDisposition. <paramref name="createAction"/> reports what happened.</summary>
    FileStoreResult<IFileHandle> Create(
        string path,
        FileAccessIntent access,
        CreateDispositionIntent disposition,
        bool directoryRequired,
        bool nonDirectoryRequired,
        out CreateOutcome createAction);

    /// <summary>Reads from an open handle.</summary>
    FileStoreResult<int> Read(IFileHandle handle, long offset, Span<byte> buffer);

    /// <summary>Writes to an open handle, returns the number of bytes written.</summary>
    FileStoreResult<int> Write(IFileHandle handle, long offset, ReadOnlySpan<byte> data);

    /// <summary>Lists a directory (optionally with a wildcard search pattern).</summary>
    FileStoreResult<IReadOnlyList<FileEntryInfo>> QueryDirectory(IFileHandle handle, string searchPattern);

    /// <summary>Sets the file size (SET FileEndOfFileInformation).</summary>
    NtStatus SetEndOfFile(IFileHandle handle, long length);

    /// <summary>Renames/moves (SET FileRenameInformation).</summary>
    NtStatus Rename(IFileHandle handle, string newPath, bool replaceIfExists);

    /// <summary>Marks for deletion on close (SET FileDispositionInformation / DELETE_ON_CLOSE).</summary>
    NtStatus SetDeleteOnClose(IFileHandle handle, bool delete);

    /// <summary>Flushes buffers to the backend.</summary>
    NtStatus Flush(IFileHandle handle);
}

/// <summary>Simplified access intent (derived from CREATE DesiredAccess, Context §13.1).</summary>
[Flags]
public enum FileAccessIntent
{
    None = 0,
    Read = 1,
    Write = 2,
    Delete = 4,
    ReadWrite = Read | Write,
}

/// <summary>CreateDisposition intent (Context §13).</summary>
public enum CreateDispositionIntent
{
    Supersede = 0,
    Open = 1,
    Create = 2,
    OpenIf = 3,
    Overwrite = 4,
    OverwriteIf = 5,
}

/// <summary>CreateAction of the response (Context §13.3).</summary>
public enum CreateOutcome
{
    Superseded = 0,
    Opened = 1,
    Created = 2,
    Overwritten = 3,
}
