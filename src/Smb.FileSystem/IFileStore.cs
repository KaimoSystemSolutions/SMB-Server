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
    /// Async variant of <see cref="GetInfo"/>. Defaults to the synchronous call — backends whose
    /// metadata lookup does real I/O (remote/cloud stores) should override this.
    /// </summary>
    ValueTask<FileEntryInfo> GetInfoAsync(CancellationToken cancellationToken = default)
        => new(GetInfo());

    /// <summary>
    /// Async close. Defaults to <see cref="IDisposable.Dispose"/> — backends whose close path
    /// does real I/O (e.g. DELETE_ON_CLOSE against a remote store) should override this.
    /// The server calls this variant; <c>Dispose</c> remains the synchronous fallback.
    /// </summary>
    ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Real path in the underlying file system — for CHANGE_NOTIFY watchers, OS locks, etc. that
    /// need a real path. <c>null</c> if the backend has none (virtual/in-memory).
    /// </summary>
    string? PhysicalPath => null;
}

/// <summary>Result payload of <see cref="IFileStore.CreateAsync"/>: opened handle + what happened.</summary>
public readonly record struct FileCreateResult(IFileHandle Handle, CreateOutcome Action);

/// <summary>
/// NTFS-semantic file backend behind a share (Context §2, §13). Returns NT status codes; a concrete
/// backend (local FS, virtual, …) maps its semantics onto this. Paths are share-relative,
/// '\\'-separated, without a leading backslash.
/// <para>
/// The contract is async-first (<see cref="ValueTask"/>): backends that are natively asynchronous
/// (network/cloud storage, databases) implement it directly without sync-over-async; purely
/// synchronous backends derive from <see cref="SyncFileStore"/> and keep their Span-based code.
/// </para>
/// </summary>
public interface IFileStore
{
    /// <summary>Opens/creates per CreateDisposition. <see cref="FileCreateResult.Action"/> reports what happened.</summary>
    ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(
        string path,
        FileAccessIntent access,
        CreateDispositionIntent disposition,
        bool directoryRequired,
        bool nonDirectoryRequired,
        CancellationToken cancellationToken = default);

    /// <summary>Reads from an open handle.</summary>
    ValueTask<FileStoreResult<int>> ReadAsync(
        IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default);

    /// <summary>Writes to an open handle, returns the number of bytes written.</summary>
    ValueTask<FileStoreResult<int>> WriteAsync(
        IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);

    /// <summary>Lists a directory (optionally with a wildcard search pattern).</summary>
    ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(
        IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default);

    /// <summary>Sets the file size (SET FileEndOfFileInformation).</summary>
    ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default);

    /// <summary>Renames/moves (SET FileRenameInformation).</summary>
    ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default);

    /// <summary>Marks for deletion on close (SET FileDispositionInformation / DELETE_ON_CLOSE).</summary>
    ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default);

    /// <summary>Flushes buffers to the backend.</summary>
    ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the security descriptor of an open handle (QUERY_INFO / InfoType Security, Phase 3).
    /// Defaults to <see cref="NtStatus.NotSupported"/> — backends that carry per-file ACLs override it.
    /// The caller selects which components to return via the request's SECURITY_INFORMATION flags.
    /// </summary>
    ValueTask<FileStoreResult<Smb.Protocol.Security.SecurityDescriptor>> GetSecurityAsync(
        IFileHandle handle, CancellationToken cancellationToken = default)
        => new(FileStoreResult<Smb.Protocol.Security.SecurityDescriptor>.Fail(NtStatus.NotSupported));

    /// <summary>
    /// Stores the security descriptor of an open handle (SET_INFO / InfoType Security, Phase 3).
    /// Defaults to <see cref="NtStatus.NotSupported"/>. The dispatcher passes the already-merged
    /// descriptor (existing descriptor with the requested SECURITY_INFORMATION components replaced).
    /// </summary>
    ValueTask<NtStatus> SetSecurityAsync(
        IFileHandle handle, Smb.Protocol.Security.SecurityDescriptor descriptor, CancellationToken cancellationToken = default)
        => new(NtStatus.NotSupported);
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
