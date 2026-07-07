using Smb.Protocol.Enums;

namespace Smb.FileSystem;

/// <summary>
/// Base class for purely synchronous backends: implements the async-first <see cref="IFileStore"/>
/// contract on top of the classic Span-based synchronous operations. Derive from this when the
/// backend does no true async I/O (local FS, in-memory) — the <see cref="ValueTask"/> chain then
/// completes synchronously without any thread hops.
/// The async methods are <c>virtual</c> so that individual operations (typically Read/Write) can
/// be overridden with genuinely asynchronous implementations later.
/// </summary>
public abstract class SyncFileStore : IFileStore
{
    /// <inheritdoc cref="IFileStore.CreateAsync"/>
    protected abstract FileStoreResult<IFileHandle> Create(
        string path,
        FileAccessIntent access,
        CreateDispositionIntent disposition,
        bool directoryRequired,
        bool nonDirectoryRequired,
        out CreateOutcome createAction);

    /// <inheritdoc cref="IFileStore.ReadAsync"/>
    protected abstract FileStoreResult<int> Read(IFileHandle handle, long offset, Span<byte> buffer);

    /// <inheritdoc cref="IFileStore.WriteAsync"/>
    protected abstract FileStoreResult<int> Write(IFileHandle handle, long offset, ReadOnlySpan<byte> data);

    /// <inheritdoc cref="IFileStore.QueryDirectoryAsync"/>
    protected abstract FileStoreResult<IReadOnlyList<FileEntryInfo>> QueryDirectory(IFileHandle handle, string searchPattern);

    /// <inheritdoc cref="IFileStore.SetEndOfFileAsync"/>
    protected abstract NtStatus SetEndOfFile(IFileHandle handle, long length);

    /// <inheritdoc cref="IFileStore.RenameAsync"/>
    protected abstract NtStatus Rename(IFileHandle handle, string newPath, bool replaceIfExists);

    /// <inheritdoc cref="IFileStore.SetDeleteOnCloseAsync"/>
    protected abstract NtStatus SetDeleteOnClose(IFileHandle handle, bool delete);

    /// <inheritdoc cref="IFileStore.FlushAsync"/>
    protected abstract NtStatus Flush(IFileHandle handle);

    public virtual ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(
        string path, FileAccessIntent access, CreateDispositionIntent disposition,
        bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
    {
        FileStoreResult<IFileHandle> result = Create(
            path, access, disposition, directoryRequired, nonDirectoryRequired, out CreateOutcome action);
        return new(result.IsSuccess
            ? FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(result.Value!, action))
            : FileStoreResult<FileCreateResult>.Fail(result.Status));
    }

    public virtual ValueTask<FileStoreResult<int>> ReadAsync(
        IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        => new(Read(handle, offset, buffer.Span));

    public virtual ValueTask<FileStoreResult<int>> WriteAsync(
        IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        => new(Write(handle, offset, data.Span));

    public virtual ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(
        IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
        => new(QueryDirectory(handle, searchPattern));

    public virtual ValueTask<NtStatus> SetEndOfFileAsync(
        IFileHandle handle, long length, CancellationToken cancellationToken = default)
        => new(SetEndOfFile(handle, length));

    public virtual ValueTask<NtStatus> RenameAsync(
        IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default)
        => new(Rename(handle, newPath, replaceIfExists));

    public virtual ValueTask<NtStatus> SetDeleteOnCloseAsync(
        IFileHandle handle, bool delete, CancellationToken cancellationToken = default)
        => new(SetDeleteOnClose(handle, delete));

    public virtual ValueTask<NtStatus> FlushAsync(
        IFileHandle handle, CancellationToken cancellationToken = default)
        => new(Flush(handle));

    public virtual ValueTask<FileStoreResult<Smb.Protocol.Security.SecurityDescriptor>> GetSecurityAsync(
        IFileHandle handle, CancellationToken cancellationToken = default)
        => new(FileStoreResult<Smb.Protocol.Security.SecurityDescriptor>.Fail(NtStatus.NotSupported));

    public virtual ValueTask<NtStatus> SetSecurityAsync(
        IFileHandle handle, Smb.Protocol.Security.SecurityDescriptor descriptor, CancellationToken cancellationToken = default)
        => new(NtStatus.NotSupported);
}
