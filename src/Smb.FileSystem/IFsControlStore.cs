using Smb.Protocol.Enums;
using Smb.Protocol.Messages;

namespace Smb.FileSystem;

/// <summary>
/// An <see cref="IFileStore"/> that supports sparse-file FSCTLs (Phase 5 / M5.2): marking a file
/// sparse, zeroing (deallocating) a byte range, and reporting the allocated extents. A backend opts
/// in by implementing this interface; the dispatcher checks for it with <c>is</c> (the same pattern as
/// <see cref="Versioning.ISnapshotStore"/>) and answers <c>STATUS_NOT_SUPPORTED</c> otherwise.
/// All ranges are byte offsets/lengths within the file.
/// </summary>
public interface ISparseFileStore
{
    /// <summary>FSCTL_SET_SPARSE (MS-FSCC §2.3.68): marks (or clears) the sparse attribute.</summary>
    ValueTask<NtStatus> SetSparseAsync(IFileHandle handle, bool sparse, CancellationToken cancellationToken = default);

    /// <summary>
    /// FSCTL_SET_ZERO_DATA (MS-FSCC §2.3.79): zeroes <paramref name="length"/> bytes from
    /// <paramref name="offset"/>. On a sparse file the range may be deallocated instead of written.
    /// </summary>
    ValueTask<NtStatus> SetZeroDataAsync(IFileHandle handle, long offset, long length, CancellationToken cancellationToken = default);

    /// <summary>
    /// FSCTL_QUERY_ALLOCATED_RANGES (MS-FSCC §2.3.34): returns the allocated (non-hole) sub-ranges
    /// that intersect the queried [offset, offset+length) window, ascending.
    /// </summary>
    ValueTask<FileStoreResult<IReadOnlyList<FsctlMessage.FileRange>>> QueryAllocatedRangesAsync(
        IFileHandle handle, long offset, long length, CancellationToken cancellationToken = default);
}

/// <summary>
/// An <see cref="IFileStore"/> that supports reparse points (Phase 5 / M5.2): symlinks, mount
/// points and other NTFS reparse tags. The reparse data buffer (MS-FSCC §2.1.2) is opaque to the
/// server — the backend owns its interpretation. Opt in like <see cref="ISparseFileStore"/>.
/// </summary>
public interface IReparsePointStore
{
    /// <summary>
    /// FSCTL_GET_REPARSE_POINT (MS-FSCC §2.3.26): returns the raw reparse data buffer, or
    /// <c>STATUS_NOT_A_REPARSE_POINT</c> when the file carries none.
    /// </summary>
    ValueTask<FileStoreResult<byte[]>> GetReparsePointAsync(IFileHandle handle, CancellationToken cancellationToken = default);

    /// <summary>FSCTL_SET_REPARSE_POINT (MS-FSCC §2.3.65): stores the raw reparse data buffer on the file.</summary>
    ValueTask<NtStatus> SetReparsePointAsync(IFileHandle handle, byte[] reparseData, CancellationToken cancellationToken = default);

    /// <summary>FSCTL_DELETE_REPARSE_POINT (MS-FSCC §2.3.5): removes the reparse point.</summary>
    ValueTask<NtStatus> DeleteReparsePointAsync(IFileHandle handle, byte[] reparseData, CancellationToken cancellationToken = default);
}

/// <summary>
/// An <see cref="IFileStore"/> that reports symbolic links encountered during CREATE path resolution
/// (Phase 11 / M11.2). When a component of the requested path is a symlink the server does not silently
/// follow it — it returns <c>STATUS_STOPPED_ON_SYMLINK</c> with a SYMLINK_ERROR_RESPONSE (MS-SMB2
/// §2.2.2.2.1) so the client decides whether to follow the link. Opt in like <see cref="IReparsePointStore"/>;
/// the dispatcher checks for it with <c>is</c> and never stops on a symlink for a backend that omits it.
/// A CREATE with <c>FILE_OPEN_REPARSE_POINT</c> opens the link itself and is not intercepted.
/// </summary>
public interface ISymlinkResolver
{
    /// <summary>
    /// Resolves <paramref name="path"/> far enough to detect a symlink. Returns the symlink target
    /// when a component of the path is a symbolic link that stops resolution; <c>null</c> to resolve
    /// the path normally (no symlink, or the link is the final component that the caller opens directly).
    /// </summary>
    ValueTask<SymlinkTarget?> ResolveSymlinkAsync(string path, CancellationToken cancellationToken = default);
}

/// <summary>
/// The target of a symbolic link encountered during path resolution (Phase 11 / M11.2), used to build the
/// SYMLINK_ERROR_RESPONSE (MS-SMB2 §2.2.2.2.1). The substitute/print names are the link's stored targets
/// (backend-defined form, e.g. <c>\??\C:\dir</c> for an absolute link or <c>..\peer</c> for a relative one).
/// </summary>
/// <param name="SubstituteName">The name used for internal resolution (the reparse SubstituteName).</param>
/// <param name="PrintName">The human-readable target; defaults to <paramref name="SubstituteName"/> when null.</param>
/// <param name="UnparsedPathLength">
/// Bytes (UTF-16) of the requested path that follow the symlink component and were not consumed. Zero when
/// the whole path resolves to the link itself.
/// </param>
/// <param name="IsRelative">True to set SYMLINK_FLAG_RELATIVE (a target relative to the link's directory).</param>
public readonly record struct SymlinkTarget(
    string SubstituteName,
    string? PrintName,
    int UnparsedPathLength,
    bool IsRelative);
