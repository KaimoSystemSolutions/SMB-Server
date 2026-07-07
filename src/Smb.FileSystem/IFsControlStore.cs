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
