using Smb.Protocol.Enums;

namespace Smb.FileSystem;

/// <summary>
/// One data stream of a file (Phase 9 / M9.1). <see cref="Name"/> is the bare stream name; the empty
/// string denotes the default unnamed <c>$DATA</c> stream (the file's primary content).
/// </summary>
public readonly record struct StreamInfo(string Name, long Size, long AllocationSize);

/// <summary>
/// Optional backend capability for NTFS-style alternate data streams (Phase 9 / M9.1). A backend that
/// implements this can open named data streams (<c>file.txt:stream</c>) and enumerate the streams of a
/// file for FileStreamInformation. Checked with <c>is</c> by the dispatcher — a store that does not
/// implement it rejects stream opens with <c>STATUS_NOT_SUPPORTED</c> and reports only the default
/// <c>::$DATA</c> stream. This is the seam a deployment maps onto real NTFS ADS (Windows) or
/// xattr/sidecar files (Linux/ZFS).
/// </summary>
public interface INamedStreamStore
{
    /// <summary>
    /// Lists the data streams of the file behind <paramref name="handle"/> (which may itself be a base
    /// file handle or a stream handle of the same file). The default unnamed stream is included for a
    /// regular file; a directory has none.
    /// </summary>
    ValueTask<FileStoreResult<IReadOnlyList<StreamInfo>>> QueryStreamsAsync(
        IFileHandle handle, CancellationToken cancellationToken = default);

    /// <summary>
    /// Opens (per <paramref name="disposition"/>) the named data stream <paramref name="streamName"/> of
    /// the base file <paramref name="basePath"/>. The returned handle flows through the normal
    /// READ/WRITE/SET_INFO path, so subsequent I/O targets the stream's content.
    /// </summary>
    ValueTask<FileStoreResult<FileCreateResult>> OpenNamedStreamAsync(
        string basePath, string streamName, FileAccessIntent access, CreateDispositionIntent disposition,
        CancellationToken cancellationToken = default);
}
