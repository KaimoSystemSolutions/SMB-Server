namespace Smb.FileSystem.Versioning;

/// <summary>
/// An <see cref="IFileStore"/> that retains previous file versions as snapshots and exposes them
/// for <c>FSCTL_SRV_ENUMERATE_SNAPSHOTS</c> (MS-SMB2 §2.2.32.2) and <c>@GMT-…</c> paths. The
/// times are UTC and are formatted by the server into <c>@GMT-…</c> tokens.
/// </summary>
public interface ISnapshotStore
{
    /// <summary>
    /// Snapshot times (UTC, ascending) for a share-relative path. An empty path (or the share
    /// root) returns the union of all snapshots (<see cref="GetAllSnapshots"/>).
    /// </summary>
    IReadOnlyList<DateTime> GetSnapshots(string path);

    /// <summary>All known snapshot times across all files (UTC, ascending, deduplicated).</summary>
    IReadOnlyList<DateTime> GetAllSnapshots();
}
