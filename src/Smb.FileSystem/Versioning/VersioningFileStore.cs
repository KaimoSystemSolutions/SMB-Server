using System.Collections.Concurrent;
using Smb.Protocol.Enums;

namespace Smb.FileSystem.Versioning;

/// <summary>
/// <see cref="IFileStore"/> decorator that emulates "previous versions" (Windows Previous Versions /
/// VSS snapshots) on top of any backend store:
/// <list type="bullet">
/// <item>Before every overwrite of an existing file, its current content is captured as a version
/// with timestamp <c>now</c>.</item>
/// <item>A leading <c>@GMT-…</c> path segment addresses the version that was current at the snapshot
/// time — read-only (write/delete → <see cref="NtStatus.AccessDenied"/>).</item>
/// <item><see cref="ISnapshotStore"/> provides the times for
/// <c>FSCTL_SRV_ENUMERATE_SNAPSHOTS</c>.</item>
/// </list>
/// The history is kept in memory (per store instance) and is limited to <c>maxVersionsPerFile</c>
/// entries per file. It is suitable for tests/dev; a persistent snapshot provider can replace this
/// class later. As a decorator it forwards the async contract 1:1 to the inner store — an async
/// backend keeps its asynchrony, a sync backend completes synchronously.
/// </summary>
public sealed class VersioningFileStore : IFileStore, ISnapshotStore
{
    /// <summary>Upper bound for capturing a version in memory (protection against huge files).</summary>
    private const long MaxCaptureBytes = 64L * 1024 * 1024;

    private readonly IFileStore _inner;
    private readonly int _maxVersionsPerFile;
    private readonly ConcurrentDictionary<string, FileHistory> _history = new(StringComparer.OrdinalIgnoreCase);

    public VersioningFileStore(IFileStore inner, int maxVersionsPerFile = 64)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _maxVersionsPerFile = Math.Max(1, maxVersionsPerFile);
    }

    public async ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(
        string path, FileAccessIntent access, CreateDispositionIntent disposition,
        bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
    {
        // 1) Snapshot access: leading @GMT segment → serve the previous version read-only.
        if (GmtToken.TrySplitSnapshotPath(path, out DateTime snapAt, out string realPath))
        {
            bool wantsWrite = access.HasFlag(FileAccessIntent.Write) || access.HasFlag(FileAccessIntent.Delete)
                || disposition is CreateDispositionIntent.Create or CreateDispositionIntent.Overwrite
                    or CreateDispositionIntent.OverwriteIf or CreateDispositionIntent.Supersede;
            if (wantsWrite)
                return FileStoreResult<FileCreateResult>.Fail(NtStatus.AccessDenied); // snapshots are read-only.

            if (!TryResolveSnapshot(realPath, snapAt, out byte[] content, out FileEntryInfo info))
                return FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectNameNotFound);

            return FileStoreResult<FileCreateResult>.Ok(
                new FileCreateResult(new SnapshotFileHandle(realPath, content, info), CreateOutcome.Opened));
        }

        // 2) Normal path: capture the current version before an overwrite.
        bool overwrites = disposition is CreateDispositionIntent.Overwrite
            or CreateDispositionIntent.OverwriteIf or CreateDispositionIntent.Supersede;
        if (overwrites)
            await CaptureCurrentVersionAsync(path, cancellationToken).ConfigureAwait(false);

        return await _inner.CreateAsync(
            path, access, disposition, directoryRequired, nonDirectoryRequired, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask<FileStoreResult<int>> ReadAsync(
        IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        => handle is SnapshotFileHandle s
            ? new(s.Read(offset, buffer.Span))
            : _inner.ReadAsync(handle, offset, buffer, cancellationToken);

    public ValueTask<FileStoreResult<int>> WriteAsync(
        IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        => handle is SnapshotFileHandle
            ? new(FileStoreResult<int>.Fail(NtStatus.AccessDenied))
            : _inner.WriteAsync(handle, offset, data, cancellationToken);

    public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(
        IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
        => handle is SnapshotFileHandle
            ? new(FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(NtStatus.InvalidParameter))
            : _inner.QueryDirectoryAsync(handle, searchPattern, cancellationToken);

    public ValueTask<NtStatus> SetEndOfFileAsync(
        IFileHandle handle, long length, CancellationToken cancellationToken = default)
        => handle is SnapshotFileHandle
            ? new(NtStatus.AccessDenied)
            : _inner.SetEndOfFileAsync(handle, length, cancellationToken);

    public ValueTask<NtStatus> RenameAsync(
        IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default)
        => handle is SnapshotFileHandle
            ? new(NtStatus.AccessDenied)
            : _inner.RenameAsync(handle, newPath, replaceIfExists, cancellationToken);

    public async ValueTask<NtStatus> SetDeleteOnCloseAsync(
        IFileHandle handle, bool delete, CancellationToken cancellationToken = default)
    {
        if (handle is SnapshotFileHandle)
            return delete ? NtStatus.AccessDenied : NtStatus.Success;

        // Capture the last version before deletion (the file still exists here).
        if (delete && !handle.IsDirectory && !string.IsNullOrEmpty(handle.Path))
            await CaptureCurrentVersionAsync(handle.Path, cancellationToken).ConfigureAwait(false);

        return await _inner.SetDeleteOnCloseAsync(handle, delete, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default)
        => handle is SnapshotFileHandle
            ? new(NtStatus.Success)
            : _inner.FlushAsync(handle, cancellationToken);

    // --- ISnapshotStore ---

    public IReadOnlyList<DateTime> GetSnapshots(string path)
    {
        if (string.IsNullOrEmpty(path) || path is "\\" or "/")
            return GetAllSnapshots();
        return _history.TryGetValue(Normalize(path), out FileHistory? h) ? h.Times() : [];
    }

    public IReadOnlyList<DateTime> GetAllSnapshots()
    {
        var set = new SortedSet<DateTime>();
        foreach (FileHistory h in _history.Values)
            foreach (DateTime t in h.Times())
                set.Add(t);
        return [.. set];
    }

    // --- Internal ---

    /// <summary>Reads the current content of an existing file and stores it as a version.</summary>
    private async ValueTask CaptureCurrentVersionAsync(string path, CancellationToken cancellationToken)
    {
        (bool ok, byte[] content, FileEntryInfo? info) = await TryReadAllAsync(path, cancellationToken).ConfigureAwait(false);
        if (!ok)
            return; // file does not exist (yet) or is a directory → nothing to capture.

        FileHistory history = _history.GetOrAdd(Normalize(path), _ => new FileHistory());
        history.Add(new FileVersion(DateTime.UtcNow, content, info!), _maxVersionsPerFile);
    }

    /// <summary>Opens the file read-only via the backend and reads it fully into memory.</summary>
    private async ValueTask<(bool Ok, byte[] Content, FileEntryInfo? Info)> TryReadAllAsync(
        string path, CancellationToken cancellationToken)
    {
        FileStoreResult<FileCreateResult> opened = await _inner.CreateAsync(
            path, FileAccessIntent.Read, CreateDispositionIntent.Open,
            directoryRequired: false, nonDirectoryRequired: true, cancellationToken).ConfigureAwait(false);
        if (!opened.IsSuccess)
            return (false, [], null);

        IFileHandle handle = opened.Value.Handle;
        try
        {
            if (handle.IsDirectory)
                return (false, [], null);

            FileEntryInfo info = await handle.GetInfoAsync(cancellationToken).ConfigureAwait(false);
            long size = info.EndOfFile;
            if (size < 0 || size > MaxCaptureBytes)
                return (false, [], null);

            var buffer = new byte[size];
            int total = 0;
            while (total < size)
            {
                FileStoreResult<int> read = await _inner.ReadAsync(
                    handle, total, buffer.AsMemory(total), cancellationToken).ConfigureAwait(false);
                if (!read.IsSuccess)
                    return (false, [], null);
                if (read.Value == 0)
                    break;
                total += read.Value;
            }

            byte[] content = total == size ? buffer : buffer[..total];
            return (true, content, info);
        }
        finally
        {
            await handle.DisposeAsync().ConfigureAwait(false);
        }
    }

    private bool TryResolveSnapshot(string realPath, DateTime snapAt, out byte[] content, out FileEntryInfo info)
    {
        content = [];
        info = null!;
        if (string.IsNullOrEmpty(realPath) || !_history.TryGetValue(Normalize(realPath), out FileHistory? history))
            return false;

        FileVersion? version = history.ResolveAtOrAfter(snapAt);
        if (version is null)
            return false;

        content = version.Content;
        info = version.SnapshotInfo();
        return true;
    }

    private static string Normalize(string path) => (path ?? string.Empty).Replace('/', '\\').Trim('\\');

    // --- Data types ---

    private sealed record FileVersion(DateTime TimeUtc, byte[] Content, FileEntryInfo Original)
    {
        /// <summary>Metadata of the snapshot view: size from the captured content, read-only.</summary>
        public FileEntryInfo SnapshotInfo() => new()
        {
            Name = Original.Name,
            Attributes = (Original.Attributes | SmbFileAttributes.ReadOnly) & ~SmbFileAttributes.Normal,
            EndOfFile = Content.Length,
            AllocationSize = (Content.Length + 4095) / 4096 * 4096,
            CreationTime = Original.CreationTime,
            LastAccessTime = Original.LastAccessTime,
            LastWriteTime = Original.LastWriteTime,
            ChangeTime = Original.ChangeTime,
        };
    }

    /// <summary>Version history of a file (ascending by time, since entries are appended on overwrite).</summary>
    private sealed class FileHistory
    {
        private readonly object _gate = new();
        private readonly List<FileVersion> _versions = [];

        public void Add(FileVersion version, int max)
        {
            lock (_gate)
            {
                _versions.Add(version);
                if (_versions.Count > max)
                    _versions.RemoveRange(0, _versions.Count - max);
            }
        }

        /// <summary>
        /// Returns the version that was current at time <paramref name="t"/>: the first captured
        /// version whose (second-precision) timestamp is ≥ <paramref name="t"/>.
        /// </summary>
        public FileVersion? ResolveAtOrAfter(DateTime t)
        {
            DateTime floor = FloorToSecond(t);
            lock (_gate)
            {
                foreach (FileVersion v in _versions) // ascending
                    if (FloorToSecond(v.TimeUtc) >= floor)
                        return v;
                return null;
            }
        }

        public IReadOnlyList<DateTime> Times()
        {
            lock (_gate)
                return [.. _versions.Select(v => v.TimeUtc)];
        }

        private static DateTime FloorToSecond(DateTime t)
        {
            DateTime u = t.Kind == DateTimeKind.Utc ? t : t.ToUniversalTime();
            return new DateTime(u.Year, u.Month, u.Day, u.Hour, u.Minute, u.Second, DateTimeKind.Utc);
        }
    }
}

/// <summary>Read-only backend handle that serves the captured content of a previous version.</summary>
internal sealed class SnapshotFileHandle : IFileHandle
{
    private readonly byte[] _content;
    private readonly FileEntryInfo _info;

    public SnapshotFileHandle(string path, byte[] content, FileEntryInfo info)
    {
        Path = path;
        _content = content;
        _info = info;
    }

    public string Path { get; }
    public bool IsDirectory => false;
    public FileEntryInfo GetInfo() => _info;

    public FileStoreResult<int> Read(long offset, Span<byte> buffer)
    {
        if (offset < 0 || offset >= _content.Length)
            return FileStoreResult<int>.Ok(0); // EOF
        int n = Math.Min(buffer.Length, _content.Length - (int)offset);
        _content.AsSpan((int)offset, n).CopyTo(buffer);
        return FileStoreResult<int>.Ok(n);
    }

    public void Dispose() { }
}
