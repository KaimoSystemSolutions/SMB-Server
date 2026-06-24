using System.Collections.Concurrent;
using Smb.Protocol.Enums;

namespace Smb.FileSystem.Versioning;

/// <summary>
/// <see cref="IFileStore"/>-Decorator, der „Vorherige Versionen" (Windows Previous Versions /
/// VSS-Snapshots) über einem beliebigen Backend-Store nachbildet:
/// <list type="bullet">
/// <item>Vor jedem Überschreiben einer existierenden Datei wird ihr aktueller Inhalt als
/// Version mit Zeitstempel <c>now</c> festgehalten.</item>
/// <item>Ein führendes <c>@GMT-…</c>-Pfadsegment adressiert die Version, die zum Snapshot-
/// Zeitpunkt aktuell war — read-only (Schreiben/Löschen → <see cref="NtStatus.AccessDenied"/>).</item>
/// <item><see cref="ISnapshotStore"/> stellt die Zeitpunkte für
/// <c>FSCTL_SRV_ENUMERATE_SNAPSHOTS</c> bereit.</item>
/// </list>
/// Die Historie liegt im Speicher (pro Store-Instanz) und ist auf <c>maxVersionsPerFile</c>
/// Einträge je Datei begrenzt. Sie eignet sich für Tests/Dev; ein persistenter Snapshot-
/// Provider kann diese Klasse später ersetzen.
/// </summary>
public sealed class VersioningFileStore : IFileStore, ISnapshotStore
{
    /// <summary>Obergrenze für das In-Memory-Festhalten einer Version (Schutz vor Riesen-Dateien).</summary>
    private const long MaxCaptureBytes = 64L * 1024 * 1024;

    private readonly IFileStore _inner;
    private readonly int _maxVersionsPerFile;
    private readonly ConcurrentDictionary<string, FileHistory> _history = new(StringComparer.OrdinalIgnoreCase);

    public VersioningFileStore(IFileStore inner, int maxVersionsPerFile = 64)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _maxVersionsPerFile = Math.Max(1, maxVersionsPerFile);
    }

    public FileStoreResult<IFileHandle> Create(
        string path, FileAccessIntent access, CreateDispositionIntent disposition,
        bool directoryRequired, bool nonDirectoryRequired, out CreateOutcome createAction)
    {
        createAction = CreateOutcome.Opened;

        // 1) Snapshot-Zugriff: führendes @GMT-Segment → frühere Version read-only liefern.
        if (GmtToken.TrySplitSnapshotPath(path, out DateTime snapAt, out string realPath))
        {
            bool wantsWrite = access.HasFlag(FileAccessIntent.Write) || access.HasFlag(FileAccessIntent.Delete)
                || disposition is CreateDispositionIntent.Create or CreateDispositionIntent.Overwrite
                    or CreateDispositionIntent.OverwriteIf or CreateDispositionIntent.Supersede;
            if (wantsWrite)
                return FileStoreResult<IFileHandle>.Fail(NtStatus.AccessDenied); // Snapshots sind read-only.

            if (!TryResolveSnapshot(realPath, snapAt, out byte[] content, out FileEntryInfo info))
                return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);

            return FileStoreResult<IFileHandle>.Ok(new SnapshotFileHandle(realPath, content, info));
        }

        // 2) Normaler Pfad: vor einem Überschreiben die aktuelle Version festhalten.
        bool overwrites = disposition is CreateDispositionIntent.Overwrite
            or CreateDispositionIntent.OverwriteIf or CreateDispositionIntent.Supersede;
        if (overwrites)
            CaptureCurrentVersion(path);

        return _inner.Create(path, access, disposition, directoryRequired, nonDirectoryRequired, out createAction);
    }

    public FileStoreResult<int> Read(IFileHandle handle, long offset, Span<byte> buffer)
        => handle is SnapshotFileHandle s ? s.Read(offset, buffer) : _inner.Read(handle, offset, buffer);

    public FileStoreResult<int> Write(IFileHandle handle, long offset, ReadOnlySpan<byte> data)
        => handle is SnapshotFileHandle
            ? FileStoreResult<int>.Fail(NtStatus.AccessDenied)
            : _inner.Write(handle, offset, data);

    public FileStoreResult<IReadOnlyList<FileEntryInfo>> QueryDirectory(IFileHandle handle, string searchPattern)
        => handle is SnapshotFileHandle
            ? FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(NtStatus.InvalidParameter)
            : _inner.QueryDirectory(handle, searchPattern);

    public NtStatus SetEndOfFile(IFileHandle handle, long length)
        => handle is SnapshotFileHandle ? NtStatus.AccessDenied : _inner.SetEndOfFile(handle, length);

    public NtStatus Rename(IFileHandle handle, string newPath, bool replaceIfExists)
        => handle is SnapshotFileHandle ? NtStatus.AccessDenied : _inner.Rename(handle, newPath, replaceIfExists);

    public NtStatus SetDeleteOnClose(IFileHandle handle, bool delete)
    {
        if (handle is SnapshotFileHandle)
            return delete ? NtStatus.AccessDenied : NtStatus.Success;

        // Vor dem Löschen die letzte Version festhalten (Datei existiert hier noch).
        if (delete && !handle.IsDirectory && !string.IsNullOrEmpty(handle.Path))
            CaptureCurrentVersion(handle.Path);

        return _inner.SetDeleteOnClose(handle, delete);
    }

    public NtStatus Flush(IFileHandle handle)
        => handle is SnapshotFileHandle ? NtStatus.Success : _inner.Flush(handle);

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

    // --- Intern ---

    /// <summary>Liest den aktuellen Inhalt einer existierenden Datei und legt ihn als Version ab.</summary>
    private void CaptureCurrentVersion(string path)
    {
        if (!TryReadAll(path, out byte[] content, out FileEntryInfo info))
            return; // Datei existiert (noch) nicht oder ist ein Verzeichnis → nichts zu sichern.

        FileHistory history = _history.GetOrAdd(Normalize(path), _ => new FileHistory());
        history.Add(new FileVersion(DateTime.UtcNow, content, info), _maxVersionsPerFile);
    }

    /// <summary>Öffnet die Datei read-only über das Backend und liest sie vollständig in den Speicher.</summary>
    private bool TryReadAll(string path, out byte[] content, out FileEntryInfo info)
    {
        content = [];
        info = null!;

        FileStoreResult<IFileHandle> opened = _inner.Create(
            path, FileAccessIntent.Read, CreateDispositionIntent.Open,
            directoryRequired: false, nonDirectoryRequired: true, out _);
        if (!opened.IsSuccess)
            return false;

        IFileHandle handle = opened.Value!;
        try
        {
            if (handle.IsDirectory)
                return false;

            info = handle.GetInfo();
            long size = info.EndOfFile;
            if (size < 0 || size > MaxCaptureBytes)
                return false;

            var buffer = new byte[size];
            int total = 0;
            while (total < size)
            {
                FileStoreResult<int> read = _inner.Read(handle, total, buffer.AsSpan(total));
                if (!read.IsSuccess)
                    return false;
                if (read.Value == 0)
                    break;
                total += read.Value;
            }

            content = total == size ? buffer : buffer[..total];
            return true;
        }
        finally
        {
            handle.Dispose();
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

    // --- Datentypen ---

    private sealed record FileVersion(DateTime TimeUtc, byte[] Content, FileEntryInfo Original)
    {
        /// <summary>Metadaten der Snapshot-Sicht: Größe aus dem festgehaltenen Inhalt, read-only.</summary>
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

    /// <summary>Versionshistorie einer Datei (aufsteigend nach Zeit, da bei Überschreiben angehängt).</summary>
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
        /// Liefert die Version, die zum Zeitpunkt <paramref name="t"/> aktuell war: die erste
        /// festgehaltene Version, deren (sekundengenauer) Zeitstempel ≥ <paramref name="t"/> ist.
        /// </summary>
        public FileVersion? ResolveAtOrAfter(DateTime t)
        {
            DateTime floor = FloorToSecond(t);
            lock (_gate)
            {
                foreach (FileVersion v in _versions) // aufsteigend
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

/// <summary>Read-only Backend-Handle, das den festgehaltenen Inhalt einer früheren Version bedient.</summary>
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
