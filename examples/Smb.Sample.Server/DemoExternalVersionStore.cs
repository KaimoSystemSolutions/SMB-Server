using System.Text;
using Smb.FileSystem;
using Smb.FileSystem.Versioning;
using Smb.Protocol.Enums;

namespace Smb.Sample.Server;

/// <summary>
/// <b>Beispiel: eigene Versionierung in die Lib einklinken.</b>
/// <para>
/// Die Lib gibt nur die Naht vor — <see cref="IFileStore"/> (Datei-Backend) und optional
/// <see cref="ISnapshotStore"/> (für FSCTL_SRV_ENUMERATE_SNAPSHOTS). Der Server-Core parst
/// <c>@GMT-…</c>-Pfade NICHT selbst; er reicht den Pfad an <see cref="Create"/> durch. Damit
/// kann ein eigener Fileserver seine (beliebig komplexe) Versions-/Snapshot-Logik hier
/// unterbringen, ohne irgendetwas am Core zu ändern.
/// </para>
/// <para>
/// Dieser Demo-Store ist absichtlich ANDERS als der mitgelieferte In-Memory-
/// <c>VersioningFileStore</c>: Er legt jede überschriebene Version <b>persistent auf Platte</b>
/// ab (Sidecar-Verzeichnis) — Versionen überleben also einen Neustart. Stellvertretend für ein
/// „echtes" System steht hier das Dateisystem; bei dir wäre es z.B. ZFS-Snapshots, eine DB,
/// ein Object-Store o.ä. Verdrahtet wird er ganz normal über <c>AddShare(new Share { FileStore = … })</c>.
/// </para>
/// </summary>
public sealed class DemoExternalVersionStore : IFileStore, ISnapshotStore
{
    private readonly IFileStore _inner;       // dein eigentliches Backend (hier: LocalFileStore)
    private readonly string _versionRoot;     // wo die Versions-Blobs liegen (außerhalb des Shares)
    private readonly Action<string>? _log;

    public DemoExternalVersionStore(IFileStore inner, string versionRoot, Action<string>? log = null)
    {
        _inner = inner;
        _versionRoot = System.IO.Path.GetFullPath(versionRoot);
        _log = log;
        Directory.CreateDirectory(_versionRoot);
    }

    public FileStoreResult<IFileHandle> Create(
        string path, FileAccessIntent access, CreateDispositionIntent disposition,
        bool directoryRequired, bool nonDirectoryRequired, out CreateOutcome createAction)
    {
        createAction = CreateOutcome.Opened;

        // (1) @GMT-Snapshot-Zugriff → read-only aus dem externen Versionsspeicher bedienen.
        //     Den Token-Parser der Lib darf man gern mitbenutzen (GmtToken), muss man aber nicht.
        if (GmtToken.TrySplitSnapshotPath(path, out DateTime snapAt, out string realPath))
        {
            bool wantsWrite = access.HasFlag(FileAccessIntent.Write) || access.HasFlag(FileAccessIntent.Delete)
                || disposition is CreateDispositionIntent.Create or CreateDispositionIntent.Overwrite
                    or CreateDispositionIntent.OverwriteIf or CreateDispositionIntent.Supersede;
            if (wantsWrite)
                return FileStoreResult<IFileHandle>.Fail(NtStatus.AccessDenied); // Snapshots sind read-only.

            if (!TryResolveSnapshot(realPath, snapAt, out byte[] bytes, out FileEntryInfo info))
                return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);

            return FileStoreResult<IFileHandle>.Ok(new ReadOnlyBlobHandle(realPath, bytes, info));
        }

        // (2) Vor jedem Überschreiben die aktuelle Version sichern, dann ans Backend delegieren.
        if (disposition is CreateDispositionIntent.Overwrite or CreateDispositionIntent.OverwriteIf
            or CreateDispositionIntent.Supersede)
            CaptureVersion(path);

        return _inner.Create(path, access, disposition, directoryRequired, nonDirectoryRequired, out createAction);
    }

    public FileStoreResult<int> Read(IFileHandle handle, long offset, Span<byte> buffer)
        => handle is ReadOnlyBlobHandle b ? b.Read(offset, buffer) : _inner.Read(handle, offset, buffer);

    public FileStoreResult<int> Write(IFileHandle handle, long offset, ReadOnlySpan<byte> data)
        => handle is ReadOnlyBlobHandle
            ? FileStoreResult<int>.Fail(NtStatus.AccessDenied)
            : _inner.Write(handle, offset, data);

    public FileStoreResult<IReadOnlyList<FileEntryInfo>> QueryDirectory(IFileHandle handle, string searchPattern)
        => handle is ReadOnlyBlobHandle
            ? FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(NtStatus.InvalidParameter)
            : _inner.QueryDirectory(handle, searchPattern);

    public NtStatus SetEndOfFile(IFileHandle handle, long length)
        => handle is ReadOnlyBlobHandle ? NtStatus.AccessDenied : _inner.SetEndOfFile(handle, length);

    public NtStatus Rename(IFileHandle handle, string newPath, bool replaceIfExists)
        => handle is ReadOnlyBlobHandle ? NtStatus.AccessDenied : _inner.Rename(handle, newPath, replaceIfExists);

    public NtStatus SetDeleteOnClose(IFileHandle handle, bool delete)
    {
        if (handle is ReadOnlyBlobHandle)
            return delete ? NtStatus.AccessDenied : NtStatus.Success;

        // Auch vor dem Löschen die letzte Version festhalten (analog zum Überschreiben).
        if (delete && !handle.IsDirectory && !string.IsNullOrEmpty(handle.Path))
            CaptureVersion(handle.Path);

        return _inner.SetDeleteOnClose(handle, delete);
    }

    public NtStatus Flush(IFileHandle handle)
        => handle is ReadOnlyBlobHandle ? NtStatus.Success : _inner.Flush(handle);

    // ── ISnapshotStore: speist FSCTL_SRV_ENUMERATE_SNAPSHOTS aus DEINEM System ──

    public IReadOnlyList<DateTime> GetSnapshots(string path)
    {
        if (string.IsNullOrEmpty(path) || path is "\\" or "/")
            return GetAllSnapshots();
        return ReadTimes(VersionDir(path));
    }

    public IReadOnlyList<DateTime> GetAllSnapshots()
    {
        var set = new SortedSet<DateTime>();
        if (Directory.Exists(_versionRoot))
            foreach (string dir in Directory.EnumerateDirectories(_versionRoot))
                foreach (DateTime t in ReadTimes(dir))
                    set.Add(t);
        return [.. set];
    }

    // ── Intern: persistenter Versionsspeicher (eine .blob-Datei je Version) ──

    private void CaptureVersion(string path)
    {
        if (!TryReadAll(path, out byte[] content))
            return; // Datei existiert (noch) nicht → nichts zu sichern.

        string dir = VersionDir(path);
        Directory.CreateDirectory(dir);
        string blob = System.IO.Path.Combine(dir, DateTime.UtcNow.Ticks + ".blob");
        File.WriteAllBytes(blob, content);
        _log?.Invoke($"Version von '{path}' gesichert ({content.Length} Bytes) → {System.IO.Path.GetFileName(blob)}");
    }

    private bool TryResolveSnapshot(string realPath, DateTime snapAt, out byte[] content, out FileEntryInfo info)
    {
        content = [];
        info = null!;
        string dir = VersionDir(realPath);
        if (!Directory.Exists(dir))
            return false;

        // Die Version, die zum Snapshot-Zeitpunkt aktuell war: kleinste Version-Zeit ≥ angefragt.
        DateTime floor = FloorToSecond(snapAt);
        string? best = null;
        DateTime bestTime = DateTime.MaxValue;
        foreach (string file in Directory.EnumerateFiles(dir, "*.blob"))
        {
            if (!long.TryParse(System.IO.Path.GetFileNameWithoutExtension(file), out long ticks))
                continue;
            var t = new DateTime(ticks, DateTimeKind.Utc);
            if (FloorToSecond(t) >= floor && t < bestTime)
            {
                bestTime = t;
                best = file;
            }
        }

        if (best is null)
            return false;

        content = File.ReadAllBytes(best);
        long ft = bestTime.ToFileTimeUtc();
        info = new FileEntryInfo
        {
            Name = System.IO.Path.GetFileName(realPath.Replace('\\', '/')),
            Attributes = SmbFileAttributes.ReadOnly,
            EndOfFile = content.Length,
            AllocationSize = (content.Length + 4095) / 4096 * 4096,
            CreationTime = ft,
            LastAccessTime = ft,
            LastWriteTime = ft,
            ChangeTime = ft,
        };
        return true;
    }

    private bool TryReadAll(string path, out byte[] content)
    {
        content = [];
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

            long size = handle.GetInfo().EndOfFile;
            var buffer = new byte[size];
            int total = 0;
            while (total < size)
            {
                FileStoreResult<int> read = _inner.Read(handle, total, buffer.AsSpan(total));
                if (!read.IsSuccess || read.Value == 0)
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

    private static IReadOnlyList<DateTime> ReadTimes(string dir)
    {
        if (!Directory.Exists(dir))
            return [];
        var list = new List<DateTime>();
        foreach (string file in Directory.EnumerateFiles(dir, "*.blob"))
            if (long.TryParse(System.IO.Path.GetFileNameWithoutExtension(file), out long ticks))
                list.Add(new DateTime(ticks, DateTimeKind.Utc));
        list.Sort();
        return list;
    }

    private string VersionDir(string path) => System.IO.Path.Combine(_versionRoot, Sanitize(path));

    private static string Sanitize(string path)
    {
        var sb = new StringBuilder(path.Length);
        foreach (char c in path.Replace('\\', '/'))
            sb.Append(char.IsLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '_');
        return sb.Length == 0 ? "_root" : sb.ToString();
    }

    private static DateTime FloorToSecond(DateTime t)
    {
        DateTime u = t.Kind == DateTimeKind.Utc ? t : t.ToUniversalTime();
        return new DateTime(u.Year, u.Month, u.Day, u.Hour, u.Minute, u.Second, DateTimeKind.Utc);
    }
}

/// <summary>Read-only Handle, das den Inhalt einer persistierten Version (Blob) bedient.</summary>
internal sealed class ReadOnlyBlobHandle : IFileHandle
{
    private readonly byte[] _data;
    private readonly FileEntryInfo _info;

    public ReadOnlyBlobHandle(string path, byte[] data, FileEntryInfo info)
    {
        Path = path;
        _data = data;
        _info = info;
    }

    public string Path { get; }
    public bool IsDirectory => false;
    public FileEntryInfo GetInfo() => _info;

    public FileStoreResult<int> Read(long offset, Span<byte> buffer)
    {
        if (offset < 0 || offset >= _data.Length)
            return FileStoreResult<int>.Ok(0); // EOF
        int n = Math.Min(buffer.Length, _data.Length - (int)offset);
        _data.AsSpan((int)offset, n).CopyTo(buffer);
        return FileStoreResult<int>.Ok(n);
    }

    public void Dispose() { }
}
