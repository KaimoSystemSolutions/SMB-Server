using System.Text;
using Smb.FileSystem;
using Smb.FileSystem.Versioning;
using Smb.Protocol.Enums;

namespace Smb.Sample.Server;

/// <summary>
/// <b>Example: plugging custom versioning into the library.</b>
/// <para>
/// The library only defines the seam — <see cref="IFileStore"/> (file backend) and optionally
/// <see cref="ISnapshotStore"/> (for FSCTL_SRV_ENUMERATE_SNAPSHOTS). The server core does NOT
/// parse <c>@GMT-…</c> paths itself; it passes the path through to <see cref="Create"/>. This
/// allows a custom file server to place its (arbitrarily complex) versioning/snapshot logic here
/// without touching anything in the core.
/// </para>
/// <para>
/// This demo store is intentionally DIFFERENT from the built-in in-memory
/// <c>VersioningFileStore</c>: it stores every overwritten version <b>persistently on disk</b>
/// (sidecar directory) — versions survive a restart. The file system stands in for a
/// "real" system; in practice you might use ZFS snapshots, a database, an object store, etc.
/// Wire it up normally via <c>AddShare(new Share { FileStore = … })</c>.
/// </para>
/// </summary>
public sealed class DemoExternalVersionStore : IFileStore, ISnapshotStore
{
    private readonly IFileStore _inner;       // your actual backend (here: LocalFileStore)
    private readonly string _versionRoot;     // where the version blobs live (outside the share)
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

        // (1) @GMT snapshot access → serve read-only from the external version store.
        //     The lib's token parser (GmtToken) can be reused but doesn't have to be.
        if (GmtToken.TrySplitSnapshotPath(path, out DateTime snapAt, out string realPath))
        {
            bool wantsWrite = access.HasFlag(FileAccessIntent.Write) || access.HasFlag(FileAccessIntent.Delete)
                || disposition is CreateDispositionIntent.Create or CreateDispositionIntent.Overwrite
                    or CreateDispositionIntent.OverwriteIf or CreateDispositionIntent.Supersede;
            if (wantsWrite)
                return FileStoreResult<IFileHandle>.Fail(NtStatus.AccessDenied); // snapshots are read-only.

            if (!TryResolveSnapshot(realPath, snapAt, out byte[] bytes, out FileEntryInfo info))
                return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);

            return FileStoreResult<IFileHandle>.Ok(new ReadOnlyBlobHandle(realPath, bytes, info));
        }

        // (2) Before each overwrite, save the current version, then delegate to the backend.
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

        // Also capture the last version before deletion (analogous to overwriting).
        if (delete && !handle.IsDirectory && !string.IsNullOrEmpty(handle.Path))
            CaptureVersion(handle.Path);

        return _inner.SetDeleteOnClose(handle, delete);
    }

    public NtStatus Flush(IFileHandle handle)
        => handle is ReadOnlyBlobHandle ? NtStatus.Success : _inner.Flush(handle);

    // ── ISnapshotStore: feeds FSCTL_SRV_ENUMERATE_SNAPSHOTS from YOUR system ──

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

    // ── Internal: persistent version store (one .blob file per version) ──

    private void CaptureVersion(string path)
    {
        if (!TryReadAll(path, out byte[] content))
            return; // file does not yet exist → nothing to save.

        string dir = VersionDir(path);
        Directory.CreateDirectory(dir);
        string blob = System.IO.Path.Combine(dir, DateTime.UtcNow.Ticks + ".blob");
        File.WriteAllBytes(blob, content);
        _log?.Invoke($"Version of '{path}' saved ({content.Length} bytes) → {System.IO.Path.GetFileName(blob)}");
    }

    private bool TryResolveSnapshot(string realPath, DateTime snapAt, out byte[] content, out FileEntryInfo info)
    {
        content = [];
        info = null!;
        string dir = VersionDir(realPath);
        if (!Directory.Exists(dir))
            return false;

        // The version that was current at snapshot time: smallest version time ≥ requested.
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

/// <summary>Read-only handle that serves the contents of a persisted version (blob).</summary>
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
