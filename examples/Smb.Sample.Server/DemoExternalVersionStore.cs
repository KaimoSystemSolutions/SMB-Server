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

    public async ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(
        string path, FileAccessIntent access, CreateDispositionIntent disposition,
        bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
    {
        // (1) @GMT snapshot access → serve read-only from the external version store.
        //     The lib's token parser (GmtToken) can be reused but doesn't have to be.
        if (GmtToken.TrySplitSnapshotPath(path, out DateTime snapAt, out string realPath))
        {
            bool wantsWrite = access.HasFlag(FileAccessIntent.Write) || access.HasFlag(FileAccessIntent.Delete)
                || disposition is CreateDispositionIntent.Create or CreateDispositionIntent.Overwrite
                    or CreateDispositionIntent.OverwriteIf or CreateDispositionIntent.Supersede;
            if (wantsWrite)
                return FileStoreResult<FileCreateResult>.Fail(NtStatus.AccessDenied); // snapshots are read-only.

            if (!TryResolveSnapshot(realPath, snapAt, out byte[] bytes, out FileEntryInfo info))
                return FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectNameNotFound);

            return FileStoreResult<FileCreateResult>.Ok(
                new FileCreateResult(new ReadOnlyBlobHandle(realPath, bytes, info), CreateOutcome.Opened));
        }

        // (2) Before each overwrite, save the current version, then delegate to the backend.
        if (disposition is CreateDispositionIntent.Overwrite or CreateDispositionIntent.OverwriteIf
            or CreateDispositionIntent.Supersede)
            await CaptureVersionAsync(path, cancellationToken);

        return await _inner.CreateAsync(path, access, disposition, directoryRequired, nonDirectoryRequired, cancellationToken);
    }

    public ValueTask<FileStoreResult<int>> ReadAsync(
        IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        => handle is ReadOnlyBlobHandle b
            ? new(b.Read(offset, buffer.Span))
            : _inner.ReadAsync(handle, offset, buffer, cancellationToken);

    public ValueTask<FileStoreResult<int>> WriteAsync(
        IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        => handle is ReadOnlyBlobHandle
            ? new(FileStoreResult<int>.Fail(NtStatus.AccessDenied))
            : _inner.WriteAsync(handle, offset, data, cancellationToken);

    public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(
        IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
        => handle is ReadOnlyBlobHandle
            ? new(FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(NtStatus.InvalidParameter))
            : _inner.QueryDirectoryAsync(handle, searchPattern, cancellationToken);

    public ValueTask<NtStatus> SetEndOfFileAsync(
        IFileHandle handle, long length, CancellationToken cancellationToken = default)
        => handle is ReadOnlyBlobHandle ? new(NtStatus.AccessDenied) : _inner.SetEndOfFileAsync(handle, length, cancellationToken);

    public ValueTask<NtStatus> RenameAsync(
        IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default)
        => handle is ReadOnlyBlobHandle ? new(NtStatus.AccessDenied) : _inner.RenameAsync(handle, newPath, replaceIfExists, cancellationToken);

    public async ValueTask<NtStatus> SetDeleteOnCloseAsync(
        IFileHandle handle, bool delete, CancellationToken cancellationToken = default)
    {
        if (handle is ReadOnlyBlobHandle)
            return delete ? NtStatus.AccessDenied : NtStatus.Success;

        // Also capture the last version before deletion (analogous to overwriting).
        if (delete && !handle.IsDirectory && !string.IsNullOrEmpty(handle.Path))
            await CaptureVersionAsync(handle.Path, cancellationToken);

        return await _inner.SetDeleteOnCloseAsync(handle, delete, cancellationToken);
    }

    public ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default)
        => handle is ReadOnlyBlobHandle ? new(NtStatus.Success) : _inner.FlushAsync(handle, cancellationToken);

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

    private async ValueTask CaptureVersionAsync(string path, CancellationToken cancellationToken)
    {
        (bool ok, byte[] content) = await TryReadAllAsync(path, cancellationToken);
        if (!ok)
            return; // file does not yet exist → nothing to save.

        string dir = VersionDir(path);
        Directory.CreateDirectory(dir);
        string blob = System.IO.Path.Combine(dir, DateTime.UtcNow.Ticks + ".blob");
        await File.WriteAllBytesAsync(blob, content, cancellationToken);
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

    private async ValueTask<(bool Ok, byte[] Content)> TryReadAllAsync(string path, CancellationToken cancellationToken)
    {
        FileStoreResult<FileCreateResult> opened = await _inner.CreateAsync(
            path, FileAccessIntent.Read, CreateDispositionIntent.Open,
            directoryRequired: false, nonDirectoryRequired: true, cancellationToken);
        if (!opened.IsSuccess)
            return (false, []);

        IFileHandle handle = opened.Value.Handle;
        try
        {
            if (handle.IsDirectory)
                return (false, []);

            long size = (await handle.GetInfoAsync(cancellationToken)).EndOfFile;
            var buffer = new byte[size];
            int total = 0;
            while (total < size)
            {
                FileStoreResult<int> read = await _inner.ReadAsync(handle, total, buffer.AsMemory(total), cancellationToken);
                if (!read.IsSuccess || read.Value == 0)
                    break;
                total += read.Value;
            }

            byte[] content = total == size ? buffer : buffer[..total];
            return (true, content);
        }
        finally
        {
            await handle.DisposeAsync();
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
