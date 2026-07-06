using Microsoft.Win32.SafeHandles;
using Smb.Protocol.Enums;

namespace Smb.FileSystem.Local;

/// <summary>
/// <see cref="IFileStore"/> backed by a local directory. Paths are share-relative
/// (backslash-separated, no leading backslash) and are protected against escaping from the
/// root directory (no <c>..</c> escape, Context §13.4). Read/Write/List/Stat.
/// Synchronously attached via <see cref="SyncFileStore"/>.
/// </summary>
public sealed class LocalFileStore : SyncFileStore
{
    private readonly string _root;
    private readonly string _realRoot;
    private readonly bool _readOnly;

    public LocalFileStore(string rootDirectory, bool readOnly = true)
    {
        _root = Path.GetFullPath(rootDirectory);
        Directory.CreateDirectory(_root);
        // Real (symlink-resolved) root for the sandbox check below. The root itself may
        // legitimately live under a symlink (e.g. /mnt/tank/... on ZFS), so both sides of
        // the containment check must be resolved consistently.
        _realRoot = TryResolveRealPath(_root) ?? _root;
        _readOnly = readOnly;
    }

    protected override FileStoreResult<IFileHandle> Create(
        string path, FileAccessIntent access, CreateDispositionIntent disposition,
        bool directoryRequired, bool nonDirectoryRequired, out CreateOutcome createAction)
    {
        createAction = CreateOutcome.Opened;

        if (!TryResolve(path, out string full))
            return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);

        bool wantsWrite = access.HasFlag(FileAccessIntent.Write) || disposition is
            CreateDispositionIntent.Create or CreateDispositionIntent.Overwrite or
            CreateDispositionIntent.OverwriteIf or CreateDispositionIntent.Supersede;
        if (_readOnly && wantsWrite)
            return FileStoreResult<IFileHandle>.Fail(NtStatus.AccessDenied);

        bool isDir = Directory.Exists(full);
        bool isFile = File.Exists(full);
        bool exists = isDir || isFile;

        if (directoryRequired && exists && !isDir)
            return FileStoreResult<IFileHandle>.Fail(NtStatus.NotADirectory);
        if (nonDirectoryRequired && exists && isDir)
            return FileStoreResult<IFileHandle>.Fail(NtStatus.FileIsADirectory);

        string relative = full == _root ? string.Empty : path;

        // Directory open/create — no file stream is held.
        if (directoryRequired || (exists && isDir))
            return CreateDirectoryHandle(full, relative, disposition, exists, out createAction);

        // Regular file: open ONE persistent OS handle for the lifetime of the SMB open (instead of
        // re-opening per READ/WRITE — O5). FileShare here is permissive; cross-open sharing semantics
        // (CREATE ShareAccess) are enforced server-side by the IShareModeManager, which also works on
        // Unix where OS FileShare is advisory only.
        return CreateFileHandle(full, relative, access, disposition, exists, out createAction);
    }

    private FileStoreResult<IFileHandle> CreateDirectoryHandle(
        string full, string relative, CreateDispositionIntent disposition, bool exists, out CreateOutcome createAction)
    {
        createAction = CreateOutcome.Opened;
        switch (disposition)
        {
            case CreateDispositionIntent.Open:
            case CreateDispositionIntent.Overwrite:
                if (!exists) return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);
                createAction = disposition == CreateDispositionIntent.Overwrite ? CreateOutcome.Overwritten : CreateOutcome.Opened;
                break;
            case CreateDispositionIntent.Create:
                if (exists) return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameCollision);
                Directory.CreateDirectory(full);
                createAction = CreateOutcome.Created;
                break;
            default: // OpenIf / OverwriteIf / Supersede
                if (!exists) { Directory.CreateDirectory(full); createAction = CreateOutcome.Created; }
                else createAction = disposition == CreateDispositionIntent.OpenIf ? CreateOutcome.Opened : CreateOutcome.Overwritten;
                break;
        }
        return FileStoreResult<IFileHandle>.Ok(new LocalFileHandle(full, relative, _root, stream: null, isDirectory: true));
    }

    private FileStoreResult<IFileHandle> CreateFileHandle(
        string full, string relative, FileAccessIntent access, CreateDispositionIntent disposition, bool exists, out CreateOutcome createAction)
    {
        createAction = CreateOutcome.Opened;

        // Pre-checks mirror the NTFS dispositions so we return a clean status before touching the file.
        if (disposition is CreateDispositionIntent.Open or CreateDispositionIntent.Overwrite && !exists)
            return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);
        if (disposition == CreateDispositionIntent.Create && exists)
            return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameCollision);

        FileMode mode = disposition switch
        {
            CreateDispositionIntent.Open => FileMode.Open,
            CreateDispositionIntent.Create => FileMode.CreateNew,
            CreateDispositionIntent.OpenIf => FileMode.OpenOrCreate,
            CreateDispositionIntent.Overwrite => FileMode.Truncate,
            CreateDispositionIntent.OverwriteIf => FileMode.Create,
            CreateDispositionIntent.Supersede => FileMode.Create,
            _ => FileMode.Open,
        };

        // Any disposition other than a plain Open creates or truncates → needs write access.
        bool needWrite = access.HasFlag(FileAccessIntent.Write) || disposition != CreateDispositionIntent.Open;
        FileAccess fileAccess = needWrite && !_readOnly ? FileAccess.ReadWrite : FileAccess.Read;
        const FileShare share = FileShare.ReadWrite | FileShare.Delete;

        try
        {
            var stream = new FileStream(full, mode, fileAccess, share);
            createAction = disposition switch
            {
                CreateDispositionIntent.Create => CreateOutcome.Created,
                CreateDispositionIntent.Overwrite => CreateOutcome.Overwritten,
                CreateDispositionIntent.OpenIf => exists ? CreateOutcome.Opened : CreateOutcome.Created,
                CreateDispositionIntent.OverwriteIf => exists ? CreateOutcome.Overwritten : CreateOutcome.Created,
                CreateDispositionIntent.Supersede => exists ? CreateOutcome.Superseded : CreateOutcome.Created,
                _ => CreateOutcome.Opened,
            };
            return FileStoreResult<IFileHandle>.Ok(new LocalFileHandle(full, relative, _root, stream, isDirectory: false));
        }
        catch (FileNotFoundException) { return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound); }
        catch (DirectoryNotFoundException) { return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectPathNotFound); }
        catch (UnauthorizedAccessException) { return FileStoreResult<IFileHandle>.Fail(NtStatus.AccessDenied); }
        catch (IOException ex) when (IsSharingViolation(ex)) { return FileStoreResult<IFileHandle>.Fail(NtStatus.SharingViolation); }
        catch (IOException) when (mode == FileMode.CreateNew) { return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameCollision); }
        catch (IOException) { return FileStoreResult<IFileHandle>.Fail(NtStatus.InvalidParameter); }
    }

    private static bool IsSharingViolation(IOException ex) => (ex.HResult & 0xFFFF) == 32; // ERROR_SHARING_VIOLATION

    protected override FileStoreResult<int> Read(IFileHandle handle, long offset, Span<byte> buffer)
    {
        var h = (LocalFileHandle)handle;
        if (h.IsDirectory) return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
        return h.ReadAt(offset, buffer); // EOF → Ok(0) (handler maps to STATUS_END_OF_FILE)
    }

    /// <summary>
    /// True async file I/O (overlapped I/O via <see cref="FileOptions.Asynchronous"/> +
    /// <see cref="RandomAccess"/>) instead of the sync fallback from the base class — READ does not
    /// block a thread-pool thread (docs/ASYNC_IO_ROADMAP.md, A5). Semantics identical to
    /// synchronous <see cref="Read"/> (EOF → 0 bytes; IOException → InvalidParameter).
    /// </summary>
    public override async ValueTask<FileStoreResult<int>> ReadAsync(
        IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var h = (LocalFileHandle)handle;
        if (h.IsDirectory) return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
        try
        {
            using SafeFileHandle file = File.OpenHandle(
                h.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, FileOptions.Asynchronous);
            if (offset >= RandomAccess.GetLength(file))
                return FileStoreResult<int>.Ok(0); // EOF (handler maps to STATUS_END_OF_FILE)
            int read = await RandomAccess.ReadAsync(file, buffer, offset, cancellationToken).ConfigureAwait(false);
            return FileStoreResult<int>.Ok(read);
        }
        catch (IOException) { return FileStoreResult<int>.Fail(NtStatus.InvalidParameter); }
    }

    protected override FileStoreResult<int> Write(IFileHandle handle, long offset, ReadOnlySpan<byte> data)
    {
        if (_readOnly) return FileStoreResult<int>.Fail(NtStatus.AccessDenied);
        var h = (LocalFileHandle)handle;
        if (h.IsDirectory) return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
        return h.WriteAt(offset, data);
    }

    /// <summary>True async write — counterpart to <see cref="ReadAsync"/> (A5). Semantics like <see cref="Write"/>.</summary>
    public override async ValueTask<FileStoreResult<int>> WriteAsync(
        IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        if (_readOnly) return FileStoreResult<int>.Fail(NtStatus.AccessDenied);
        var h = (LocalFileHandle)handle;
        if (h.IsDirectory) return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
        try
        {
            using SafeFileHandle file = File.OpenHandle(
                h.FullPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite, FileOptions.Asynchronous);
            await RandomAccess.WriteAsync(file, data, offset, cancellationToken).ConfigureAwait(false);
            return FileStoreResult<int>.Ok(data.Length);
        }
        catch (IOException) { return FileStoreResult<int>.Fail(NtStatus.DiskFull); }
    }

    protected override FileStoreResult<IReadOnlyList<FileEntryInfo>> QueryDirectory(IFileHandle handle, string searchPattern)
    {
        var h = (LocalFileHandle)handle;
        if (!h.IsDirectory) return FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(NtStatus.InvalidParameter);

        string pattern = string.IsNullOrEmpty(searchPattern) ? "*" : searchPattern;
        var entries = new List<FileEntryInfo>();

        // Prepend "." and ".." (expected by clients).
        var dirInfo = new DirectoryInfo(h.FullPath);
        entries.Add(ToEntry(dirInfo, "."));
        if (Path.GetFullPath(h.FullPath) != _root)
            entries.Add(ToEntry(dirInfo.Parent ?? dirInfo, ".."));

        try
        {
            foreach (FileSystemInfo info in dirInfo.EnumerateFileSystemInfos(pattern))
                entries.Add(ToEntry(info, info.Name));
        }
        catch (DirectoryNotFoundException)
        {
            return FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(NtStatus.ObjectNameNotFound);
        }

        return FileStoreResult<IReadOnlyList<FileEntryInfo>>.Ok(entries);
    }

    protected override NtStatus SetEndOfFile(IFileHandle handle, long length)
    {
        if (_readOnly) return NtStatus.AccessDenied;
        return ((LocalFileHandle)handle).SetLength(length);
    }

    protected override NtStatus Rename(IFileHandle handle, string newPath, bool replaceIfExists)
    {
        if (_readOnly) return NtStatus.AccessDenied;
        var h = (LocalFileHandle)handle;
        if (!TryResolve(newPath, out string dest)) return NtStatus.ObjectPathNotFound;
        try
        {
            if (File.Exists(dest) && !replaceIfExists) return NtStatus.ObjectNameCollision;
            // The open stream was created with FileShare.Delete, so the file can be renamed while
            // open; afterwards the handle must point at the new location for GetInfo/DeleteOnClose.
            if (h.IsDirectory) Directory.Move(h.FullPath, dest);
            else File.Move(h.FullPath, dest, replaceIfExists);
            h.Relocate(dest, dest == _root ? string.Empty : newPath);
            return NtStatus.Success;
        }
        catch (IOException) { return NtStatus.AccessDenied; }
    }

    protected override NtStatus SetDeleteOnClose(IFileHandle handle, bool delete)
    {
        if (_readOnly && delete) return NtStatus.AccessDenied;
        ((LocalFileHandle)handle).DeleteOnClose = delete;
        return NtStatus.Success;
    }

    protected override NtStatus Flush(IFileHandle handle) => ((LocalFileHandle)handle).FlushStream();

    /// <summary>Resolves a share-relative path to a full path, sandboxed against directory escape.</summary>
    private bool TryResolve(string relative, out string fullPath)
    {
        fullPath = _root;
        string normalized = (relative ?? string.Empty).Replace('\\', Path.DirectorySeparatorChar).TrimStart(Path.DirectorySeparatorChar);

        // Invalid path characters (e.g. from @GMT-/snapshot paths or misbehaving clients)
        // would otherwise cause an exception in Path.GetFullPath. Handle cleanly as
        // "unresolvable" instead of throwing (Context §13.4).
        if (normalized.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            return false;

        string candidate;
        try { candidate = Path.GetFullPath(Path.Combine(_root, normalized)); }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException or NotSupportedException)
        {
            return false;
        }

        // Sandbox (string level): must stay within root (no .. escape, Context §13.4).
        string rootWithSep = _root.EndsWith(Path.DirectorySeparatorChar) ? _root : _root + Path.DirectorySeparatorChar;
        if (candidate != _root && !candidate.StartsWith(rootWithSep, StringComparison.OrdinalIgnoreCase))
            return false;

        // [AUDIT-2026-06] Sandbox (real path): Path.GetFullPath above only canonicalizes the string
        // ("..", slashes, drive-relative) — it does NOT follow symbolic links. A symlink placed
        // inside the share that points outside would pass the string check above and then be
        // followed by the OS on open → sandbox escape (critical on Unix/ZFS such as TrueNAS).
        // Resolve the real path (following links at every existing component) and re-check
        // containment. See docs/SECURITY_AUDIT.md (Finding H4).
        if (!IsWithinRealRoot(candidate))
            return false;

        fullPath = candidate;
        return true;
    }

    /// <summary>True if the symlink-resolved real path of <paramref name="candidate"/> stays within the (resolved) root.</summary>
    private bool IsWithinRealRoot(string candidate)
    {
        string? real = TryResolveRealPath(candidate);
        if (real is null) return false; // unresolvable (cyclic/broken link or error) → deny, never fail open
        if (string.Equals(real, _realRoot, StringComparison.OrdinalIgnoreCase)) return true;
        string sep = _realRoot.EndsWith(Path.DirectorySeparatorChar) ? _realRoot : _realRoot + Path.DirectorySeparatorChar;
        return real.StartsWith(sep, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Resolves an existing filesystem path to its real location, following symbolic links at
    /// <b>every</b> path component (a manual realpath — .NET has no built-in). Trailing segments
    /// that do not exist yet (e.g. a file about to be created) cannot contain a link and are
    /// appended verbatim. Returns <c>null</c> on any error so the caller fails closed.
    /// </summary>
    private static string? TryResolveRealPath(string path)
    {
        try
        {
            string full = Path.GetFullPath(path);
            string root = Path.GetPathRoot(full) ?? string.Empty;
            if (string.IsNullOrEmpty(root)) return full;

            string current = root;
            foreach (string seg in full[root.Length..].Split(
                         new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                         StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, seg);

                FileSystemInfo? info =
                    Directory.Exists(current) ? new DirectoryInfo(current) :
                    File.Exists(current) ? new FileInfo(current) : null;
                if (info is null) continue; // non-existing segment: nothing to resolve, keep appending

                FileSystemInfo? target = info.ResolveLinkTarget(returnFinalTarget: true);
                if (target is not null)
                {
                    string parent = Path.GetDirectoryName(current) ?? current;
                    current = Path.GetFullPath(Path.Combine(parent, target.FullName));
                }
            }
            return Path.GetFullPath(current);
        }
        catch
        {
            return null;
        }
    }

    private static FileEntryInfo ToEntry(FileSystemInfo info, string name)
    {
        bool isDir = (info.Attributes & FileAttributes.Directory) != 0;
        long size = isDir ? 0 : ((FileInfo)info).Length;
        return new FileEntryInfo
        {
            Name = name,
            Attributes = MapAttributes(info.Attributes),
            EndOfFile = size,
            AllocationSize = isDir ? 0 : AlignUp(size, 4096),
            CreationTime = SafeFileTime(info.CreationTimeUtc),
            LastAccessTime = SafeFileTime(info.LastAccessTimeUtc),
            LastWriteTime = SafeFileTime(info.LastWriteTimeUtc),
            ChangeTime = SafeFileTime(info.LastWriteTimeUtc),
            IndexNumber = PathId.Of(info.FullName),
        };
    }

    private static SmbFileAttributes MapAttributes(FileAttributes a)
    {
        SmbFileAttributes r = 0;
        if ((a & FileAttributes.Directory) != 0) r |= SmbFileAttributes.Directory;
        if ((a & FileAttributes.ReadOnly) != 0) r |= SmbFileAttributes.ReadOnly;
        if ((a & FileAttributes.Hidden) != 0) r |= SmbFileAttributes.Hidden;
        if ((a & FileAttributes.System) != 0) r |= SmbFileAttributes.System;
        if ((a & FileAttributes.Archive) != 0) r |= SmbFileAttributes.Archive;
        if (r == 0) r = SmbFileAttributes.Normal;
        return r;
    }

    private static long SafeFileTime(DateTime utc)
    {
        try { return utc.ToFileTimeUtc(); } catch { return 0; }
    }

    private static long AlignUp(long value, long alignment) => (value + alignment - 1) / alignment * alignment;
}

/// <summary>
/// Backend handle for a local file or directory entry. For files it owns ONE persistent
/// <see cref="FileStream"/> for the lifetime of the SMB open (O5) — READ/WRITE/flush/truncate go
/// through it instead of re-opening per request. Directories carry no stream.
/// </summary>
internal sealed class LocalFileHandle : IFileHandle
{
    private readonly string _root;
    private readonly FileStream? _stream;
    private readonly bool _isDirectory;
    private readonly object _io = new();

    public LocalFileHandle(string fullPath, string relativePath, string root, FileStream? stream, bool isDirectory)
    {
        FullPath = fullPath;
        Path = relativePath;
        _root = root;
        _stream = stream;
        _isDirectory = isDirectory;
    }

    public string FullPath { get; private set; }
    public string Path { get; private set; }
    public bool DeleteOnClose { get; set; }
    public bool IsDirectory => _isDirectory;
    public string? PhysicalPath => FullPath;

    public FileStoreResult<int> ReadAt(long offset, Span<byte> buffer)
    {
        if (_stream is null) return FileStoreResult<int>.Fail(NtStatus.InvalidParameter);
        lock (_io)
        {
            try
            {
                if (offset >= _stream.Length) return FileStoreResult<int>.Ok(0);
                _stream.Seek(offset, SeekOrigin.Begin);
                return FileStoreResult<int>.Ok(_stream.Read(buffer));
            }
            catch (IOException) { return FileStoreResult<int>.Fail(NtStatus.InvalidParameter); }
        }
    }

    public FileStoreResult<int> WriteAt(long offset, ReadOnlySpan<byte> data)
    {
        if (_stream is null || !_stream.CanWrite) return FileStoreResult<int>.Fail(NtStatus.AccessDenied);
        lock (_io)
        {
            try
            {
                _stream.Seek(offset, SeekOrigin.Begin);
                _stream.Write(data);
                return FileStoreResult<int>.Ok(data.Length);
            }
            catch (IOException) { return FileStoreResult<int>.Fail(NtStatus.DiskFull); }
        }
    }

    public NtStatus SetLength(long length)
    {
        if (_stream is null || !_stream.CanWrite) return NtStatus.AccessDenied;
        lock (_io)
        {
            try { _stream.SetLength(length); return NtStatus.Success; }
            catch (IOException) { return NtStatus.InvalidParameter; }
        }
    }

    public NtStatus FlushStream()
    {
        lock (_io)
        {
            try { _stream?.Flush(flushToDisk: true); return NtStatus.Success; }
            catch (IOException) { return NtStatus.InvalidParameter; }
        }
    }

    /// <summary>Updates the path after a rename so GetInfo/DeleteOnClose target the new location.</summary>
    public void Relocate(string newFull, string newRelative)
    {
        FullPath = newFull;
        Path = newRelative;
    }

    public FileEntryInfo GetInfo()
    {
        if (_isDirectory)
            return Build(new DirectoryInfo(FullPath), 0, isDir: true);

        var fi = new FileInfo(FullPath);
        long size;
        lock (_io) { size = _stream is not null ? _stream.Length : (fi.Exists ? fi.Length : 0); }
        return Build(fi, size, isDir: false);
    }

    private FileEntryInfo Build(FileSystemInfo info, long size, bool isDir) => new()
    {
        Name = System.IO.Path.GetFileName(FullPath),
        Attributes = isDir ? SmbFileAttributes.Directory : SmbFileAttributes.Normal,
        EndOfFile = size,
        AllocationSize = isDir ? 0 : (size + 4095) / 4096 * 4096,
        CreationTime = Safe(info.CreationTimeUtc),
        LastAccessTime = Safe(info.LastAccessTimeUtc),
        LastWriteTime = Safe(info.LastWriteTimeUtc),
        ChangeTime = Safe(info.LastWriteTimeUtc),
        IndexNumber = PathId.Of(FullPath),
    };

    private static long Safe(DateTime utc) { try { return utc.ToFileTimeUtc(); } catch { return 0; } }

    public void Dispose()
    {
        _stream?.Dispose(); // release the OS handle first so DeleteOnClose can remove the file
        if (DeleteOnClose)
        {
            try { if (_isDirectory) Directory.Delete(FullPath, true); else File.Delete(FullPath); }
            catch { /* best effort */ }
        }
    }
}

/// <summary>
/// Stable, process-independent 64-bit id derived from a file's full path (FNV-1a). Replaces
/// <c>string.GetHashCode()</c> (which .NET randomizes per process) for FileId/IndexNumber, so a
/// client sees a stable identifier across requests/reconnects (O2). Not a real inode, but stable
/// and collision-resistant within a share.
/// </summary>
internal static class PathId
{
    public static long Of(string fullPath)
    {
        const ulong offsetBasis = 14695981039346656037UL;
        const ulong prime = 1099511628211UL;
        ulong h = offsetBasis;
        foreach (char c in fullPath) { h ^= c; h *= prime; }
        return (long)(h & 0x7FFFFFFFFFFFFFFFUL); // keep positive
    }
}
