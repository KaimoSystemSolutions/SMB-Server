using Smb.Protocol.Enums;

namespace Smb.FileSystem.Local;

/// <summary>
/// <see cref="IFileStore"/> backed by a local directory. Paths are share-relative
/// (backslash-separated, no leading backslash) and are protected against escaping from the
/// root directory (no <c>..</c> escape, Context §13.4). Read/Write/List/Stat.
/// </summary>
public sealed class LocalFileStore : IFileStore
{
    private readonly string _root;
    private readonly bool _readOnly;

    public LocalFileStore(string rootDirectory, bool readOnly = true)
    {
        _root = Path.GetFullPath(rootDirectory);
        Directory.CreateDirectory(_root);
        _readOnly = readOnly;
    }

    public FileStoreResult<IFileHandle> Create(
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

        switch (disposition)
        {
            case CreateDispositionIntent.Open:
                if (!exists) return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);
                createAction = CreateOutcome.Opened;
                break;

            case CreateDispositionIntent.Create:
                if (exists) return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameCollision);
                CreateNew(full, directoryRequired);
                createAction = CreateOutcome.Created;
                break;

            case CreateDispositionIntent.OpenIf:
                if (!exists) { CreateNew(full, directoryRequired); createAction = CreateOutcome.Created; }
                else createAction = CreateOutcome.Opened;
                break;

            case CreateDispositionIntent.Overwrite:
                if (!exists) return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);
                if (isFile) File.WriteAllBytes(full, []);
                createAction = CreateOutcome.Overwritten;
                break;

            case CreateDispositionIntent.OverwriteIf:
            case CreateDispositionIntent.Supersede:
                if (exists && isFile) File.WriteAllBytes(full, []);
                else if (!exists) CreateNew(full, directoryRequired);
                createAction = exists ? CreateOutcome.Overwritten : CreateOutcome.Created;
                break;
        }

        return FileStoreResult<IFileHandle>.Ok(new LocalFileHandle(full, Path.GetFullPath(full) == _root ? string.Empty : path, _root));
    }

    public FileStoreResult<int> Read(IFileHandle handle, long offset, Span<byte> buffer)
    {
        var h = (LocalFileHandle)handle;
        if (h.IsDirectory) return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
        try
        {
            using var fs = new FileStream(h.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (offset >= fs.Length) return FileStoreResult<int>.Ok(0); // EOF: 0 bytes read (handler maps to STATUS_END_OF_FILE)
            fs.Seek(offset, SeekOrigin.Begin);
            int read = fs.Read(buffer);
            return FileStoreResult<int>.Ok(read);
        }
        catch (IOException) { return FileStoreResult<int>.Fail(NtStatus.InvalidParameter); }
    }

    public FileStoreResult<int> Write(IFileHandle handle, long offset, ReadOnlySpan<byte> data)
    {
        if (_readOnly) return FileStoreResult<int>.Fail(NtStatus.AccessDenied);
        var h = (LocalFileHandle)handle;
        if (h.IsDirectory) return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
        try
        {
            using var fs = new FileStream(h.FullPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite);
            fs.Seek(offset, SeekOrigin.Begin);
            fs.Write(data);
            return FileStoreResult<int>.Ok(data.Length);
        }
        catch (IOException) { return FileStoreResult<int>.Fail(NtStatus.DiskFull); }
    }

    public FileStoreResult<IReadOnlyList<FileEntryInfo>> QueryDirectory(IFileHandle handle, string searchPattern)
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

    public NtStatus SetEndOfFile(IFileHandle handle, long length)
    {
        if (_readOnly) return NtStatus.AccessDenied;
        var h = (LocalFileHandle)handle;
        try { using var fs = new FileStream(h.FullPath, FileMode.Open, FileAccess.Write); fs.SetLength(length); return NtStatus.Success; }
        catch (IOException) { return NtStatus.InvalidParameter; }
    }

    public NtStatus Rename(IFileHandle handle, string newPath, bool replaceIfExists)
    {
        if (_readOnly) return NtStatus.AccessDenied;
        var h = (LocalFileHandle)handle;
        if (!TryResolve(newPath, out string dest)) return NtStatus.ObjectPathNotFound;
        try
        {
            if (File.Exists(dest) && !replaceIfExists) return NtStatus.ObjectNameCollision;
            if (h.IsDirectory) Directory.Move(h.FullPath, dest);
            else File.Move(h.FullPath, dest, replaceIfExists);
            return NtStatus.Success;
        }
        catch (IOException) { return NtStatus.AccessDenied; }
    }

    public NtStatus SetDeleteOnClose(IFileHandle handle, bool delete)
    {
        if (_readOnly && delete) return NtStatus.AccessDenied;
        ((LocalFileHandle)handle).DeleteOnClose = delete;
        return NtStatus.Success;
    }

    public NtStatus Flush(IFileHandle handle) => NtStatus.Success;

    private void CreateNew(string full, bool directory)
    {
        if (directory) Directory.CreateDirectory(full);
        else File.Create(full).Dispose();
    }

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

        // Sandbox: must stay within root (no .. escape, Context §13.4).
        string rootWithSep = _root.EndsWith(Path.DirectorySeparatorChar) ? _root : _root + Path.DirectorySeparatorChar;
        if (candidate != _root && !candidate.StartsWith(rootWithSep, StringComparison.OrdinalIgnoreCase))
            return false;

        fullPath = candidate;
        return true;
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

/// <summary>Backend handle for a local file or directory entry.</summary>
internal sealed class LocalFileHandle : IFileHandle
{
    private readonly string _root;

    public LocalFileHandle(string fullPath, string relativePath, string root)
    {
        FullPath = fullPath;
        Path = relativePath;
        _root = root;
    }

    public string FullPath { get; }
    public string Path { get; }
    public bool DeleteOnClose { get; set; }
    public bool IsDirectory => Directory.Exists(FullPath);
    public string? PhysicalPath => FullPath;

    public FileEntryInfo GetInfo()
    {
        FileSystemInfo info = IsDirectory ? new DirectoryInfo(FullPath) : new FileInfo(FullPath);
        bool isDir = IsDirectory;
        long size = isDir ? 0 : ((FileInfo)info).Length;
        return new FileEntryInfo
        {
            Name = System.IO.Path.GetFileName(FullPath),
            Attributes = isDir ? SmbFileAttributes.Directory : SmbFileAttributes.Normal,
            EndOfFile = size,
            AllocationSize = isDir ? 0 : (size + 4095) / 4096 * 4096,
            CreationTime = Safe(info.CreationTimeUtc),
            LastAccessTime = Safe(info.LastAccessTimeUtc),
            LastWriteTime = Safe(info.LastWriteTimeUtc),
            ChangeTime = Safe(info.LastWriteTimeUtc),
        };
    }

    private static long Safe(DateTime utc) { try { return utc.ToFileTimeUtc(); } catch { return 0; } }

    public void Dispose()
    {
        if (DeleteOnClose)
        {
            try { if (IsDirectory) Directory.Delete(FullPath, true); else File.Delete(FullPath); }
            catch { /* best effort */ }
        }
    }
}
