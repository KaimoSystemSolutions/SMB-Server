using Microsoft.Win32.SafeHandles;
using System.IO.Enumeration;
using Smb.FileSystem.Security;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Security;

namespace Smb.FileSystem.Local;

/// <summary>
/// <see cref="IFileStore"/> backed by a local directory. Paths are share-relative
/// (backslash-separated, no leading backslash) and are protected against escaping from the
/// root directory (no <c>..</c> escape, Context §13.4). Read/Write/List/Stat.
/// Synchronously attached via <see cref="SyncFileStore"/>.
/// </summary>
public sealed class LocalFileStore : SyncFileStore, INamedStreamStore, IExtendedAttributeStore, IBasicInfoStore
{
    private readonly string _root;
    private readonly string _realRoot;
    private readonly bool _readOnly;
    private readonly ISecurityDescriptorStore _securityStore;

    // [Phase 9] Alternate data streams (M9.1) and extended attributes (M9.2). The default backing is
    // in-process (portable + testable, enough for SMB-level semantics); a deployment that needs real
    // NTFS ADS / OS xattr provides its own IFileStore. Streams are keyed by base physical path + the
    // case-folded stream name; EAs by physical path. Guarded by a single lock (operations are short).
    private sealed class StreamData { public required string Name; public byte[] Content = []; }
    private readonly object _adsLock = new();
    private readonly Dictionary<string, StreamData> _streams = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<ExtendedAttribute>> _eas = new(StringComparer.Ordinal);

    public LocalFileStore(string rootDirectory, bool readOnly = true, ISecurityDescriptorStore? securityStore = null)
    {
        _root = Path.GetFullPath(rootDirectory);
        Directory.CreateDirectory(_root);
        // Real (symlink-resolved) root for the sandbox check below. The root itself may
        // legitimately live under a symlink (e.g. /mnt/tank/... on ZFS), so both sides of
        // the containment check must be resolved consistently.
        _realRoot = TryResolveRealPath(_root) ?? _root;
        _readOnly = readOnly;
        _securityStore = securityStore ?? new InMemorySecurityDescriptorStore();
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
        {
            FileStoreResult<IFileHandle> dir = CreateDirectoryHandle(full, relative, disposition, exists, out createAction);
            if (dir.IsSuccess && createAction == CreateOutcome.Created)
                ApplyInheritedSecurity(full, isDirectory: true);
            return dir;
        }

        // Regular file: open ONE persistent OS handle for the lifetime of the SMB open (instead of
        // re-opening per READ/WRITE — O5). FileShare here is permissive; cross-open sharing semantics
        // (CREATE ShareAccess) are enforced server-side by the IShareModeManager, which also works on
        // Unix where OS FileShare is advisory only.
        FileStoreResult<IFileHandle> file = CreateFileHandle(full, relative, access, disposition, exists, out createAction);
        if (file.IsSuccess && createAction == CreateOutcome.Created)
            ApplyInheritedSecurity(full, isDirectory: false);
        return file;
    }

    /// <summary>
    /// [M3.3] On creating a new entry, inherit the parent directory's inheritable ACEs (MS-DTYP
    /// §2.5.3.4) into a stored descriptor for the child. Applied only when the parent has an explicit
    /// descriptor — a share that never sets an ACL keeps the permissive default for new files, so the
    /// prior behavior is unchanged.
    /// </summary>
    private void ApplyInheritedSecurity(string childFull, bool isDirectory)
    {
        string? parent = Path.GetDirectoryName(childFull);
        if (parent is null)
            return;
        SecurityDescriptor? parentSd = _securityStore.TryGet(parent);
        if (parentSd is null)
            return;
        SecurityDescriptor? inherited = AclInheritance.ComputeInherited(parentSd, isDirectory);
        if (inherited is not null)
            _securityStore.Set(childFull, inherited);
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
            // bufferSize 1 disables FileStream's user-space read/write buffering. The async ReadAsync/
            // WriteAsync overrides open a fresh OS handle per request (overlapped I/O), so a buffered
            // read here could return stale bytes, and a buffered write could stay invisible to those
            // fresh handles until flush/close. Unbuffered keeps this persistent handle coherent with them.
            var stream = new FileStream(full, mode, fileAccess, share, bufferSize: 1);
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
        if (handle is NamedStreamHandle ns) return StreamRead(ns.BaseFullPath, ns.StreamName, offset, buffer);
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
        if (handle is NamedStreamHandle ns) return StreamRead(ns.BaseFullPath, ns.StreamName, offset, buffer.Span);
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
        if (handle is NamedStreamHandle ns) return StreamWrite(ns.BaseFullPath, ns.StreamName, offset, data);
        if (_readOnly) return FileStoreResult<int>.Fail(NtStatus.AccessDenied);
        var h = (LocalFileHandle)handle;
        if (h.IsDirectory) return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
        return h.WriteAt(offset, data);
    }

    /// <summary>True async write — counterpart to <see cref="ReadAsync"/> (A5). Semantics like <see cref="Write"/>.</summary>
    public override async ValueTask<FileStoreResult<int>> WriteAsync(
        IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        if (handle is NamedStreamHandle ns) return StreamWrite(ns.BaseFullPath, ns.StreamName, offset, data.Span);
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

        // Prepend "." and ".." — but only when the search pattern matches them, like any other entry
        // (FsRtlIsNameInExpression semantics; wildcards match, a specific name does not). Synthesizing
        // them unconditionally broke Explorer's new-folder flow: its post-CREATE lookup with the exact
        // folder name + SL_RETURN_SINGLE_ENTRY got "." as the single entry, so the new folder displayed
        // as "." and the inline-rename box never opened. It also masked STATUS_NO_SUCH_FILE for
        // non-matching specific patterns (the list was never empty).
        var dirInfo = new DirectoryInfo(h.FullPath);
        if (FileSystemName.MatchesWin32Expression(pattern, "."))
            entries.Add(ToEntry(dirInfo, "."));
        if (Path.GetFullPath(h.FullPath) != _root && FileSystemName.MatchesWin32Expression(pattern, ".."))
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

    /// <summary>
    /// [D2] Bounded enumeration that stops early so a huge directory is never fully materialized.
    /// <see cref="DirectoryInfo.EnumerateFileSystemInfos(string)"/> is lazy, so this allocates at most
    /// <paramref name="maxEntries"/> (+1 to detect overflow) entries. The synthetic "." / ".." entries
    /// count toward the bound like any other.
    /// </summary>
    protected override FileStoreResult<BoundedDirectoryListing> QueryDirectory(IFileHandle handle, string searchPattern, int maxEntries)
    {
        var h = (LocalFileHandle)handle;
        if (!h.IsDirectory) return FileStoreResult<BoundedDirectoryListing>.Fail(NtStatus.InvalidParameter);

        string pattern = string.IsNullOrEmpty(searchPattern) ? "*" : searchPattern;
        var entries = new List<FileEntryInfo>();

        // Pattern-gated "." / ".." synthesis — same rule as the unbounded overload above.
        var dirInfo = new DirectoryInfo(h.FullPath);
        if (FileSystemName.MatchesWin32Expression(pattern, "."))
            entries.Add(ToEntry(dirInfo, "."));
        if (Path.GetFullPath(h.FullPath) != _root && FileSystemName.MatchesWin32Expression(pattern, ".."))
            entries.Add(ToEntry(dirInfo.Parent ?? dirInfo, ".."));

        bool truncated = false;
        try
        {
            foreach (FileSystemInfo info in dirInfo.EnumerateFileSystemInfos(pattern))
            {
                if (maxEntries > 0 && entries.Count >= maxEntries)
                {
                    truncated = true;
                    break;
                }
                entries.Add(ToEntry(info, info.Name));
            }
        }
        catch (DirectoryNotFoundException)
        {
            return FileStoreResult<BoundedDirectoryListing>.Fail(NtStatus.ObjectNameNotFound);
        }

        return FileStoreResult<BoundedDirectoryListing>.Ok(new BoundedDirectoryListing(entries, truncated));
    }

    protected override NtStatus SetEndOfFile(IFileHandle handle, long length)
    {
        if (_readOnly) return NtStatus.AccessDenied;
        if (handle is NamedStreamHandle ns) return StreamSetLength(ns.BaseFullPath, ns.StreamName, length);
        return ((LocalFileHandle)handle).SetLength(length);
    }

    protected override NtStatus Rename(IFileHandle handle, string newPath, bool replaceIfExists)
    {
        if (_readOnly) return NtStatus.AccessDenied;
        if (handle is NamedStreamHandle) return NtStatus.NotSupported; // renaming a stream is not modeled
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

    /// <summary>
    /// [IBasicInfoStore] Applies SET_INFO/FileBasicInformation to the real file: the timestamps a copy stamps
    /// onto its destination, and the DOS attributes behind Explorer's read-only/hidden checkboxes.
    /// <para>
    /// Applied to the path rather than the open handle: the handle exists, but .NET exposes no
    /// SetFileTime/SetFileAttributes on <see cref="FileStream"/>, and the store opens with FileShare.ReadWrite
    /// so a second, short-lived handle on the same path is not a conflict. ChangeTime has no OS-level setter
    /// on either platform — the filesystem owns it — so it is accepted and left to the filesystem.
    /// </para>
    /// </summary>
    public ValueTask<NtStatus> SetBasicInfoAsync(
        IFileHandle handle, FileBasicInfoUpdate update, CancellationToken cancellationToken = default)
    {
        if (_readOnly) return new(NtStatus.AccessDenied);
        // A named stream shares the base file's timestamps and attributes.
        string path = handle is NamedStreamHandle ns ? ns.BaseFullPath : ((LocalFileHandle)handle).FullPath;

        try
        {
            bool isDir = Directory.Exists(path);
            if (update.CreationTime is { } created)
                SetTime(path, isDir, File.SetCreationTimeUtc, Directory.SetCreationTimeUtc, created);
            if (update.LastAccessTime is { } accessed)
                SetTime(path, isDir, File.SetLastAccessTimeUtc, Directory.SetLastAccessTimeUtc, accessed);
            if (update.LastWriteTime is { } written)
                SetTime(path, isDir, File.SetLastWriteTimeUtc, Directory.SetLastWriteTimeUtc, written);

            // A directory's FILE_ATTRIBUTE_DIRECTORY is owned by the filesystem; masking it off would be an
            // attempt to turn the directory into a file. Keep only the bits a client may actually set.
            if (update.Attributes is { } attrs)
                File.SetAttributes(path, (FileAttributes)(attrs & SettableAttributes));

            return new(NtStatus.Success);
        }
        catch (UnauthorizedAccessException) { return new(NtStatus.AccessDenied); }
        catch (ArgumentOutOfRangeException) { return new(NtStatus.InvalidParameter); } // FILETIME out of range
        catch (IOException) { return new(NtStatus.AccessDenied); }

        static void SetTime(string path, bool isDir, Action<string, DateTime> setFile,
            Action<string, DateTime> setDir, long fileTime)
        {
            DateTime value = DateTime.FromFileTimeUtc(fileTime);
            if (isDir) setDir(path, value); else setFile(path, value);
        }
    }

    /// <summary>
    /// The FILE_ATTRIBUTE_* bits a client may set via FileBasicInformation. DIRECTORY/REPARSE_POINT and the
    /// other filesystem-owned bits are dropped rather than rejected — Windows sends back the full mask it read
    /// from a QUERY_INFO, so treating those bits as an error would fail ordinary round trips.
    /// </summary>
    private const uint SettableAttributes =
        0x1 /* ReadOnly */ | 0x2 /* Hidden */ | 0x4 /* System */ | 0x20 /* Archive */ |
        0x80 /* Normal */ | 0x100 /* Temporary */ | 0x2000 /* NotContentIndexed */;

    protected override NtStatus SetDeleteOnClose(IFileHandle handle, bool delete)
    {
        if (_readOnly && delete) return NtStatus.AccessDenied;

        // MS-FSA §2.1.5.14.3: marking a file (or a stream of it) delete-pending while it carries
        // FILE_ATTRIBUTE_READONLY must fail with STATUS_CANNOT_DELETE. Explorer relies on the decline:
        // it asks the user, clears the attribute and retries — a server that deletes anyway removes
        // files Windows promised were protected.
        if (delete && HasReadOnlyAttribute(handle))
            return NtStatus.CannotDelete;

        if (handle is NamedStreamHandle ns) { ns.DeleteOnClose = delete; return NtStatus.Success; }
        ((LocalFileHandle)handle).DeleteOnClose = delete;
        return NtStatus.Success;
    }

    private static bool HasReadOnlyAttribute(IFileHandle handle)
    {
        string path = handle is NamedStreamHandle ns ? ns.BaseFullPath : ((LocalFileHandle)handle).FullPath;
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReadOnly) != 0;
        }
        catch (IOException)
        {
            return false; // no attributes to protect (e.g. just created, or already gone)
        }
    }

    protected override NtStatus Flush(IFileHandle handle)
        => handle is NamedStreamHandle ? NtStatus.Success : ((LocalFileHandle)handle).FlushStream();

    /// <summary>
    /// Returns the stored security descriptor for the handle, or a permissive default (owner Local
    /// System, DACL granting Everyone full control) when none has been set — so a file with no explicit
    /// ACL behaves as before. Descriptors live in the injected <see cref="ISecurityDescriptorStore"/>.
    /// </summary>
    public override ValueTask<FileStoreResult<SecurityDescriptor>> GetSecurityAsync(
        IFileHandle handle, CancellationToken cancellationToken = default)
    {
        // A named stream shares the base file's security descriptor.
        string key = handle is NamedStreamHandle ns ? ns.BaseFullPath : ((LocalFileHandle)handle).FullPath;
        SecurityDescriptor sd = _securityStore.TryGet(key) ?? DefaultDescriptor();
        return new(FileStoreResult<SecurityDescriptor>.Ok(sd));
    }

    public override ValueTask<NtStatus> SetSecurityAsync(
        IFileHandle handle, SecurityDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        if (_readOnly) return new(NtStatus.AccessDenied);
        string key = handle is NamedStreamHandle ns ? ns.BaseFullPath : ((LocalFileHandle)handle).FullPath;
        _securityStore.Set(key, descriptor);
        return new(NtStatus.Success);
    }

    // ---------------------------------------------------------------------
    //  [Phase 9 / M9.1] Alternate data streams
    // ---------------------------------------------------------------------

    /// <inheritdoc/>
    public ValueTask<FileStoreResult<FileCreateResult>> OpenNamedStreamAsync(
        string basePath, string streamName, FileAccessIntent access, CreateDispositionIntent disposition,
        CancellationToken cancellationToken = default)
    {
        if (!TryResolve(basePath, out string fullBase))
            return Fail(NtStatus.ObjectNameNotFound);

        bool wantsWrite = access.HasFlag(FileAccessIntent.Write) || disposition is
            CreateDispositionIntent.Create or CreateDispositionIntent.Overwrite or
            CreateDispositionIntent.OverwriteIf or CreateDispositionIntent.Supersede;
        if (_readOnly && wantsWrite)
            return Fail(NtStatus.AccessDenied);

        // A data stream requires an existing base file (directory streams are not modeled here).
        if (!File.Exists(fullBase))
            return Fail(NtStatus.ObjectNameNotFound);

        string key = StreamKey(fullBase, streamName);
        CreateOutcome outcome;
        lock (_adsLock)
        {
            bool exists = _streams.ContainsKey(key);
            switch (disposition)
            {
                case CreateDispositionIntent.Open:
                    if (!exists) return Fail(NtStatus.ObjectNameNotFound);
                    outcome = CreateOutcome.Opened;
                    break;
                case CreateDispositionIntent.Create:
                    if (exists) return Fail(NtStatus.ObjectNameCollision);
                    _streams[key] = new StreamData { Name = streamName };
                    outcome = CreateOutcome.Created;
                    break;
                case CreateDispositionIntent.Overwrite:
                    if (!exists) return Fail(NtStatus.ObjectNameNotFound);
                    _streams[key] = new StreamData { Name = streamName };
                    outcome = CreateOutcome.Overwritten;
                    break;
                case CreateDispositionIntent.OpenIf:
                    if (!exists) { _streams[key] = new StreamData { Name = streamName }; outcome = CreateOutcome.Created; }
                    else outcome = CreateOutcome.Opened;
                    break;
                case CreateDispositionIntent.OverwriteIf:
                    outcome = exists ? CreateOutcome.Overwritten : CreateOutcome.Created;
                    _streams[key] = new StreamData { Name = streamName };
                    break;
                default: // Supersede
                    outcome = exists ? CreateOutcome.Superseded : CreateOutcome.Created;
                    _streams[key] = new StreamData { Name = streamName };
                    break;
            }
        }

        var handle = new NamedStreamHandle(this, fullBase, streamName);
        return new(FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(handle, outcome)));

        static ValueTask<FileStoreResult<FileCreateResult>> Fail(NtStatus s)
            => new(FileStoreResult<FileCreateResult>.Fail(s));
    }

    /// <inheritdoc/>
    public ValueTask<FileStoreResult<IReadOnlyList<StreamInfo>>> QueryStreamsAsync(
        IFileHandle handle, CancellationToken cancellationToken = default)
    {
        string fullBase = handle is NamedStreamHandle ns ? ns.BaseFullPath : ((LocalFileHandle)handle).FullPath;
        var list = new List<StreamInfo>();

        // The default unnamed $DATA stream exists for a regular file (a directory has no data stream).
        if (File.Exists(fullBase))
        {
            long size = new FileInfo(fullBase).Length;
            list.Add(new StreamInfo(string.Empty, size, AlignUp(size, 4096)));
        }

        string prefix = fullBase + "\u0000";
        lock (_adsLock)
        {
            foreach (KeyValuePair<string, StreamData> kv in _streams)
                if (kv.Key.StartsWith(prefix, StringComparison.Ordinal))
                    list.Add(new StreamInfo(kv.Value.Name, kv.Value.Content.Length, AlignUp(kv.Value.Content.Length, 4096)));
        }
        return new(FileStoreResult<IReadOnlyList<StreamInfo>>.Ok(list));
    }

    private static string StreamKey(string fullBase, string streamName)
        => fullBase + "\u0000" + streamName.ToUpperInvariant();

    internal FileStoreResult<int> StreamRead(string fullBase, string streamName, long offset, Span<byte> buffer)
    {
        lock (_adsLock)
        {
            if (!_streams.TryGetValue(StreamKey(fullBase, streamName), out StreamData? s))
                return FileStoreResult<int>.Fail(NtStatus.FileClosed);
            if (offset < 0 || offset >= s.Content.Length) return FileStoreResult<int>.Ok(0);
            int n = (int)Math.Min(buffer.Length, s.Content.Length - offset);
            s.Content.AsSpan((int)offset, n).CopyTo(buffer);
            return FileStoreResult<int>.Ok(n);
        }
    }

    internal FileStoreResult<int> StreamWrite(string fullBase, string streamName, long offset, ReadOnlySpan<byte> data)
    {
        if (_readOnly) return FileStoreResult<int>.Fail(NtStatus.AccessDenied);
        if (offset < 0) return FileStoreResult<int>.Fail(NtStatus.InvalidParameter);
        lock (_adsLock)
        {
            if (!_streams.TryGetValue(StreamKey(fullBase, streamName), out StreamData? s))
                return FileStoreResult<int>.Fail(NtStatus.FileClosed);
            long end = offset + data.Length;
            if (end > s.Content.Length)
            {
                var grown = new byte[end];
                s.Content.CopyTo(grown, 0);
                s.Content = grown;
            }
            data.CopyTo(s.Content.AsSpan((int)offset));
            return FileStoreResult<int>.Ok(data.Length);
        }
    }

    internal NtStatus StreamSetLength(string fullBase, string streamName, long length)
    {
        if (_readOnly) return NtStatus.AccessDenied;
        if (length < 0) return NtStatus.InvalidParameter;
        lock (_adsLock)
        {
            if (!_streams.TryGetValue(StreamKey(fullBase, streamName), out StreamData? s))
                return NtStatus.FileClosed;
            var resized = new byte[length];
            Array.Copy(s.Content, resized, Math.Min(s.Content.Length, length));
            s.Content = resized;
            return NtStatus.Success;
        }
    }

    internal long StreamLength(string fullBase, string streamName)
    {
        lock (_adsLock)
            return _streams.TryGetValue(StreamKey(fullBase, streamName), out StreamData? s) ? s.Content.Length : 0;
    }

    internal void StreamRemove(string fullBase, string streamName)
    {
        lock (_adsLock) _streams.Remove(StreamKey(fullBase, streamName));
    }

    // ---------------------------------------------------------------------
    //  [Phase 9 / M9.2] Extended attributes
    // ---------------------------------------------------------------------

    /// <inheritdoc/>
    public ValueTask<FileStoreResult<IReadOnlyList<ExtendedAttribute>>> GetExtendedAttributesAsync(
        IFileHandle handle, CancellationToken cancellationToken = default)
    {
        string key = EaKey(handle);
        lock (_adsLock)
        {
            if (_eas.TryGetValue(key, out List<ExtendedAttribute>? list))
                return new(FileStoreResult<IReadOnlyList<ExtendedAttribute>>.Ok(list.ToArray()));
        }
        return new(FileStoreResult<IReadOnlyList<ExtendedAttribute>>.Ok(Array.Empty<ExtendedAttribute>()));
    }

    /// <inheritdoc/>
    public ValueTask<NtStatus> SetExtendedAttributesAsync(
        IFileHandle handle, IReadOnlyList<ExtendedAttribute> entries, CancellationToken cancellationToken = default)
    {
        if (_readOnly) return new(NtStatus.AccessDenied);
        string key = EaKey(handle);
        lock (_adsLock)
        {
            if (!_eas.TryGetValue(key, out List<ExtendedAttribute>? list))
                _eas[key] = list = new List<ExtendedAttribute>();

            foreach (ExtendedAttribute e in entries)
            {
                list.RemoveAll(x => string.Equals(x.Name, e.Name, StringComparison.OrdinalIgnoreCase));
                if (e.Value is { Length: > 0 })   // a zero-length value deletes the attribute (§2.4.15)
                    list.Add(e);
            }
            if (list.Count == 0) _eas.Remove(key);
        }
        return new(NtStatus.Success);
    }

    private static string EaKey(IFileHandle handle)
        => handle is NamedStreamHandle ns ? ns.BaseFullPath : ((LocalFileHandle)handle).FullPath;

    /// <summary>The implicit ACL for a file that has none set: everyone gets full control (0x1F01FF).</summary>
    private static SecurityDescriptor DefaultDescriptor()
    {
        var dacl = new Acl { Aces = [Ace.Allow(WellKnownSids.Everyone, 0x001F01FF)] };
        return SecurityDescriptor.Create(WellKnownSids.LocalSystem, WellKnownSids.BuiltinUsers, dacl);
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

    /// <summary>Maps real filesystem attributes to their SMB bits. Shared with <see cref="LocalFileHandle"/>,
    /// so a stat of an open handle reports the same attributes as a directory listing of the same file.</summary>
    internal static SmbFileAttributes MapAttributes(FileAttributes a)
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
/// [Phase 9 / M9.1] Backend handle for a named alternate data stream of a local file. Content lives in
/// the owning <see cref="LocalFileStore"/>'s in-process stream table; all I/O routes back through the
/// store. <see cref="PhysicalPath"/> is the base file so directory-lease / security keying is unchanged.
/// </summary>
internal sealed class NamedStreamHandle : IFileHandle
{
    private readonly LocalFileStore _store;

    public NamedStreamHandle(LocalFileStore store, string baseFullPath, string streamName)
    {
        _store = store;
        BaseFullPath = baseFullPath;
        StreamName = streamName;
    }

    public string BaseFullPath { get; }
    public string StreamName { get; }
    public bool DeleteOnClose { get; set; }
    public string Path => System.IO.Path.GetFileName(BaseFullPath) + ":" + StreamName;
    public bool IsDirectory => false;
    public string? PhysicalPath => BaseFullPath;

    public FileEntryInfo GetInfo()
    {
        long size = _store.StreamLength(BaseFullPath, StreamName);
        var fi = new FileInfo(BaseFullPath);
        long ct = Safe(fi, static f => f.CreationTimeUtc);
        long at = Safe(fi, static f => f.LastAccessTimeUtc);
        long wt = Safe(fi, static f => f.LastWriteTimeUtc);
        return new FileEntryInfo
        {
            Name = System.IO.Path.GetFileName(BaseFullPath) + ":" + StreamName + ":$DATA",
            Attributes = SmbFileAttributes.Normal,
            EndOfFile = size,
            AllocationSize = (size + 4095) / 4096 * 4096,
            CreationTime = ct,
            LastAccessTime = at,
            LastWriteTime = wt,
            ChangeTime = wt,
            IndexNumber = PathId.Of(BaseFullPath + ":" + StreamName),
        };
    }

    private static long Safe(FileInfo fi, Func<FileInfo, DateTime> pick)
    {
        try { return fi.Exists ? pick(fi).ToFileTimeUtc() : 0; } catch { return 0; }
    }

    public void Dispose()
    {
        if (DeleteOnClose) _store.StreamRemove(BaseFullPath, StreamName);
    }
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
        // The file's real attributes, not a constant. Reporting Normal here made a QUERY_INFO on an open
        // handle disagree with a directory listing of the same file (which has always mapped them): a hidden
        // or read-only file looked Normal in its Properties dialog, and a SET of those bits read back as if
        // it had been ignored.
        Attributes = LocalFileStore.MapAttributes(info.Attributes),
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
