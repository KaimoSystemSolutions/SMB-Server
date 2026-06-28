using Smb.FileSystem;
using Smb.FileSystem.Versioning;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Messages.Fscc;
using Smb.Server.Oplocks;
using Smb.Server.Rpc;
using Smb.Server.Sharing;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// File commands (M4, Context §13–§16): CREATE, CLOSE, READ, WRITE, QUERY_DIRECTORY,
/// QUERY_INFO via an <see cref="IFileStore"/> backend. Read-only browsing works
/// fully; writing depends on backend configuration.
/// </summary>
public sealed partial class Smb2Dispatcher
{
    // Access mask bits (Context §13.1).
    private const uint FileReadData = 0x00000001, FileWriteData = 0x00000002, FileAppendData = 0x00000004;
    private const uint Delete = 0x00010000, GenericRead = 0x80000000, GenericWrite = 0x40000000;
    private const uint GenericAll = 0x10000000, MaximumAllowed = 0x02000000;

    private bool TryGetFileStore(SmbSession session, uint treeId, out IFileStore store, out NtStatus error)
    {
        store = null!;
        error = NtStatus.Success;
        if (!session.TreeConnects.TryGetValue(treeId, out SmbTreeConnect? tree))
        {
            error = NtStatus.NetworkNameDeleted;
            return false;
        }
        if (tree.Share.FileStore is null)
        {
            error = NtStatus.NotSupported; // e.g. IPC$ without a file backend
            return false;
        }
        store = tree.Share.FileStore;
        return true;
    }

    private bool TryGetOpen(SmbSession session, ulong persistent, ulong volatileId, out SmbOpen open)
        => session.Opens.TryGetValue((persistent, volatileId), out open!);

    private ResponseSegment HandleCreate(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);
        if (!session.TreeConnects.TryGetValue(header.TreeId, out SmbTreeConnect? tree))
            return BuildError(header, NtStatus.NetworkNameDeleted);

        // Named-pipe share (IPC$): open a DCERPC pipe instead of using the file backend.
        if (tree.Share.Type == ShareType.Pipe)
            return HandlePipeCreate(connection, header, session, tree, segment);

        if (tree.Share.FileStore is not { } store)
            return BuildError(header, NtStatus.NotSupported);

        CreateRequest request = CreateRequest.Parse(segment, Smb2Header.Size);

        // [AUDIT-2026-06] Enforce DesiredAccess against the MaximalAccess granted by the
        // authorization policy (§3.3.5.9). Previously DesiredAccess was granted unfiltered →
        // a policy with reduced rights (e.g. ReadOnly per user/group) had no effect on file
        // operations; only the global readOnly flag of the FileStore limited access.
        // MAXIMUM_ALLOWED grants exactly the permitted mask. Comparison at intent level
        // (Read/Write/Delete) to handle generic bits correctly.
        // See docs/SECURITY_AUDIT.md (Finding H3).
        FileAccessIntent allowedIntent = MapAccess(tree.MaximalAccess);
        bool maximumAllowed = (request.DesiredAccess & MaximumAllowed) != 0;
        FileAccessIntent access = maximumAllowed ? allowedIntent : MapAccess(request.DesiredAccess);
        if (!maximumAllowed && (access & ~allowedIntent) != 0)
            return BuildError(header, NtStatus.AccessDenied);
        uint grantedAccess = maximumAllowed ? tree.MaximalAccess : request.DesiredAccess;

        var disposition = (CreateDispositionIntent)(uint)request.Disposition;
        bool dirRequired = request.Options.HasFlag(CreateOptions.DirectoryFile);
        bool nonDirRequired = request.Options.HasFlag(CreateOptions.NonDirectoryFile);

        // Allocate the open up front so the share-mode reservation can be keyed to it.
        ulong volatileId = connection.AllocateFileId();
        var open = new SmbOpen
        {
            PersistentFileId = 0,
            VolatileFileId = volatileId,
            Session = session,
            TreeConnect = tree,
            GrantedAccess = grantedAccess,
            PathName = request.Name,
        };

        // [O5] Sharing-violation check BEFORE the backend acts, so a conflict causes no side effects
        // (e.g. truncation). Keyed on the share-scoped logical path; released at CLOSE/teardown.
        string shareKey = ShareModeKey(tree, request.Name);
        if (!_server.Options.ShareModeManager.TryOpen(shareKey, open, access, MapShare(request.ShareAccess)))
            return BuildError(header, NtStatus.SharingViolation);
        open.ShareModeKey = shareKey;

        FileStoreResult<IFileHandle> result = store.Create(
            request.Name, access, disposition, dirRequired, nonDirRequired, out CreateOutcome outcome);
        if (!result.IsSuccess)
        {
            _server.Options.ShareModeManager.Close(shareKey, open);
            return BuildError(header, result.Status);
        }

        IFileHandle handle = result.Value!;
        open.LocalOpen = handle;
        if (request.Options.HasFlag(CreateOptions.DeleteOnClose))
        {
            // DELETE_ON_CLOSE may require the Delete permission (enforced by the backend). Honor a
            // denial here instead of silently dropping it: roll the open back and fail the CREATE.
            NtStatus delStatus = store.SetDeleteOnClose(handle, true);
            if (delStatus != NtStatus.Success)
            {
                handle.Dispose();
                _server.Options.ShareModeManager.Close(shareKey, open);
                return BuildError(header, delStatus);
            }
        }

        session.Opens[open.Key] = open;
        Interlocked.Increment(ref tree.OpenCount);

        // Request oplock (Context §15): the manager determines the granted level and delivers
        // any breaks due to other holders, who are notified out-of-band.
        OplockGrant grant = _server.Options.OplockManager.RequestOplock(open, request.RequestedOplockLevel);
        open.OplockLevel = grant.GrantedLevel;
        DispatchOplockBreaks(grant.Breaks);

        FileEntryInfo info = handle.GetInfo();
        var response = new CreateResponse
        {
            OplockLevel = grant.GrantedLevel,
            CreateAction = (CreateAction)(uint)outcome,
            CreationTime = info.CreationTime,
            LastAccessTime = info.LastAccessTime,
            LastWriteTime = info.LastWriteTime,
            ChangeTime = info.ChangeTime,
            AllocationSize = info.AllocationSize,
            EndOfFile = info.EndOfFile,
            FileAttributes = (uint)info.Attributes,
            PersistentFileId = open.PersistentFileId,
            VolatileFileId = open.VolatileFileId,
        };

        return MaybeSigned(session, RespHeader(header, session), response.ToBody());
    }

    private ResponseSegment HandlePipeCreate(SmbConnection connection, Smb2Header header,
        SmbSession session, SmbTreeConnect tree, ReadOnlySpan<byte> segment)
    {
        CreateRequest request = CreateRequest.Parse(segment, Smb2Header.Size);
        string pipeName = request.Name.TrimStart('\\');

        // Currently only srvsvc (share enumeration). Other pipes → not found.
        if (!pipeName.Equals("srvsvc", StringComparison.OrdinalIgnoreCase))
            return BuildError(header, NtStatus.ObjectNameNotFound);

        // Visible shares (filtered by the authorization policy) as the enumeration source.
        var entries = new List<ShareEntry>();
        foreach (IShare share in _server.GetVisibleShares(session.Identity ?? AnonymousIdentity, connection))
            entries.Add(new ShareEntry(share.Name, SrvsvcEndpoint.MapStype(share.Type), share.Remark));

        var pipe = new RpcPipe(new SrvsvcEndpoint(entries));

        ulong volatileId = connection.AllocateFileId();
        var open = new SmbOpen
        {
            PersistentFileId = 0,
            VolatileFileId = volatileId,
            Session = session,
            TreeConnect = tree,
            Pipe = pipe,
            GrantedAccess = request.DesiredAccess,
            PathName = pipeName,
        };
        session.Opens[open.Key] = open;

        var response = new CreateResponse
        {
            OplockLevel = OplockLevel.None,
            CreateAction = CreateAction.Opened,
            FileAttributes = (uint)SmbFileAttributes.Normal,
            PersistentFileId = open.PersistentFileId,
            VolatileFileId = open.VolatileFileId,
        };
        return MaybeSigned(session, RespHeader(header, session), response.ToBody());
    }

    private ResponseSegment HandleIoctl(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        IoctlMessage.Request req = IoctlMessage.ParseRequest(segment, Smb2Header.Size);

        // FSCTL_PIPE_TRANSCEIVE: DCERPC request → response via the named pipe.
        if (req.CtlCode == IoctlMessage.FsctlPipeTransceive
            && TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open)
            && open.Pipe is { } pipe)
        {
            byte[] output = pipe.Transceive(req.Input);
            return MaybeSigned(session, RespHeader(header, session),
                IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, output));
        }

        // FSCTL_SRV_ENUMERATE_SNAPSHOTS: list "Previous Versions" of a versioned share.
        if (req.CtlCode == IoctlMessage.FsctlSrvEnumerateSnapshots)
            return HandleEnumerateSnapshots(header, session, req);

        return BuildError(header, NtStatus.InvalidDeviceRequest);
    }

    /// <summary>
    /// Handles FSCTL_SRV_ENUMERATE_SNAPSHOTS when the share backend provides snapshots
    /// (<see cref="ISnapshotStore"/>). The path of the open handle determines for which file
    /// (or, at the root, for all files) the <c>@GMT-…</c> tokens are returned.
    /// </summary>
    private ResponseSegment HandleEnumerateSnapshots(Smb2Header header, SmbSession session, IoctlMessage.Request req)
    {
        if (!session.TreeConnects.TryGetValue(header.TreeId, out SmbTreeConnect? tree)
            || tree.Share.FileStore is not ISnapshotStore snapshots)
            return BuildError(header, NtStatus.InvalidDeviceRequest);

        string path = TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open)
            ? open.PathName
            : string.Empty;

        IReadOnlyList<DateTime> times = snapshots.GetSnapshots(path);
        var tokens = new List<string>(times.Count);
        foreach (DateTime t in times)
            tokens.Add(GmtToken.Format(t));

        byte[] output = IoctlMessage.BuildEnumerateSnapshotsResponse(tokens, req.MaxOutputResponse);
        return MaybeSigned(session, RespHeader(header, session),
            IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, output));
    }

    private ResponseSegment HandleClose(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        (ushort flags, ulong persistent, ulong vol) = CloseMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, persistent, vol, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);

        FileEntryInfo? info = (flags & CloseMessage.FlagPostQueryAttributes) != 0 ? open.LocalOpen?.GetInfo() : null;
        session.Opens.TryRemove(open.Key, out _);
        ReleaseLocks(connection, open);
        _server.Options.OplockManager.ReleaseOwner(open);
        if (open.ShareModeKey is { } shareKey) _server.Options.ShareModeManager.Close(shareKey, open);
        open.LocalOpen?.Dispose();

        byte[] body = info is null
            ? CloseMessage.BuildResponseBody()
            : CloseMessage.BuildResponseBody(true,
                new FileTimes(info.CreationTime, info.LastAccessTime, info.LastWriteTime, info.ChangeTime),
                info.AllocationSize, info.EndOfFile, (uint)info.Attributes);

        return MaybeSigned(session, RespHeader(header, session), body);
    }

    private ResponseSegment HandleRead(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        ReadMessage.Request req = ReadMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);

        // Named-pipe READ: deliver the buffered DCERPC response (Write→Read pattern).
        if (open.Pipe is { } pipe)
            return MaybeSigned(session, RespHeader(header, session), ReadMessage.BuildResponseBody(pipe.TakeOutput()));

        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err) || open.LocalOpen is null)
            return BuildError(header, err == NtStatus.Success ? NtStatus.FileClosed : err);

        uint length = Math.Min(req.Length, connection.MaxReadSize);
        if (!_server.Options.LockManager.IsRangeAccessible(open, req.Offset, length, forWrite: false))
            return BuildError(header, NtStatus.FileLockConflict);
        var buffer = new byte[length];
        FileStoreResult<int> result = store.Read(open.LocalOpen, (long)req.Offset, buffer);
        if (!result.IsSuccess)
            return BuildError(header, result.Status);
        if (result.Value == 0 && length > 0)
            return BuildError(header, NtStatus.EndOfFile);

        return MaybeSigned(session, RespHeader(header, session),
            ReadMessage.BuildResponseBody(buffer.AsSpan(0, result.Value)));
    }

    private ResponseSegment HandleWrite(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        WriteMessage.Request req = WriteMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);

        // Named-pipe WRITE: process the DCERPC request and buffer the response (for the subsequent READ).
        if (open.Pipe is { } pipe)
        {
            pipe.Transceive(req.Data);
            return MaybeSigned(session, RespHeader(header, session), WriteMessage.BuildResponseBody((uint)req.Data.Length));
        }

        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err) || open.LocalOpen is null)
            return BuildError(header, err == NtStatus.Success ? NtStatus.FileClosed : err);

        if (!_server.Options.LockManager.IsRangeAccessible(open, req.Offset, (ulong)req.Data.Length, forWrite: true))
            return BuildError(header, NtStatus.FileLockConflict);

        FileStoreResult<int> result = store.Write(open.LocalOpen, (long)req.Offset, req.Data);
        if (!result.IsSuccess)
            return BuildError(header, result.Status);

        return MaybeSigned(session, RespHeader(header, session),
            WriteMessage.BuildResponseBody((uint)result.Value));
    }

    private ResponseSegment HandleQueryDirectory(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);
        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err))
            return BuildError(header, err);

        QueryDirectoryMessage.Request req = QueryDirectoryMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);

        // SL_RESTART_SCAN → re-snapshot from the top (Context §14, MS-SMB2 §3.3.5.18).
        if ((req.Flags & QueryDirectoryMessage.FlagRestartScan) != 0)
        {
            open.DirectoryListing = null;
            open.DirectoryCursor = 0;
        }

        // First call of a scan: snapshot the listing once. The search pattern applies to this scan
        // only; later (continuation) calls page through the snapshot regardless of any pattern sent.
        if (open.DirectoryListing is null)
        {
            FileStoreResult<IReadOnlyList<FileEntryInfo>> listing = store.QueryDirectory(open.LocalOpen, req.SearchPattern);
            if (!listing.IsSuccess)
                return BuildError(header, listing.Status);
            if (listing.Value!.Count == 0)
                return BuildError(header, NtStatus.NoSuchFile);
            open.DirectoryListing = listing.Value;
            open.DirectoryCursor = 0;
        }

        IReadOnlyList<FileEntryInfo> all = open.DirectoryListing;
        if (open.DirectoryCursor >= all.Count)
            return BuildError(header, NtStatus.NoMoreFiles); // fully enumerated

        // Map only as many entries as could plausibly fit the client's buffer (bounds the work for
        // huge directories); SL_RETURN_SINGLE_ENTRY caps at one. The builder enforces the exact budget.
        bool single = (req.Flags & QueryDirectoryMessage.FlagReturnSingleEntry) != 0;
        int remaining = all.Count - open.DirectoryCursor;
        int cap = single ? 1 : Math.Min(remaining, (int)(req.OutputBufferLength / 12) + 2);
        var page = new List<FsccFileStat>(cap);
        for (int i = 0; i < cap; i++)
            page.Add(ToStat(all[open.DirectoryCursor + i]));

        byte[] buffer = FsccStructures.BuildDirectoryListing(page, req.InfoClass, (int)req.OutputBufferLength, out int wrote);
        if (wrote == 0)
            return BuildError(header, NtStatus.InfoLengthMismatch); // not even one entry fits the buffer

        open.DirectoryCursor += wrote;
        return MaybeSigned(session, RespHeader(header, session), QueryDirectoryMessage.BuildResponseBody(buffer));
    }

    private ResponseSegment HandleQueryInfo(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        QueryInfoMessage.Request req = QueryInfoMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);

        FsccFileStat stat = ToStat(open.LocalOpen.GetInfo());

        byte[]? buffer = req.InfoType switch
        {
            InfoType.File => FsccStructures.BuildFileInformation(stat, (FileInformationClass)req.FileInfoClass),
            InfoType.FileSystem => BuildFsInfo(session, header.TreeId, (FsInformationClass)req.FileInfoClass),
            _ => null,
        };

        if (buffer is null)
            return BuildError(header, NtStatus.InvalidInfoClass);

        return MaybeSigned(session, RespHeader(header, session), QueryInfoMessage.BuildResponseBody(buffer));
    }

    private ResponseSegment HandleSetInfo(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);
        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err))
            return BuildError(header, err);

        SetInfoMessage.Request req = SetInfoMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);

        if (req.InfoType != InfoType.File)
            return BuildError(header, NtStatus.NotSupported);

        NtStatus status = (FileInformationClass)req.FileInfoClass switch
        {
            FileInformationClass.FileEndOfFileInformation =>
                store.SetEndOfFile(open.LocalOpen, System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(req.Buffer)),
            FileInformationClass.FileDispositionInformation =>
                store.SetDeleteOnClose(open.LocalOpen, req.Buffer.Length > 0 && req.Buffer[0] != 0),
            FileInformationClass.FileRenameInformation => DoRename(store, open.LocalOpen, req.Buffer),
            // Times/attributes/allocation are accepted (no hard setting needed for browsing/writing).
            FileInformationClass.FileBasicInformation => NtStatus.Success,
            FileInformationClass.FileAllocationInformation => NtStatus.Success,
            FileInformationClass.FilePositionInformation => NtStatus.Success,
            _ => NtStatus.InvalidInfoClass,
        };

        if (status != NtStatus.Success)
            return BuildError(header, status);

        return MaybeSigned(session, RespHeader(header, session), SetInfoMessage.BuildResponseBody());
    }

    private static NtStatus DoRename(IFileStore store, IFileHandle handle, byte[] buffer)
    {
        (bool replace, string newPath) = SetInfoMessage.ParseRename(buffer);
        return store.Rename(handle, newPath, replace);
    }

    private ResponseSegment HandleFlush(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        // FLUSH Request (§2.2.17): StructureSize(2)+Reserved1(2)+Reserved2(4)+FileId(16).
        ulong persistent = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(segment.Slice(Smb2Header.Size + 8, 8));
        ulong vol = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(segment.Slice(Smb2Header.Size + 16, 8));
        if (TryGetOpen(session, persistent, vol, out SmbOpen open) && open.LocalOpen is not null
            && TryGetFileStore(session, header.TreeId, out IFileStore store, out _))
            store.Flush(open.LocalOpen);

        // FLUSH Response (§2.2.18): StructureSize=4, Reserved(2).
        var body = new byte[4];
        new Smb.Protocol.Wire.SpanWriter(body).WriteUInt16(4);
        return MaybeSigned(session, RespHeader(header, session), body);
    }

    // --- Helper functions ---

    private Smb2Header RespHeader(Smb2Header request, SmbSession session)
    {
        Smb2Header h = request.CreateResponse(NtStatus.Success);
        h.SessionId = session.SessionId;
        h.CreditRequestResponse = CreditManager.ComputeCreditGrant(request.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        return h;
    }

    private static FileAccessIntent MapAccess(uint desiredAccess)
    {
        FileAccessIntent intent = FileAccessIntent.None;
        if ((desiredAccess & (FileReadData | GenericRead | GenericAll | MaximumAllowed)) != 0)
            intent |= FileAccessIntent.Read;
        if ((desiredAccess & (FileWriteData | FileAppendData | GenericWrite | GenericAll)) != 0)
            intent |= FileAccessIntent.Write;
        if ((desiredAccess & (Delete | GenericAll)) != 0)
            intent |= FileAccessIntent.Delete;
        return intent;
    }

    private static FileShareMode MapShare(uint shareAccess)
    {
        FileShareMode m = FileShareMode.None;
        if ((shareAccess & 0x1) != 0) m |= FileShareMode.Read;   // FILE_SHARE_READ
        if ((shareAccess & 0x2) != 0) m |= FileShareMode.Write;  // FILE_SHARE_WRITE
        if ((shareAccess & 0x4) != 0) m |= FileShareMode.Delete; // FILE_SHARE_DELETE
        return m;
    }

    /// <summary>Share-scoped, case-folded logical path key for the share-mode table (O5).</summary>
    private static string ShareModeKey(SmbTreeConnect tree, string name)
        => tree.Share.Name + "\0" + name.Replace('\\', '/').Trim('/').ToLowerInvariant();

    /// <summary>
    /// Releases all server-side state of every open on a connection at teardown (Context §3.3.7.1):
    /// byte-range locks, oplocks, share-mode reservations and the backend handle (persistent OS file
    /// handle, O5). Without this, an abrupt disconnect would leak handles and keep files "open".
    /// </summary>
    public void OnConnectionClosed(SmbConnection connection)
    {
        foreach (SmbSession session in connection.Sessions.Values)
        {
            CloseSessionOpens(session);
            _server.SessionGlobalList.TryRemove(session.SessionId, out _);
        }
    }

    private void CloseSessionOpens(SmbSession session)
    {
        foreach (SmbOpen open in session.Opens.Values)
        {
            _server.Options.LockManager.ReleaseOwner(open);
            _server.Options.OplockManager.ReleaseOwner(open);
            if (open.ShareModeKey is { } shareKey) _server.Options.ShareModeManager.Close(shareKey, open);
            open.LocalOpen?.Dispose();
        }
        session.Opens.Clear();
    }

    /// <summary>
    /// Builds a FileSystem-class QUERY_INFO buffer. Uses the backend's real volume label/serial/free
    /// space when its <see cref="IFileStore"/> implements <see cref="IVolumeInfoProvider"/>, otherwise
    /// generic placeholders.
    /// </summary>
    private byte[]? BuildFsInfo(SmbSession session, uint treeId, FsInformationClass infoClass)
    {
        if (TryGetFileStore(session, treeId, out IFileStore store, out _) && store is IVolumeInfoProvider vip)
        {
            VolumeInfo vi = vip.GetVolumeInfo();
            return FsccStructures.BuildFileSystemInformation(
                infoClass, vi.Label, vi.SerialNumber, vi.TotalBytes, vi.AvailableBytes);
        }
        return FsccStructures.BuildFileSystemInformation(infoClass, "SHARE", 0x12345678);
    }

    private static FsccFileStat ToStat(FileEntryInfo info) => new()
    {
        Name = info.Name,
        FileAttributes = (uint)info.Attributes,
        EndOfFile = info.EndOfFile,
        AllocationSize = info.AllocationSize,
        CreationTime = info.CreationTime,
        LastAccessTime = info.LastAccessTime,
        LastWriteTime = info.LastWriteTime,
        ChangeTime = info.ChangeTime,
        IsDirectory = info.IsDirectory,
        IndexNumber = info.IndexNumber, // stable backend FileId (O2), no longer Name.GetHashCode()
    };
}
