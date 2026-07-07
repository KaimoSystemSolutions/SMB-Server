using Smb.Auth;
using Smb.FileSystem;
using Smb.FileSystem.Versioning;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Messages.Fscc;
using Smb.Protocol.Security;
using Smb.Protocol.Wire;
using Smb.Server.Leases;
using Smb.Server.Oplocks;
using Smb.Server.Rpc;
using Smb.Server.Sharing;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// File commands (M4, Context §13–§16): CREATE, CLOSE, READ, WRITE, QUERY_DIRECTORY,
/// QUERY_INFO via an <see cref="IFileStore"/> backend. Read-only browsing works
/// fully; writing depends on backend configuration. Handlers are async
/// (backend I/O does not block a thread); parsing happens before the first <c>await</c>,
/// since request records carry only scalars/<c>byte[]</c>.
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

    private async ValueTask<ResponseSegment> HandleCreateAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);
        if (!session.TreeConnects.TryGetValue(header.TreeId, out SmbTreeConnect? tree))
            return BuildError(header, NtStatus.NetworkNameDeleted);

        // Named-pipe share (IPC$): open a DCERPC pipe instead of using the file backend.
        if (tree.Share.Type == ShareType.Pipe)
            return HandlePipeCreate(connection, header, session, tree, segment.Span);

        if (tree.Share.FileStore is not { } store)
            return BuildError(header, NtStatus.NotSupported);

        CreateRequest request = CreateRequest.Parse(segment.Span, Smb2Header.Size);

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

        FileStoreResult<FileCreateResult> result = await store.CreateAsync(
            request.Name, access, disposition, dirRequired, nonDirRequired).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            _server.Options.ShareModeManager.Close(shareKey, open);
            return BuildError(header, result.Status);
        }

        IFileHandle handle = result.Value.Handle;
        CreateOutcome outcome = result.Value.Action;
        open.LocalOpen = handle;

        // [M3.3] Per-file DACL enforcement (MS-DTYP §2.5.3.2): evaluate the file's security descriptor
        // against the caller's SIDs and cap the granted access to what the DACL permits. On a backend
        // that carries no descriptors (GetSecurityAsync → NotSupported) only the share-level check above
        // applies. Runs after the open so we have the handle, but before any observable side effect from
        // DeleteOnClose; on denial the open is rolled back cleanly (§3.3.5.9).
        FileStoreResult<SecurityDescriptor> sd = await store.GetSecurityAsync(handle).ConfigureAwait(false);
        if (sd.IsSuccess)
        {
            IReadOnlyList<Sid> callerSids = BuildCallerSids(session.Identity);
            uint desired = maximumAllowed ? MaximumAllowed : AccessMask.MapGenericToSpecific(request.DesiredAccess);
            if (!AccessCheck.IsGranted(sd.Value!, callerSids, desired, out uint daclGranted))
            {
                await handle.DisposeAsync().ConfigureAwait(false);
                _server.Options.ShareModeManager.Close(shareKey, open);
                return BuildError(header, NtStatus.AccessDenied);
            }
            grantedAccess = daclGranted;
        }
        else
        {
            grantedAccess = AccessMask.MapGenericToSpecific(grantedAccess);
        }
        open.GrantedAccess = grantedAccess; // specific-rights mask, enforced per-operation below

        if (request.Options.HasFlag(CreateOptions.DeleteOnClose))
        {
            // DELETE_ON_CLOSE may require the Delete permission (enforced by the backend). Honor a
            // denial here instead of silently dropping it: roll the open back and fail the CREATE.
            NtStatus delStatus = await store.SetDeleteOnCloseAsync(handle, true).ConfigureAwait(false);
            if (delStatus != NtStatus.Success)
            {
                await handle.DisposeAsync().ConfigureAwait(false);
                _server.Options.ShareModeManager.Close(shareKey, open);
                return BuildError(header, delStatus);
            }
            open.DeleteOnClose = true;   // so CLOSE knows the entry will be removed (directory-lease break)
        }

        session.Opens[open.Key] = open;
        Interlocked.Increment(ref tree.OpenCount);

        // Caching delegation (Context §15): a modern client (SMB 2.1+) requests a *lease* via the
        // "RqLs" CREATE context; older clients request a classic *oplock* via RequestedOplockLevel.
        // The two are mutually exclusive per open — grant whichever was asked for, mirror it in the
        // response (and, for a lease, echo the granted state back in a response context).
        OplockLevel grantedOplock;
        byte[]? responseContexts = null;

        CreateContext? leaseContext = CreateContextList.Find(request.Contexts, CreateContextNames.Lease);
        if (leaseContext is not null)
        {
            LeaseRequest leaseReq = LeaseRequest.FromContext(leaseContext);
            open.LeaseKey = leaseReq.Key;
            open.ParentLeaseKey = leaseReq.ParentKey;

            LeaseGrant leaseGrant = _server.Options.LeaseManager.RequestLease(open, leaseReq);
            open.LeaseState = leaseGrant.GrantedState;
            open.LeaseEpoch = leaseGrant.Epoch;
            DispatchLeaseBreaks(leaseGrant.Breaks);

            grantedOplock = OplockLevel.Lease;
            responseContexts = CreateContextList.Serialize(new CreateContext[]
            {
                new()
                {
                    Name = leaseContext.Name,
                    Data = leaseReq.SerializeResponse(leaseGrant.GrantedState, leaseGrant.Epoch),
                },
            });
        }
        else
        {
            // Request oplock (Context §15): the manager determines the granted level and delivers
            // any breaks due to other holders, who are notified out-of-band.
            OplockGrant grant = _server.Options.OplockManager.RequestOplock(open, request.RequestedOplockLevel);
            grantedOplock = grant.GrantedLevel;
            DispatchOplockBreaks(grant.Breaks);
        }
        open.OplockLevel = grantedOplock;

        // A newly created entry changes its parent directory's listing → break any directory lease
        // cached on the parent so the holder re-enumerates (directory leasing, M1.3).
        if (outcome == CreateOutcome.Created)
            BreakParentDirectoryLease(handle.PhysicalPath);

        FileEntryInfo info = await handle.GetInfoAsync().ConfigureAwait(false);
        var response = new CreateResponse
        {
            OplockLevel = grantedOplock,
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

        return MaybeSigned(session, RespHeader(header, session), response.ToBody(responseContexts));
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

    private ResponseSegment HandleIoctl(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment, frameEncrypted))
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

    private async ValueTask<ResponseSegment> HandleCloseAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        (ushort flags, ulong persistent, ulong vol) = CloseMessage.ParseRequest(segment.Span, Smb2Header.Size);
        if (!TryGetOpen(session, persistent, vol, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);

        FileEntryInfo? info = null;
        if ((flags & CloseMessage.FlagPostQueryAttributes) != 0 && open.LocalOpen is not null)
            info = await open.LocalOpen.GetInfoAsync().ConfigureAwait(false);
        session.Opens.TryRemove(open.Key, out _);
        ReleaseLocks(connection, open);
        _server.Options.OplockManager.ReleaseOwner(open);
        _server.Options.LeaseManager.ReleaseOwner(open);
        if (open.ShareModeKey is { } shareKey) _server.Options.ShareModeManager.Close(shareKey, open);

        // A DELETE_ON_CLOSE entry disappears from its parent directory on dispose → capture the path
        // beforehand and break the parent's directory lease afterwards (directory leasing, M1.3).
        string? removedPhysicalPath = open.DeleteOnClose ? open.LocalOpen?.PhysicalPath : null;
        if (open.LocalOpen is not null)
            await open.LocalOpen.DisposeAsync().ConfigureAwait(false);
        if (removedPhysicalPath is not null)
            BreakParentDirectoryLease(removedPhysicalPath);

        byte[] body = info is null
            ? CloseMessage.BuildResponseBody()
            : CloseMessage.BuildResponseBody(true,
                new FileTimes(info.CreationTime, info.LastAccessTime, info.LastWriteTime, info.ChangeTime),
                info.AllocationSize, info.EndOfFile, (uint)info.Attributes);

        return MaybeSigned(session, RespHeader(header, session), body);
    }

    private async ValueTask<ResponseSegment> HandleReadAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        ReadMessage.Request req = ReadMessage.ParseRequest(segment.Span, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);

        // Named-pipe READ: deliver the buffered DCERPC response (Write→Read pattern).
        if (open.Pipe is { } pipe)
            return MaybeSigned(session, RespHeader(header, session), ReadMessage.BuildResponseBody(pipe.TakeOutput()));

        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err) || open.LocalOpen is null)
            return BuildError(header, err == NtStatus.Success ? NtStatus.FileClosed : err);

        // [M3.3] The handle must have been granted FILE_READ_DATA at open (DACL access check).
        if ((open.GrantedAccess & AccessMask.FileReadData) == 0)
            return BuildError(header, NtStatus.AccessDenied);

        uint length = Math.Min(req.Length, connection.MaxReadSize);
        if (!_server.Options.LockManager.IsRangeAccessible(open, req.Offset, length, forWrite: false))
            return BuildError(header, NtStatus.FileLockConflict);
        var buffer = new byte[length];
        FileStoreResult<int> result = await store.ReadAsync(open.LocalOpen, (long)req.Offset, buffer).ConfigureAwait(false);
        if (!result.IsSuccess)
            return BuildError(header, result.Status);
        if (result.Value == 0 && length > 0)
            return BuildError(header, NtStatus.EndOfFile);

        return MaybeSigned(session, RespHeader(header, session),
            ReadMessage.BuildResponseBody(buffer.AsSpan(0, result.Value)));
    }

    private async ValueTask<ResponseSegment> HandleWriteAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        WriteMessage.Request req = WriteMessage.ParseRequest(segment.Span, Smb2Header.Size);
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

        // [M3.3] The handle must have been granted FILE_WRITE_DATA / FILE_APPEND_DATA at open.
        if ((open.GrantedAccess & AccessMask.WriteAccess) == 0)
            return BuildError(header, NtStatus.AccessDenied);

        if (!_server.Options.LockManager.IsRangeAccessible(open, req.Offset, (ulong)req.Data.Length, forWrite: true))
            return BuildError(header, NtStatus.FileLockConflict);

        FileStoreResult<int> result = await store.WriteAsync(open.LocalOpen, (long)req.Offset, req.Data).ConfigureAwait(false);
        if (!result.IsSuccess)
            return BuildError(header, result.Status);

        return MaybeSigned(session, RespHeader(header, session),
            WriteMessage.BuildResponseBody((uint)result.Value));
    }

    private async ValueTask<ResponseSegment> HandleQueryDirectoryAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);
        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err))
            return BuildError(header, err);

        QueryDirectoryMessage.Request req = QueryDirectoryMessage.ParseRequest(segment.Span, Smb2Header.Size);
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
            FileStoreResult<IReadOnlyList<FileEntryInfo>> listing = await store.QueryDirectoryAsync(open.LocalOpen, req.SearchPattern).ConfigureAwait(false);
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

    private async ValueTask<ResponseSegment> HandleQueryInfoAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        QueryInfoMessage.Request req = QueryInfoMessage.ParseRequest(segment.Span, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);

        if (req.InfoType == InfoType.Security)
            return await HandleQuerySecurityAsync(session, header, open, req).ConfigureAwait(false);

        FsccFileStat stat = ToStat(await open.LocalOpen.GetInfoAsync().ConfigureAwait(false));

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

    private async ValueTask<ResponseSegment> HandleSetInfoAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);
        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err))
            return BuildError(header, err);

        SetInfoMessage.Request req = SetInfoMessage.ParseRequest(segment.Span, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);

        if (req.InfoType == InfoType.Security)
            return await HandleSetSecurityAsync(session, header, store, open, req).ConfigureAwait(false);

        if (req.InfoType != InfoType.File)
            return BuildError(header, NtStatus.NotSupported);

        var infoClass = (FileInformationClass)req.FileInfoClass;

        // [M3.3] Enforce the handle's granted access for state-changing SET_INFO classes: truncation is a
        // write, delete-disposition and rename both require DELETE. Other classes (times/attributes) are
        // accepted no-ops and are not gated here.
        uint requiredAccess = infoClass switch
        {
            FileInformationClass.FileEndOfFileInformation => AccessMask.FileWriteData,
            FileInformationClass.FileDispositionInformation => AccessMask.Delete,
            FileInformationClass.FileRenameInformation => AccessMask.Delete,
            _ => 0u,
        };
        if (requiredAccess != 0 && (open.GrantedAccess & requiredAccess) == 0)
            return BuildError(header, NtStatus.AccessDenied);

        // The physical path before a rename (its parent dir loses the entry); captured up front because
        // the handle relocates in place during the rename (directory leasing, M1.3).
        string? renameOldPhysicalPath = infoClass == FileInformationClass.FileRenameInformation
            ? open.LocalOpen.PhysicalPath : null;

        NtStatus status = infoClass switch
        {
            FileInformationClass.FileEndOfFileInformation =>
                await store.SetEndOfFileAsync(open.LocalOpen,
                    System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(req.Buffer)).ConfigureAwait(false),
            FileInformationClass.FileDispositionInformation =>
                await store.SetDeleteOnCloseAsync(open.LocalOpen, req.Buffer.Length > 0 && req.Buffer[0] != 0).ConfigureAwait(false),
            FileInformationClass.FileRenameInformation => await DoRenameAsync(store, open.LocalOpen, req.Buffer).ConfigureAwait(false),
            // Times/attributes/allocation are accepted (no hard setting needed for browsing/writing).
            FileInformationClass.FileBasicInformation => NtStatus.Success,
            FileInformationClass.FileAllocationInformation => NtStatus.Success,
            FileInformationClass.FilePositionInformation => NtStatus.Success,
            _ => NtStatus.InvalidInfoClass,
        };

        if (status != NtStatus.Success)
            return BuildError(header, status);

        if (infoClass == FileInformationClass.FileDispositionInformation)
            // Track the delete intent on the open so CLOSE can break the parent directory lease.
            open.DeleteOnClose = req.Buffer.Length > 0 && req.Buffer[0] != 0;
        else if (renameOldPhysicalPath is not null)
        {
            // A rename removes the entry from the source directory and adds it to the target directory
            // → break directory leases on both parents (they coincide for an in-place rename, in which
            // case the second call is a harmless no-op).
            BreakParentDirectoryLease(renameOldPhysicalPath);
            BreakParentDirectoryLease(open.LocalOpen.PhysicalPath);
        }

        return MaybeSigned(session, RespHeader(header, session), SetInfoMessage.BuildResponseBody());
    }

    private static ValueTask<NtStatus> DoRenameAsync(IFileStore store, IFileHandle handle, byte[] buffer)
    {
        (bool replace, string newPath) = SetInfoMessage.ParseRename(buffer);
        return store.RenameAsync(handle, newPath, replace);
    }

    /// <summary>
    /// QUERY_INFO with InfoType Security (§2.2.37 / MS-DTYP §2.4.6): returns the open's security
    /// descriptor, limited to the components the client requested via AdditionalInformation.
    /// </summary>
    private async ValueTask<ResponseSegment> HandleQuerySecurityAsync(
        SmbSession session, Smb2Header header, SmbOpen open, QueryInfoMessage.Request req)
    {
        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err))
            return BuildError(header, err);

        FileStoreResult<SecurityDescriptor> result = await store.GetSecurityAsync(open.LocalOpen!).ConfigureAwait(false);
        if (!result.IsSuccess)
            return BuildError(header, result.Status);

        var which = (SecurityInformation)req.AdditionalInformation;
        byte[] descriptor = FilterSecurityDescriptor(result.Value!, which).ToBytes();

        // The client sizes its buffer; if the descriptor does not fit it retries with the needed size.
        if (descriptor.Length > req.OutputBufferLength)
            return BuildError(header, NtStatus.BufferTooSmall);

        return MaybeSigned(session, RespHeader(header, session), QueryInfoMessage.BuildResponseBody(descriptor));
    }

    /// <summary>
    /// SET_INFO with InfoType Security (§2.2.39): merges the requested components (per
    /// AdditionalInformation) from the supplied descriptor into the stored one and persists it.
    /// </summary>
    private async ValueTask<ResponseSegment> HandleSetSecurityAsync(
        SmbSession session, Smb2Header header, IFileStore store, SmbOpen open, SetInfoMessage.Request req)
    {
        SecurityDescriptor incoming;
        try { incoming = SecurityDescriptor.Parse(req.Buffer); }
        catch (SmbWireFormatException) { return BuildError(header, NtStatus.InvalidParameter); }

        FileStoreResult<SecurityDescriptor> existing = await store.GetSecurityAsync(open.LocalOpen!).ConfigureAwait(false);
        if (!existing.IsSuccess)
            return BuildError(header, existing.Status);

        var which = (SecurityInformation)req.AdditionalInformation;
        SecurityDescriptor merged = MergeSecurityDescriptor(existing.Value!, incoming, which);

        NtStatus status = await store.SetSecurityAsync(open.LocalOpen!, merged).ConfigureAwait(false);
        if (status != NtStatus.Success)
            return BuildError(header, status);

        return MaybeSigned(session, RespHeader(header, session), SetInfoMessage.BuildResponseBody());
    }

    /// <summary>Returns a descriptor containing only the components selected by <paramref name="which"/>.</summary>
    private static SecurityDescriptor FilterSecurityDescriptor(SecurityDescriptor sd, SecurityInformation which)
        => SecurityDescriptor.Create(
            which.HasFlag(SecurityInformation.Owner) ? sd.Owner : null,
            which.HasFlag(SecurityInformation.Group) ? sd.Group : null,
            which.HasFlag(SecurityInformation.Dacl) ? sd.Dacl : null,
            which.HasFlag(SecurityInformation.Sacl) ? sd.Sacl : null);

    /// <summary>Copies the components selected by <paramref name="which"/> from <paramref name="incoming"/>
    /// over <paramref name="existing"/>, keeping the rest.</summary>
    private static SecurityDescriptor MergeSecurityDescriptor(
        SecurityDescriptor existing, SecurityDescriptor incoming, SecurityInformation which)
        => SecurityDescriptor.Create(
            which.HasFlag(SecurityInformation.Owner) ? incoming.Owner : existing.Owner,
            which.HasFlag(SecurityInformation.Group) ? incoming.Group : existing.Group,
            which.HasFlag(SecurityInformation.Dacl) ? incoming.Dacl : existing.Dacl,
            which.HasFlag(SecurityInformation.Sacl) ? incoming.Sacl : existing.Sacl);

    private async ValueTask<ResponseSegment> HandleFlushAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        // FLUSH Request (§2.2.17): StructureSize(2)+Reserved1(2)+Reserved2(4)+FileId(16).
        ulong persistent = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(segment.Span.Slice(Smb2Header.Size + 8, 8));
        ulong vol = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(segment.Span.Slice(Smb2Header.Size + 16, 8));
        if (TryGetOpen(session, persistent, vol, out SmbOpen open) && open.LocalOpen is not null
            && TryGetFileStore(session, header.TreeId, out IFileStore store, out _))
            await store.FlushAsync(open.LocalOpen).ConfigureAwait(false);

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

    /// <summary>
    /// Builds the caller's SID set for a DACL access check (M3.3): the primary user SID, all group SIDs
    /// and the well-known Everyone group; an authenticated (non-anonymous) caller additionally carries
    /// Authenticated Users. Unparseable SID strings are skipped rather than failing the whole check.
    /// </summary>
    private static IReadOnlyList<Sid> BuildCallerSids(SecurityIdentity? identity)
    {
        var sids = new List<Sid> { WellKnownSids.Everyone };
        if (identity is null || identity.IsAnonymous)
            return sids;

        sids.Add(WellKnownSids.AuthenticatedUsers);
        if (Sid.TryParse(identity.UserSid, out Sid user))
            sids.Add(user);
        foreach (string group in identity.GroupSids)
            if (Sid.TryParse(group, out Sid g))
                sids.Add(g);
        return sids;
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
            _server.Options.LeaseManager.ReleaseOwner(open);
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
