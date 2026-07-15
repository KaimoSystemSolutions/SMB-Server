using Smb.Auth;
using Smb.FileSystem;
using Smb.FileSystem.Versioning;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Messages.Fscc;
using Smb.Protocol.Security;
using Smb.Protocol.Wire;
using Smb.Server.Dfs;
using Smb.Server.Diagnostics;
using Smb.Server.Durable;
using Smb.Server.Leases;
using Smb.Server.Oplocks;
using Smb.Server.Quota;
using Smb.Server.Rpc;
using Smb.Server.Sharing;
using Smb.Server.State;
using Smb.Server.Witness;

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

    /// <summary>
    /// CREATE (§3.3.5.9). <paramref name="standalone"/> = the request is a whole message on its own, which
    /// is the precondition for parking it behind an oplock/lease break acknowledgment (W1.1, see the tail
    /// of this method).
    /// </summary>
    private async ValueTask<ResponseSegment?> HandleCreateAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted, bool standalone)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);
        if (!session.TreeConnects.TryGetValue(header.TreeId, out SmbTreeConnect? tree))
            return BuildError(header, NtStatus.NetworkNameDeleted);

        // Named-pipe share (IPC$): open a DCERPC pipe instead of using the file backend.
        if (tree.Share.Type == ShareType.Pipe)
            return await HandlePipeCreateAsync(connection, header, session, tree, segment).ConfigureAwait(false);

        if (tree.Share.FileStore is not { } store)
            return BuildError(header, NtStatus.NotSupported);

        CreateRequest request = CreateRequest.Parse(segment.Span, Smb2Header.Size);

        // [M4.1/M4.2] Durable-handle reconnect ("DHnC"/"DH2C"): restore an open preserved across a
        // transport drop instead of opening a new backend handle (§3.3.5.9.7).
        CreateContext? reconnectV2Ctx = CreateContextList.Find(request.Contexts, CreateContextNames.DurableHandleReconnectV2);
        if (reconnectV2Ctx is not null)
            return await HandleDurableReconnectV2Async(header, session, tree, reconnectV2Ctx).ConfigureAwait(false);
        CreateContext? reconnectCtx = CreateContextList.Find(request.Contexts, CreateContextNames.DurableHandleReconnect);
        if (reconnectCtx is not null)
            return await HandleDurableReconnectAsync(header, session, tree, reconnectCtx).ConfigureAwait(false);

        // [M7.2] DFS link resolution: on a DFS-root share a path at or below a DFS link is not served
        // locally — the server answers STATUS_PATH_NOT_COVERED so the client requests a referral
        // (FSCTL_DFS_GET_REFERRALS, M7.1) and reconnects to the target (§3.3.5.9 / MS-DFSC).
        if (tree.Share.IsDfs && _server.Options.DfsNamespace is { } dfsNamespace
            && dfsNamespace.IsLinkCovered(BuildDfsPath(tree.Share.Name, request.Name)))
            return BuildError(header, NtStatus.PathNotCovered);

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

        // [M9.1] Alternate data stream: a CREATE name of the form "path\file:stream[:$DATA]" opens a
        // named data stream of the base file. An empty stream name ("file::$DATA") is just the file's
        // default data stream — served as a normal open of the base path. A non-empty stream needs a
        // backend that implements INamedStreamStore; otherwise the object name has no valid stream
        // (STATUS_NOT_SUPPORTED, as on a non-ADS file system).
        bool hasStreamSuffix = TrySplitStreamName(request.Name, out string baseName, out string streamName);
        string effectiveName = hasStreamSuffix ? baseName : request.Name;
        bool namedStream = hasStreamSuffix && streamName.Length > 0;
        if (namedStream && store is not INamedStreamStore)
            return BuildError(header, NtStatus.NotSupported);

        // [M11.2] Symlink / reparse-point resolution: if a component of the path is a symbolic link the
        // server does not silently follow it — it answers STATUS_STOPPED_ON_SYMLINK with a
        // SYMLINK_ERROR_RESPONSE (§2.2.2.2.1) so the client re-targets and retries (§3.3.5.9). A CREATE
        // asking for FILE_OPEN_REPARSE_POINT opens the link itself and is served normally. Only backends
        // that implement ISymlinkResolver participate; others resolve as before.
        if (!request.Options.HasFlag(CreateOptions.OpenReparsePoint) && store is ISymlinkResolver symlinkResolver)
        {
            SymlinkTarget? link = await symlinkResolver.ResolveSymlinkAsync(effectiveName).ConfigureAwait(false);
            if (link is { } target)
            {
                byte[] errorData = SymlinkErrorResponse.Build(
                    target.SubstituteName, target.PrintName ?? target.SubstituteName,
                    target.UnparsedPathLength, target.IsRelative);
                return BuildError(connection, header, NtStatus.StoppedOnSymlink, errorData);
            }
        }

        // [D2] Per-session open-handle cap (resource limit): reject a new open once the session already
        // holds the configured maximum, before any backend side effect, so a client cannot exhaust server
        // memory with unbounded opens. ≤ 0 disables the cap. Reconnect/durable-restore paths returned above.
        int handleCap = _server.Options.MaxOpenHandlesPerSession;
        if (handleCap > 0 && session.Opens.Count >= handleCap)
            return BuildError(header, NtStatus.InsufficientResources);

        // Allocate the open up front so the share-mode reservation can be keyed to it.
        ulong volatileId = connection.AllocateFileId();
        var open = new SmbOpen
        {
            PersistentFileId = 0,
            VolatileFileId = volatileId,
            Session = session,
            TreeConnect = tree,
            GrantedAccess = grantedAccess,
            ShareAccess = request.ShareAccess,
            PathName = request.Name,
        };

        // [O5] Sharing-violation check BEFORE the backend acts, so a conflict causes no side effects
        // (e.g. truncation). Keyed on the share-scoped logical path; released at CLOSE/teardown.
        string shareKey = ShareModeKey(tree, request.Name);
        if (!_server.Options.ShareModeManager.TryOpen(shareKey, open, access, MapShare(request.ShareAccess)))
            return BuildError(header, NtStatus.SharingViolation);
        open.ShareModeKey = shareKey;

        FileStoreResult<FileCreateResult> result = namedStream
            ? await ((INamedStreamStore)store).OpenNamedStreamAsync(
                baseName, streamName, access, disposition).ConfigureAwait(false)
            : await store.CreateAsync(
                effectiveName, access, disposition, dirRequired, nonDirRequired).ConfigureAwait(false);
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
        var responseCtxList = new List<CreateContext>();

        // [W1.1] The breaks this open forces on other holders are *armed* here (registered with the break
        // tracker, holder state mirrored) but sent further down — after this CREATE's interim, if it parks.
        ArmedBreaks armed = ArmedBreaks.None;

        CreateContext? leaseContext = CreateContextList.Find(request.Contexts, CreateContextNames.Lease);
        if (leaseContext is not null)
        {
            LeaseRequest leaseReq = LeaseRequest.FromContext(leaseContext);
            open.LeaseKey = leaseReq.Key;
            open.ParentLeaseKey = leaseReq.ParentKey;

            LeaseGrant leaseGrant = _server.Options.LeaseManager.RequestLease(open, leaseReq);
            open.LeaseState = leaseGrant.GrantedState;
            open.LeaseEpoch = leaseGrant.Epoch;
            armed = ArmLeaseBreaks(leaseGrant.Breaks, track: true);

            grantedOplock = OplockLevel.Lease;
            responseCtxList.Add(new CreateContext
            {
                Name = leaseContext.Name,
                Data = leaseReq.SerializeResponse(leaseGrant.GrantedState, leaseGrant.Epoch),
            });
        }
        else
        {
            // Request oplock (Context §15): the manager determines the granted level and delivers
            // any breaks due to other holders, who are notified out-of-band.
            OplockGrant grant = _server.Options.OplockManager.RequestOplock(open, request.RequestedOplockLevel);
            grantedOplock = grant.GrantedLevel;
            armed = ArmOplockBreaks(grant.Breaks, track: true);
        }
        open.OplockLevel = grantedOplock;

        // [M4.1/M4.2] Durable-handle request ("DHnQ"/"DH2Q"): grant durability only when the open holds a
        // caching guarantee that lets the client safely reconnect (a batch/exclusive oplock or a lease
        // with handle caching, §3.3.5.9.6). The open then gets a stable persistent FileId and is preserved
        // on a transport drop instead of being released. A request without such a guarantee is ignored
        // (the client falls back to a normal handle), which is spec-compliant. v2 additionally carries a
        // create GUID (matched on reconnect), a client-requested timeout, and an optional persistent flag
        // (honored only on a continuously-available share).
        CreateContext? durableV2 = CreateContextList.Find(request.Contexts, CreateContextNames.DurableHandleRequestV2);
        CreateContext? durableV1 = CreateContextList.Find(request.Contexts, CreateContextNames.DurableHandleRequest);
        if ((durableV2 is not null || durableV1 is not null) && DurabilityAllowed(grantedOplock, open.LeaseState))
        {
            session.Opens.TryRemove(open.Key, out _);          // re-key: persistent id changes from 0
            open.PersistentFileId = _server.AllocatePersistentId();
            open.IsDurable = true;

            if (durableV2 is not null)
            {
                DurableHandleMessages.V2Request v2 = DurableHandleMessages.ParseV2Request(durableV2.Data);
                open.DurableCreateGuid = v2.CreateGuid;
                open.IsPersistentHandle = v2.IsPersistent && tree.Share.ContinuousAvailability;
                open.DurableTimeout = ResolveDurableTimeout(v2.TimeoutMs);
                responseCtxList.Add(DurableHandleMessages.BuildV2ResponseContext(
                    (uint)open.DurableTimeout.TotalMilliseconds, open.IsPersistentHandle));
            }
            else
            {
                open.DurableTimeout = _server.Options.DurableHandleTimeout;
                responseCtxList.Add(DurableHandleMessages.BuildV1ResponseContext());
            }
            session.Opens[open.Key] = open;

            // [C2] A persistent (CA) handle must survive a full server restart: write its reconnect metadata
            // to the durable store now, while the handle is live, so even a crash before a graceful disconnect
            // leaves a record to rehydrate from.
            if (open.IsPersistentHandle && _server.Options.DurableHandleStore is IPersistentHandleStore persistent)
                persistent.Persist(new PersistentHandleRecord(
                    open.PersistentFileId, open.VolatileFileId, OwnerKey(session.Identity), open.DurableCreateGuid,
                    tree.Share.Name, open.PathName, open.GrantedAccess, open.ShareAccess));
        }

        // A newly created entry changes its parent directory's listing → break any directory lease
        // cached on the parent so the holder re-enumerates (directory leasing, M1.3). Creating a named
        // stream adds no directory entry, so it does not trigger a break.
        if (outcome == CreateOutcome.Created && !namedStream)
            BreakParentDirectoryLease(handle.PhysicalPath);

        _server.Options.Metrics.OnHandleOpened();
        Audit(SmbAuditEventType.FileOpened, SmbLogLevel.Information, connection,
            user: DescribeIdentity(session.Identity), share: tree.Share.Name, path: request.Name);

        // [W1.1] Break-before-grant (§3.3.5.9.8). If this open cost another holder its write/handle caching,
        // that holder still has dirty data client-side. Withhold the response — and with it the FileId the
        // client needs to read anything at all — until the holder has acknowledged (or the break timed out,
        // W1.2). This is also why the body is built *after* the wait: the file the holder flushes into is
        // the file whose size/timestamps this response reports.
        if (armed.Wait is { } breakWait && standalone)
            return await ParkCreateBehindBreakAsync(
                connection, header, session, open, armed, breakWait, BuildCreateBodyAsync).ConfigureAwait(false);

        // Nothing to wait for (no break, none needing an acknowledgment, blocking disabled, or a compound
        // element that cannot answer out-of-band): send the notifications and answer straight away.
        _ = SendArmedBreaksAsync(armed);
        return MaybeSigned(session, RespHeader(header, session), await BuildCreateBodyAsync().ConfigureAwait(false));

        async ValueTask<byte[]> BuildCreateBodyAsync()
        {
            byte[]? responseContexts = responseCtxList.Count > 0 ? CreateContextList.Serialize(responseCtxList) : null;
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
            return response.ToBody(responseContexts);
        }
    }

    /// <summary>
    /// [W1.1/W1.2] Parks a CREATE that broke another holder's caching until the holder acknowledges or the
    /// break times out, then answers out-of-band with an ASYNC final (§3.3.4.2) — the CHANGE_NOTIFY
    /// mechanism, with one deliberate difference: the interim is written <i>here</i> rather than returned to
    /// the caller. The order interim → notification → wait is load-bearing (§2.2.24): send the notification
    /// first and a fast holder could acknowledge, releasing the final, before the client has even seen the
    /// AsyncId that final is tagged with. Returning the interim as the frame's response would leave that
    /// order to a race between two tasks, so this path writes it itself and the frame answers with nothing.
    /// <para>
    /// <b>Why this does not deadlock the connection</b> (the trap W1.0 was written for): the frame does not
    /// stay in flight while parked. It returns as soon as the interim and the notification are out, so the
    /// host's read loop is free to read the acknowledgment — whether OPLOCK_BREAK arrives as a barrier frame
    /// (it drains an in-flight list this CREATE has already left) or, with ConcurrentMetadataOps off, while
    /// the read loop would otherwise still be sitting inside this very CREATE. Parking the frame instead of
    /// the response is what would have needed the acknowledgment taken off the barrier.
    /// </para>
    /// </summary>
    private async ValueTask<ResponseSegment?> ParkCreateBehindBreakAsync(
        SmbConnection connection, Smb2Header header, SmbSession session, SmbOpen open,
        ArmedBreaks armed, Task<BreakOutcome[]> breakWait, Func<ValueTask<byte[]>> buildBody)
    {
        // Resource protection as CHANGE_NOTIFY/LOCK do it: a parked CREATE holds a PendingRequest. At the
        // cap, answer synchronously rather than reject — the client gets a correct handle, only without the
        // coherency wait, which is strictly better than STATUS_INSUFFICIENT_RESOURCES on a valid open.
        if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests)
        {
            _ = SendArmedBreaksAsync(armed);   // the holder must still learn about the break
            return MaybeSigned(session, RespHeader(header, session), await buildBody().ConfigureAwait(false));
        }

        ulong asyncId = connection.AllocateAsyncId();
        var pending = new PendingAsyncRequest { MessageId = header.MessageId, AsyncId = asyncId, Owner = open };
        connection.PendingRequests[header.MessageId] = pending;
        bool encrypt = ResponseNeedsEncryption(session, open);

        await SendOutOfBandAsync(session, connection, InterimResponse(header, session, asyncId), encrypt).ConfigureAwait(false);
        await SendArmedBreaksAsync(armed).ConfigureAwait(false);

        _ = CompleteParkedCreateAsync(connection, header, session, asyncId, pending, breakWait, buildBody, encrypt);
        return null;   // the final response follows out-of-band
    }

    /// <summary>
    /// [W1.1] Waits out the break and sends the parked CREATE's final response. The wait always ends —
    /// acknowledged or timed out (W1.2) — so this cannot become the very freeze W1 exists to remove.
    /// <para>
    /// <b>A parked CREATE is deliberately not cancellable.</b> Its <see cref="PendingAsyncRequest.Token"/>
    /// exists for the accounting and so a CANCEL finds *something*, but the token is not honoured:
    /// §3.3.5.16 lets the server ignore a cancel it cannot service, and here cancelling would be actively
    /// harmful — the open already exists, so a client that never learns its FileId could never close it.
    /// The timeout bounds the wait instead.
    /// </para>
    /// <para>
    /// <b>The ambient <c>SmbCaller</c> survives into here</b>, which <c>buildBody</c> needs for a per-user
    /// backend: this task is started inside the CREATE's async flow, so it captures the ExecutionContext
    /// while the caller is still set. <c>DispatchOneAsync</c>'s <c>finally</c> clearing it afterwards does not
    /// reach this branch (an <c>AsyncLocal</c> write does not flow to an already-started child). Detaching
    /// this task any later — e.g. from the tracker's timer callback — would lose the identity.
    /// </para>
    /// </summary>
    private async Task CompleteParkedCreateAsync(
        SmbConnection connection, Smb2Header header, SmbSession session, ulong asyncId,
        PendingAsyncRequest pending, Task<BreakOutcome[]> breakWait, Func<ValueTask<byte[]>> buildBody, bool encrypt)
    {
        try
        {
            BreakOutcome[] outcomes = await breakWait.ConfigureAwait(false);

            // Connection teardown may have completed this request already (CancelNonSurvivingPending
            // removes it); then the open is gone too and there is nothing left to answer.
            if (!connection.PendingRequests.TryRemove(pending.MessageId, out _))
                return;

            if (Array.IndexOf(outcomes, BreakOutcome.TimedOut) >= 0)
                _log?.Invoke($"[oplock] break not acknowledged within {_server.Options.OplockBreakTimeout}; " +
                             $"proceeding with CREATE mid={header.MessageId} (coherency degraded for the holder)");

            await SendAsyncFinalAsync(connection, header, session, asyncId, NtStatus.Success,
                await buildBody().ConfigureAwait(false), encrypt).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // This runs detached: an escaping exception would be an unobserved task exception *and* would
            // leave the client waiting out its own timeout for a response that never comes. Answer with the
            // mapped status instead — the same safety net DispatchOneAsync gives every in-band handler.
            connection.PendingRequests.TryRemove(pending.MessageId, out _);
            _log?.Invoke($"[error] parked CREATE mid={header.MessageId} → {ex.GetType().Name}: {ex.Message}");
            try
            {
                await SendAsyncFinalAsync(connection, header, session, asyncId, MapException(ex),
                    ErrorResponse.BuildBody(), encrypt).ConfigureAwait(false);
            }
            catch { /* channel gone — nothing left to tell anyone */ }
        }
    }

    private async ValueTask<ResponseSegment> HandlePipeCreateAsync(SmbConnection connection, Smb2Header header,
        SmbSession session, SmbTreeConnect tree, ReadOnlyMemory<byte> segment)
    {
        // Parse off the span before the await below (a ReadOnlySpan cannot cross an await point);
        // CreateRequest is a class, so `request` itself survives it.
        CreateRequest request = CreateRequest.Parse(segment.Span, Smb2Header.Size);
        string pipeName = request.Name.TrimStart('\\');

        IRpcEndpoint? endpoint = await OpenRpcEndpointAsync(connection, session, pipeName).ConfigureAwait(false);
        if (endpoint is null)
            return BuildError(header, NtStatus.ObjectNameNotFound); // unknown pipe

        var pipe = new RpcPipe(endpoint);

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

    /// <summary>
    /// Resolves a well-known IPC$ named pipe to its DCERPC endpoint, or null if the pipe is unknown.
    /// <c>srvsvc</c> serves share enumeration; <c>witness</c> serves the MS-SWN witness service (C1).
    /// <para>
    /// [W6.2b] Async because the visible-share snapshot consults the authorization policy
    /// (<c>IShareAccessPolicy.IsVisibleAsync</c>), which may be I/O-bound. Note the policy is consulted
    /// here — when the pipe is <i>opened</i> — and the resulting list is baked into the endpoint; the DCERPC
    /// request path (NetrShareEnum) itself never touches the policy and stays synchronous.
    /// </para>
    /// </summary>
    private async ValueTask<IRpcEndpoint?> OpenRpcEndpointAsync(SmbConnection connection, SmbSession session, string pipeName)
    {
        if (pipeName.Equals("srvsvc", StringComparison.OrdinalIgnoreCase))
        {
            // Visible shares (filtered by the authorization policy) as the enumeration source.
            var entries = new List<ShareEntry>();
            foreach (IShare share in await _server.GetVisibleSharesAsync(session.Identity ?? AnonymousIdentity, connection).ConfigureAwait(false))
                entries.Add(new ShareEntry(share.Name, SrvsvcEndpoint.MapStype(share.Type), share.Remark));
            return new SrvsvcEndpoint(entries);
        }

        if (pipeName.Equals("witness", StringComparison.OrdinalIgnoreCase))
        {
            string serverName = _server.Options.ServerName;
            var nicProvider = _server.Options.NetworkInterfaceProvider;
            // Snapshot the live NICs per GetInterfaceList call (same source multichannel advertises).
            return new WitnessEndpoint(
                _server.WitnessRegistrations, connection.ConnectionId,
                () => WitnessEndpoint.FromNetworkInterfaces(serverName, nicProvider.GetInterfaces()));
        }

        return null;
    }

    private async ValueTask<ResponseSegment?> HandleIoctlAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        IoctlMessage.Request req = IoctlMessage.ParseRequest(segment.Span, Smb2Header.Size);

        // [M5.3] FSCTL_VALIDATE_NEGOTIATE_INFO — secure-negotiate downgrade check (3.0/3.0.2).
        if (req.CtlCode == IoctlMessage.FsctlValidateNegotiateInfo)
            return HandleValidateNegotiate(connection, header, session, req);

        // [M6.2] FSCTL_QUERY_NETWORK_INTERFACE_INFO — advertise server NICs for multichannel.
        if (req.CtlCode == NetworkInterfaceInfoMessage.FsctlQueryNetworkInterfaceInfo)
            return HandleQueryNetworkInterfaceInfo(connection, header, session, req);

        // FSCTL_PIPE_TRANSCEIVE: DCERPC request → response via the named pipe.
        if (req.CtlCode == IoctlMessage.FsctlPipeTransceive
            && TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open)
            && open.Pipe is { } pipe)
        {
            // [C1.3] Witness WitnessrAsyncNotify is a long-pending call: send STATUS_PENDING now and the
            // RESP_ASYNC_NOTIFY out-of-band once a failover event is queued (or on cancel/teardown).
            if (pipe.Endpoint is WitnessEndpoint witness
                && witness.TryBeginAsyncNotify(req.Input, out WitnessRegistration reg, out uint callId))
                return BeginWitnessAsyncNotify(connection, header, session, open, reg, callId, req.PersistentId, req.VolatileId);

            byte[] output = pipe.Transceive(req.Input);
            return MaybeSigned(session, RespHeader(header, session),
                IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, output));
        }

        // FSCTL_SRV_ENUMERATE_SNAPSHOTS: list "Previous Versions" of a versioned share.
        if (req.CtlCode == IoctlMessage.FsctlSrvEnumerateSnapshots)
            return HandleEnumerateSnapshots(header, session, req);

        // [M5.1] Server-side copy: hand out a resume key for a source, then copy chunks into a destination.
        if (req.CtlCode == CopyChunkMessage.FsctlSrvRequestResumeKey)
            return HandleRequestResumeKey(header, session, req);
        if (req.CtlCode is CopyChunkMessage.FsctlSrvCopyChunk or CopyChunkMessage.FsctlSrvCopyChunkWrite)
            return await HandleCopyChunkAsync(header, session, req).ConfigureAwait(false);

        // [M5.2] Sparse-file / reparse-point / DFS FSCTLs.
        switch (req.CtlCode)
        {
            case FsctlMessage.FsctlSetSparse:
            case FsctlMessage.FsctlSetZeroData:
            case FsctlMessage.FsctlQueryAllocatedRanges:
                return await HandleSparseFsctlAsync(header, session, req).ConfigureAwait(false);
            case FsctlMessage.FsctlGetReparsePoint:
            case FsctlMessage.FsctlSetReparsePoint:
            case FsctlMessage.FsctlDeleteReparsePoint:
                return await HandleReparseFsctlAsync(header, session, req).ConfigureAwait(false);
            case FsctlMessage.FsctlDfsGetReferrals:
            case FsctlMessage.FsctlDfsGetReferralsEx:
                return HandleDfsGetReferrals(header, session, req);
        }

        return BuildError(header, NtStatus.InvalidDeviceRequest);
    }

    /// <summary>
    /// FSCTL_SRV_REQUEST_RESUME_KEY (MS-SMB2 §3.3.5.15.5): assigns the open a stable 24-byte opaque
    /// key and returns it. The client presents this key as the <c>SourceKey</c> of a later
    /// FSCTL_SRV_COPYCHUNK to identify the copy source.
    /// </summary>
    private ResponseSegment HandleRequestResumeKey(Smb2Header header, SmbSession session, IoctlMessage.Request req)
    {
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);

        // Assign once; a repeated request for the same open returns the same key.
        byte[] key = open.ResumeKey ??= System.Security.Cryptography.RandomNumberGenerator.GetBytes(CopyChunkMessage.ResumeKeyLength);
        byte[] output = CopyChunkMessage.BuildResumeKeyResponse(key);
        return MaybeSigned(session, RespHeader(header, session),
            IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, output));
    }

    /// <summary>
    /// FSCTL_SRV_COPYCHUNK / _WRITE (MS-SMB2 §3.3.5.15.6): copies the requested ranges from the source
    /// open (located by resume key within the same session) into the destination open the IOCTL was
    /// issued on. Chunk count/size and the total are bounded; exceeding a limit returns the maximums
    /// with STATUS_INVALID_PARAMETER so the client can re-chunk.
    /// </summary>
    private async ValueTask<ResponseSegment> HandleCopyChunkAsync(Smb2Header header, SmbSession session, IoctlMessage.Request req)
    {
        // Destination handle = the open the IOCTL targets; must be writable.
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen dest) || dest.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);
        if (!TryGetFileStore(session, header.TreeId, out IFileStore destStore, out NtStatus destErr))
            return BuildError(header, destErr);
        if ((dest.GrantedAccess & AccessMask.WriteAccess) == 0)
            return BuildError(header, NtStatus.AccessDenied);

        CopyChunkMessage.CopyRequest copy = CopyChunkMessage.ParseCopyRequest(req.Input);

        // Locate the source by resume key (same session, possibly a different tree/share).
        if (!TryFindOpenByResumeKey(session, copy.SourceKey, out SmbOpen source) || source.LocalOpen is null)
            return BuildError(header, NtStatus.ObjectNameNotFound);
        if ((source.GrantedAccess & AccessMask.FileReadData) == 0)
            return BuildError(header, NtStatus.AccessDenied);
        if (source.TreeConnect.Share.FileStore is not { } sourceStore)
            return BuildError(header, NtStatus.ObjectNameNotFound);

        // Enforce the server-side-copy limits (§2.2.31.1) before doing any I/O.
        if (!ValidateCopyLimits(copy.Chunks))
        {
            Smb2Header limitHeader = RespHeader(header, session);
            limitHeader.Status = NtStatus.InvalidParameter;
            return MaybeSigned(session, limitHeader, IoctlMessage.BuildResponseBody(
                req.CtlCode, req.PersistentId, req.VolatileId, CopyChunkMessage.BuildLimitExceededResponse()));
        }

        uint chunksWritten = 0;
        uint totalWritten = 0;
        foreach (CopyChunkMessage.Chunk chunk in copy.Chunks)
        {
            FileStoreResult<long> copied = await CopyRangeAsync(
                sourceStore, source.LocalOpen, (long)chunk.SourceOffset,
                destStore, dest.LocalOpen, (long)chunk.TargetOffset, chunk.Length).ConfigureAwait(false);

            if (!copied.IsSuccess)
            {
                // Report progress so far alongside the failure (§3.3.5.15.6).
                Smb2Header failHeader = RespHeader(header, session);
                failHeader.Status = copied.Status;
                return MaybeSigned(session, failHeader, IoctlMessage.BuildResponseBody(
                    req.CtlCode, req.PersistentId, req.VolatileId,
                    CopyChunkMessage.BuildCopyResponse(chunksWritten, 0, totalWritten)));
            }

            chunksWritten++;
            totalWritten += (uint)copied.Value;
        }

        byte[] output = CopyChunkMessage.BuildCopyResponse(chunksWritten, 0, totalWritten);
        return MaybeSigned(session, RespHeader(header, session),
            IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, output));
    }

    /// <summary>Validates chunk count / per-chunk size / total against the §2.2.31.1 limits.</summary>
    private static bool ValidateCopyLimits(IReadOnlyList<CopyChunkMessage.Chunk> chunks)
    {
        if (chunks.Count > CopyChunkMessage.MaxChunks)
            return false;
        ulong total = 0;
        foreach (CopyChunkMessage.Chunk chunk in chunks)
        {
            if (chunk.Length > CopyChunkMessage.MaxChunkSize)
                return false;
            total += chunk.Length;
        }
        return total <= CopyChunkMessage.MaxTotalSize;
    }

    /// <summary>Finds the open in the session whose <see cref="SmbOpen.ResumeKey"/> matches (constant-length compare).</summary>
    private static bool TryFindOpenByResumeKey(SmbSession session, byte[] sourceKey, out SmbOpen match)
    {
        foreach (SmbOpen candidate in session.Opens.Values)
        {
            if (candidate.ResumeKey is { } key && key.AsSpan().SequenceEqual(sourceKey))
            {
                match = candidate;
                return true;
            }
        }
        match = null!;
        return false;
    }

    /// <summary>
    /// Copies one range, preferring the backend's native offload (<see cref="IFileStore.CopyRangeAsync"/>)
    /// when source and destination share the same store, and otherwise falling back to a bounded
    /// user-space read/write loop that also spans two different backends (cross-share copy).
    /// </summary>
    private static async ValueTask<FileStoreResult<long>> CopyRangeAsync(
        IFileStore sourceStore, IFileHandle source, long sourceOffset,
        IFileStore destStore, IFileHandle destination, long destOffset, long length)
    {
        if (length <= 0)
            return FileStoreResult<long>.Ok(0);

        if (ReferenceEquals(sourceStore, destStore))
        {
            FileStoreResult<long> offloaded = await destStore.CopyRangeAsync(
                source, sourceOffset, destination, destOffset, length).ConfigureAwait(false);
            if (offloaded.Status != NtStatus.NotSupported)
                return offloaded;
        }

        // Fallback: pull the range through a buffer. 64 KiB blocks keep the peak allocation bounded
        // even for the maximum 1 MiB chunk.
        const int block = 64 * 1024;
        var buffer = new byte[(int)Math.Min(length, block)];
        long remaining = length;
        long copied = 0;
        while (remaining > 0)
        {
            int want = (int)Math.Min(remaining, buffer.Length);
            FileStoreResult<int> read = await sourceStore.ReadAsync(
                source, sourceOffset + copied, buffer.AsMemory(0, want)).ConfigureAwait(false);
            if (!read.IsSuccess)
                return FileStoreResult<long>.Fail(read.Status);
            if (read.Value == 0)
                break;                       // source EOF — copy what was available

            int off = 0;
            while (off < read.Value)
            {
                FileStoreResult<int> written = await destStore.WriteAsync(
                    destination, destOffset + copied + off, buffer.AsMemory(off, read.Value - off)).ConfigureAwait(false);
                if (!written.IsSuccess)
                    return FileStoreResult<long>.Fail(written.Status);
                if (written.Value == 0)
                    return FileStoreResult<long>.Fail(NtStatus.DiskFull);
                off += written.Value;
            }

            copied += read.Value;
            remaining -= read.Value;
        }

        return FileStoreResult<long>.Ok(copied);
    }

    /// <summary>
    /// [M5.2] FSCTL_SET_SPARSE / FSCTL_SET_ZERO_DATA / FSCTL_QUERY_ALLOCATED_RANGES. Requires the
    /// backend to implement <see cref="ISparseFileStore"/>; otherwise <c>STATUS_NOT_SUPPORTED</c>.
    /// </summary>
    private async ValueTask<ResponseSegment> HandleSparseFsctlAsync(Smb2Header header, SmbSession session, IoctlMessage.Request req)
    {
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);
        if (open.TreeConnect.Share.FileStore is not ISparseFileStore sparse)
            return BuildError(header, NtStatus.NotSupported);

        switch (req.CtlCode)
        {
            case FsctlMessage.FsctlSetSparse:
            {
                // Setting sparse mutates file state → needs write access.
                if ((open.GrantedAccess & AccessMask.WriteAccess) == 0)
                    return BuildError(header, NtStatus.AccessDenied);
                NtStatus status = await sparse.SetSparseAsync(open.LocalOpen, FsctlMessage.ParseSetSparse(req.Input)).ConfigureAwait(false);
                return IoctlResult(header, session, req, status, []);
            }
            case FsctlMessage.FsctlSetZeroData:
            {
                if ((open.GrantedAccess & AccessMask.WriteAccess) == 0)
                    return BuildError(header, NtStatus.AccessDenied);
                FsctlMessage.FileRange range = FsctlMessage.ParseZeroData(req.Input);
                NtStatus status = await sparse.SetZeroDataAsync(open.LocalOpen, range.Offset, range.Length).ConfigureAwait(false);
                return IoctlResult(header, session, req, status, []);
            }
            default: // FsctlQueryAllocatedRanges
            {
                if ((open.GrantedAccess & AccessMask.FileReadData) == 0)
                    return BuildError(header, NtStatus.AccessDenied);
                FsctlMessage.FileRange query = FsctlMessage.ParseAllocatedRangeQuery(req.Input);
                FileStoreResult<IReadOnlyList<FsctlMessage.FileRange>> result =
                    await sparse.QueryAllocatedRangesAsync(open.LocalOpen, query.Offset, query.Length).ConfigureAwait(false);
                if (!result.IsSuccess)
                    return BuildError(header, result.Status);

                byte[] output = FsctlMessage.BuildAllocatedRanges(result.Value!);
                // Honour the client's output cap (§2.2.31): report BUFFER_TOO_SMALL if it does not fit.
                if ((uint)output.Length > req.MaxOutputResponse)
                    return BuildError(header, NtStatus.BufferTooSmall);
                return IoctlResult(header, session, req, NtStatus.Success, output);
            }
        }
    }

    /// <summary>
    /// [M5.2] FSCTL_GET/SET/DELETE_REPARSE_POINT. Requires the backend to implement
    /// <see cref="IReparsePointStore"/>; GET on a non-reparse backend answers
    /// <c>STATUS_NOT_A_REPARSE_POINT</c>, SET/DELETE answer <c>STATUS_NOT_SUPPORTED</c>.
    /// </summary>
    private async ValueTask<ResponseSegment> HandleReparseFsctlAsync(Smb2Header header, SmbSession session, IoctlMessage.Request req)
    {
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);
        IReparsePointStore? reparse = open.TreeConnect.Share.FileStore as IReparsePointStore;

        if (req.CtlCode == FsctlMessage.FsctlGetReparsePoint)
        {
            if (reparse is null)
                return BuildError(header, NtStatus.NotAReparsePoint);
            FileStoreResult<byte[]> result = await reparse.GetReparsePointAsync(open.LocalOpen).ConfigureAwait(false);
            if (!result.IsSuccess)
                return BuildError(header, result.Status);
            byte[] data = result.Value!;
            if ((uint)data.Length > req.MaxOutputResponse)
                return BuildError(header, NtStatus.BufferTooSmall);
            return IoctlResult(header, session, req, NtStatus.Success, data);
        }

        // SET / DELETE mutate the file → write access + a reparse-capable backend.
        if (reparse is null)
            return BuildError(header, NtStatus.NotSupported);
        if ((open.GrantedAccess & AccessMask.WriteAccess) == 0)
            return BuildError(header, NtStatus.AccessDenied);

        NtStatus status = req.CtlCode == FsctlMessage.FsctlSetReparsePoint
            ? await reparse.SetReparsePointAsync(open.LocalOpen, req.Input).ConfigureAwait(false)
            : await reparse.DeleteReparsePointAsync(open.LocalOpen, req.Input).ConfigureAwait(false);
        return IoctlResult(header, session, req, status, []);
    }

    /// <summary>
    /// [M5.3] FSCTL_VALIDATE_NEGOTIATE_INFO (MS-SMB2 §3.3.5.15.12): the client re-sends the NEGOTIATE
    /// parameters it observed so the server can prove a man-in-the-middle did not downgrade them. Every
    /// field (capabilities, client GUID, security mode, and the negotiated dialect derived from the
    /// dialect list) must match what this connection actually negotiated; any mismatch is treated as an
    /// attack and the transport connection is terminated with no response. On success the server returns
    /// its own negotiated values (signed, so the client can trust them).
    /// </summary>
    private ResponseSegment? HandleValidateNegotiate(SmbConnection connection, Smb2Header header, SmbSession session, IoctlMessage.Request req)
    {
        IoctlMessage.ValidateNegotiateRequest v = IoctlMessage.ParseValidateNegotiate(req.Input);

        ushort negotiated = PickDialect(v.Dialects);
        bool matches =
            (uint)connection.ClientCapabilities == v.Capabilities
            && connection.ClientGuid.AsSpan().SequenceEqual(v.Guid)
            && (ushort)connection.ClientSecurityMode == v.SecurityMode
            && negotiated == (ushort)connection.Dialect;

        if (!matches)
        {
            // Downgrade attempt (or a broken client): drop the connection without answering.
            _log?.Invoke($"[validate-negotiate] mismatch on conn {connection.ConnectionId:N} → terminating");
            connection.MustTerminate = true;
            return null;
        }

        byte[] output = IoctlMessage.BuildValidateNegotiateResponse(
            (uint)connection.ServerCapabilities, _server.Options.ServerGuid,
            (ushort)connection.ServerSecurityMode, (ushort)connection.Dialect);
        return MaybeSigned(session, RespHeader(header, session),
            IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, output));
    }

    /// <summary>
    /// [M6.2] FSCTL_QUERY_NETWORK_INTERFACE_INFO (§3.3.5.15.4): returns the server's network interfaces
    /// so a multichannel client can open extra connections and bind them. Issued without a file handle
    /// (FileId 0xFFFF…). Refused when multichannel is disabled or the dialect is &lt; 3.0.
    /// </summary>
    private ResponseSegment HandleQueryNetworkInterfaceInfo(SmbConnection connection, Smb2Header header, SmbSession session, IoctlMessage.Request req)
    {
        if (!_server.Options.EnableMultichannel || !connection.Dialect.IsSmb3OrLater())
            return BuildError(header, NtStatus.NotSupported);

        byte[] output = NetworkInterfaceInfoMessage.Build(_server.Options.NetworkInterfaceProvider.GetInterfaces());

        // Honour the client's output cap (§3.3.5.15): if the interface list doesn't fit, ask it to retry.
        if (output.Length > req.MaxOutputResponse)
            return BuildError(header, NtStatus.BufferTooSmall);

        return MaybeSigned(session, RespHeader(header, session),
            IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, output));
    }

    /// <summary>
    /// [M7.1] FSCTL_DFS_GET_REFERRALS / _EX (MS-DFSC §3.3.5.4): resolves the requested path against the
    /// configured DFS namespace and returns a referral (target list). Issued on IPC$ without a file
    /// handle. With no namespace configured, or a path outside it, the answer is <c>STATUS_NOT_FOUND</c>
    /// so the client uses the literal path (§3.3.5.15.2).
    /// </summary>
    private ResponseSegment HandleDfsGetReferrals(Smb2Header header, SmbSession session, IoctlMessage.Request req)
    {
        IDfsNamespace? ns = _server.Options.DfsNamespace;
        if (ns is null)
            return BuildError(header, NtStatus.NotFound);

        DfsReferralMessage.Request dfsReq = req.CtlCode == FsctlMessage.FsctlDfsGetReferralsEx
            ? DfsReferralMessage.ParseRequestEx(req.Input)
            : DfsReferralMessage.ParseRequest(req.Input);

        DfsReferralResult? result = ns.Resolve(dfsReq.RequestFileName);
        if (result is null || result.Targets.Count == 0)
            return BuildError(header, NtStatus.NotFound);

        ushort serverType = result.IsRootReferral
            ? DfsReferralMessage.ServerTypeRoot
            : DfsReferralMessage.ServerTypeLink;
        var entries = result.Targets
            .Select(t => new DfsReferralMessage.ReferralEntry
            {
                DfsPath = result.ConsumedPath,
                TargetPath = t.TargetPath,
                TimeToLive = result.TimeToLiveSeconds,
                ServerType = serverType,
            })
            .ToList();

        uint headerFlags = result.IsRootReferral
            ? DfsReferralMessage.HeaderFlagReferralServers
            : DfsReferralMessage.HeaderFlagStorageServers;
        var pathConsumed = (ushort)(result.ConsumedPath.Length * 2);

        byte[] output = DfsReferralMessage.BuildResponse(pathConsumed, headerFlags, entries);

        // Honour the client's output cap (§3.3.5.15): if the referral list doesn't fit, ask it to retry.
        if (output.Length > req.MaxOutputResponse)
            return BuildError(header, NtStatus.BufferTooSmall);

        return MaybeSigned(session, RespHeader(header, session),
            IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, output));
    }

    /// <summary>
    /// [M7.2] Builds the full DFS namespace path (<c>\Server\Share\relative</c>) for a share-relative
    /// CREATE name, so it can be checked against the DFS namespace. Matches the path a client sends in a
    /// referral request for the same share, keeping link resolution and referral serving consistent.
    /// </summary>
    private string BuildDfsPath(string shareName, string relativeName)
    {
        string rel = relativeName.Replace('/', '\\').Trim('\\');
        string basePath = $"\\{_server.Options.ServerName}\\{shareName}";
        return rel.Length == 0 ? basePath : $"{basePath}\\{rel}";
    }

    /// <summary>Greatest dialect this server supports among the client-offered list (0 = none common).</summary>
    private static ushort PickDialect(ushort[] offered)
    {
        ushort best = 0;
        foreach (ushort d in offered)
            if (Array.IndexOf(SupportedDialects, d) >= 0 && d > best)
                best = d;
        return best;
    }

    private static readonly ushort[] SupportedDialects =
    [
        (ushort)SmbDialect.Smb202, (ushort)SmbDialect.Smb210,
        (ushort)SmbDialect.Smb300, (ushort)SmbDialect.Smb302, (ushort)SmbDialect.Smb311,
    ];

    /// <summary>Builds an IOCTL response with an explicit NT status and output buffer.</summary>
    private ResponseSegment IoctlResult(Smb2Header header, SmbSession session, IoctlMessage.Request req, NtStatus status, ReadOnlySpan<byte> output)
    {
        if (status != NtStatus.Success)
            return BuildError(header, status);
        return MaybeSigned(session, RespHeader(header, session),
            IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, output));
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
        if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
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

        // [C2] A persistent handle is gone for good on CLOSE → drop its restart-surviving record.
        if (open.IsPersistentHandle && _server.Options.DurableHandleStore is IPersistentHandleStore persistentStore)
            persistentStore.RemovePersisted(open.PersistentFileId, open.VolatileFileId);

        // A DELETE_ON_CLOSE entry disappears from its parent directory on dispose → capture the path
        // beforehand and break the parent's directory lease afterwards (directory leasing, M1.3).
        string? removedPhysicalPath = open.DeleteOnClose ? open.LocalOpen?.PhysicalPath : null;
        if (open.LocalOpen is not null)
            await open.LocalOpen.DisposeAsync().ConfigureAwait(false);
        if (removedPhysicalPath is not null)
            BreakParentDirectoryLease(removedPhysicalPath);

        _server.Options.Metrics.OnHandleClosed();
        if (open.DeleteOnClose)
            Audit(SmbAuditEventType.FileDeleted, SmbLogLevel.Information, connection,
                user: DescribeIdentity(session.Identity), share: open.TreeConnect.Share.Name, path: open.PathName);
        Audit(SmbAuditEventType.FileClosed, SmbLogLevel.Information, connection,
            user: DescribeIdentity(session.Identity), share: open.TreeConnect.Share.Name, path: open.PathName);

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
        if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
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
        {
            _server.Options.Metrics.OnLockContention();
            return BuildError(header, NtStatus.FileLockConflict);
        }
        var buffer = new byte[length];
        FileStoreResult<int> result = await store.ReadAsync(open.LocalOpen, (long)req.Offset, buffer).ConfigureAwait(false);
        if (!result.IsSuccess)
            return BuildError(header, result.Status);
        if (result.Value == 0 && length > 0)
            return BuildError(header, NtStatus.EndOfFile);

        _server.Options.Metrics.OnBytesRead(open.TreeConnect.Share.Name, result.Value);
        return MaybeSigned(session, RespHeader(header, session),
            ReadMessage.BuildResponseBody(buffer.AsSpan(0, result.Value)));
    }

    private async ValueTask<ResponseSegment> HandleWriteAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
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
        {
            _server.Options.Metrics.OnLockContention();
            return BuildError(header, NtStatus.FileLockConflict);
        }

        // [M11.1] Quota enforcement: reserve the bytes by which this write grows the file against the
        // owner's (authenticated user's) quota; over-limit → STATUS_DISK_FULL. Only when a provider is
        // active and the caller has a resolvable SID (anonymous writes are not charged).
        IQuotaProvider quota = _server.Options.QuotaProvider;
        IShare quotaShare = open.TreeConnect.Share;
        long quotaReserved = 0;
        Sid? quotaOwner = null;
        if (quota.IsSupported && Sid.TryParse(session.Identity?.UserSid, out Sid owner))
        {
            quotaOwner = owner;
            long currentSize = ToStat(await open.LocalOpen.GetInfoAsync().ConfigureAwait(false)).EndOfFile;
            long endOfWrite = (long)req.Offset + req.Data.Length;
            quotaReserved = Math.Max(0, endOfWrite - currentSize);
            if (quotaReserved > 0 && !quota.TryReserve(quotaShare, owner, quotaReserved))
                return BuildError(header, NtStatus.DiskFull);
        }

        FileStoreResult<int> result = await store.WriteAsync(open.LocalOpen, (long)req.Offset, req.Data).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            if (quotaReserved > 0 && quotaOwner is not null) quota.Release(quotaShare, quotaOwner, quotaReserved);
            return BuildError(header, result.Status);
        }

        _server.Options.Metrics.OnBytesWritten(open.TreeConnect.Share.Name, result.Value);
        return MaybeSigned(session, RespHeader(header, session),
            WriteMessage.BuildResponseBody((uint)result.Value));
    }

    private async ValueTask<ResponseSegment> HandleQueryDirectoryAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
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
            // [D2] Bound the materialized listing so a huge directory cannot exhaust server memory. The
            // built-in backend stops enumerating early; if the directory holds more than the cap the scan
            // is refused (STATUS_INSUFFICIENT_RESOURCES) rather than served silently incomplete.
            int maxEntries = _server.Options.MaxDirectoryEnumerationEntries;
            FileStoreResult<BoundedDirectoryListing> listing =
                await store.QueryDirectoryAsync(open.LocalOpen, req.SearchPattern, maxEntries).ConfigureAwait(false);
            if (!listing.IsSuccess)
                return BuildError(header, listing.Status);
            if (listing.Value.Truncated)
                return BuildError(header, NtStatus.InsufficientResources);
            if (listing.Value.Entries.Count == 0)
                return BuildError(header, NtStatus.NoSuchFile);
            open.DirectoryListing = listing.Value.Entries;
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
        if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        QueryInfoMessage.Request req = QueryInfoMessage.ParseRequest(segment.Span, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);

        if (req.InfoType == InfoType.Security)
            return await HandleQuerySecurityAsync(session, header, open, req).ConfigureAwait(false);

        // [M11.1] Disk quota (QUERY_QUOTA_INFO, §2.2.37 InfoType.Quota).
        if (req.InfoType == InfoType.Quota)
            return HandleQueryQuota(session, header, open, req);

        // [M9.1/M9.2] Stream enumeration and extended attributes need the backend, not just the stat.
        if (req.InfoType == InfoType.File)
        {
            switch ((FileInformationClass)req.FileInfoClass)
            {
                case FileInformationClass.FileStreamInformation:
                    return await HandleQueryStreamsAsync(session, header, open, req).ConfigureAwait(false);
                case FileInformationClass.FileFullEaInformation:
                    return await HandleQueryEaAsync(session, header, open, req).ConfigureAwait(false);
            }
        }

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
        if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);
        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err))
            return BuildError(header, err);

        SetInfoMessage.Request req = SetInfoMessage.ParseRequest(segment.Span, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open) || open.LocalOpen is null)
            return BuildError(header, NtStatus.FileClosed);

        if (req.InfoType == InfoType.Security)
            return await HandleSetSecurityAsync(connection, session, header, store, open, req).ConfigureAwait(false);

        // [M11.1] Disk quota (SET_QUOTA_INFO, §2.2.39 InfoType.Quota).
        if (req.InfoType == InfoType.Quota)
            return HandleSetQuota(session, header, open, req);

        if (req.InfoType != InfoType.File)
            return BuildError(header, NtStatus.NotSupported);

        var infoClass = (FileInformationClass)req.FileInfoClass;

        // [M9.2] Extended attributes are backend state, handled via the IExtendedAttributeStore seam.
        if (infoClass == FileInformationClass.FileFullEaInformation)
            return await HandleSetEaAsync(session, header, store, open, req).ConfigureAwait(false);

        // [M3.3] Enforce the handle's granted access for state-changing SET_INFO classes: truncation is a
        // write, delete-disposition and rename both require DELETE, and times/attributes require
        // FILE_WRITE_ATTRIBUTES now that they are actually applied to the backend.
        uint requiredAccess = infoClass switch
        {
            FileInformationClass.FileEndOfFileInformation => AccessMask.FileWriteData,
            FileInformationClass.FileDispositionInformation => AccessMask.Delete,
            FileInformationClass.FileRenameInformation => AccessMask.Delete,
            FileInformationClass.FileBasicInformation => AccessMask.FileWriteAttributes,
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
            FileInformationClass.FileBasicInformation =>
                await DoSetBasicInfoAsync(store, open.LocalOpen, req.Buffer).ConfigureAwait(false),
            // Allocation size is a hint about reserved space, not observable content — accepted as a no-op.
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
    /// SET_INFO/FileBasicInformation (MS-FSCC §2.4.7): timestamps + DOS attributes. Applied by backends that
    /// implement <see cref="IBasicInfoStore"/>; for the rest this stays the historical accept-and-drop, which
    /// keeps ordinary Windows operations working (every file copy stamps its destination's times at the end)
    /// at the cost of wrong metadata — see the remarks on <see cref="IBasicInfoStore"/>.
    /// </summary>
    private static ValueTask<NtStatus> DoSetBasicInfoAsync(IFileStore store, IFileHandle handle, byte[] buffer)
        => store is IBasicInfoStore basicInfo
            ? basicInfo.SetBasicInfoAsync(handle, SetInfoMessage.ParseBasicInfo(buffer))
            : new ValueTask<NtStatus>(NtStatus.Success);

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
        SmbConnection connection, SmbSession session, Smb2Header header, IFileStore store, SmbOpen open, SetInfoMessage.Request req)
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

        Audit(SmbAuditEventType.PermissionChanged, SmbLogLevel.Information, connection,
            user: DescribeIdentity(session.Identity), share: open.TreeConnect.Share.Name, path: open.PathName);
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

    /// <summary>
    /// [M9.1] QUERY_INFO FileStreamInformation (§2.4.43): enumerates the file's data streams. A backend
    /// with <see cref="INamedStreamStore"/> reports the default plus every named stream; any other
    /// backend reports just the default unnamed <c>::$DATA</c> stream from the file size.
    /// </summary>
    private async ValueTask<ResponseSegment> HandleQueryStreamsAsync(
        SmbSession session, Smb2Header header, SmbOpen open, QueryInfoMessage.Request req)
    {
        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err))
            return BuildError(header, err);

        IReadOnlyList<FsccStreamEntry> entries;
        if (store is INamedStreamStore streams)
        {
            FileStoreResult<IReadOnlyList<StreamInfo>> res = await streams.QueryStreamsAsync(open.LocalOpen!).ConfigureAwait(false);
            if (!res.IsSuccess)
                return BuildError(header, res.Status);
            entries = res.Value!.Select(s => new FsccStreamEntry(s.Name, s.Size, s.AllocationSize)).ToList();
        }
        else
        {
            FileEntryInfo info = await open.LocalOpen!.GetInfoAsync().ConfigureAwait(false);
            entries = info.IsDirectory
                ? Array.Empty<FsccStreamEntry>()
                : [new FsccStreamEntry(string.Empty, info.EndOfFile, info.AllocationSize)];
        }

        byte[] buffer = StreamInformation.Build(entries);
        if ((uint)buffer.Length > req.OutputBufferLength)
            return BuildError(header, NtStatus.BufferTooSmall);
        return MaybeSigned(session, RespHeader(header, session), QueryInfoMessage.BuildResponseBody(buffer));
    }

    /// <summary>
    /// [M9.2] QUERY_INFO FileFullEaInformation (§2.4.15): returns the file's extended attributes. Needs
    /// <see cref="IExtendedAttributeStore"/> (else an empty list) and the FILE_READ_EA right on the open.
    /// </summary>
    private async ValueTask<ResponseSegment> HandleQueryEaAsync(
        SmbSession session, Smb2Header header, SmbOpen open, QueryInfoMessage.Request req)
    {
        if (!TryGetFileStore(session, header.TreeId, out IFileStore store, out NtStatus err))
            return BuildError(header, err);

        IReadOnlyList<FsccEaEntry> eas = [];
        if (store is IExtendedAttributeStore eaStore)
        {
            if ((open.GrantedAccess & AccessMask.FileReadEa) == 0)
                return BuildError(header, NtStatus.AccessDenied);
            FileStoreResult<IReadOnlyList<ExtendedAttribute>> res = await eaStore.GetExtendedAttributesAsync(open.LocalOpen!).ConfigureAwait(false);
            if (!res.IsSuccess)
                return BuildError(header, res.Status);
            eas = res.Value!.Select(e => new FsccEaEntry(e.Flags, e.Name, e.Value)).ToList();
        }

        byte[] buffer = FullEaInformation.Build(eas);
        if ((uint)buffer.Length > req.OutputBufferLength)
            return BuildError(header, NtStatus.BufferTooSmall);
        return MaybeSigned(session, RespHeader(header, session), QueryInfoMessage.BuildResponseBody(buffer));
    }

    /// <summary>
    /// [M9.2] SET_INFO FileFullEaInformation (§2.4.15): applies an EA change set (add/replace; a
    /// zero-length value deletes). Needs <see cref="IExtendedAttributeStore"/> and FILE_WRITE_EA.
    /// </summary>
    private async ValueTask<ResponseSegment> HandleSetEaAsync(
        SmbSession session, Smb2Header header, IFileStore store, SmbOpen open, SetInfoMessage.Request req)
    {
        if (store is not IExtendedAttributeStore eaStore)
            return BuildError(header, NtStatus.NotSupported);
        if ((open.GrantedAccess & AccessMask.FileWriteEa) == 0)
            return BuildError(header, NtStatus.AccessDenied);

        IReadOnlyList<FsccEaEntry> parsed;
        try { parsed = FullEaInformation.Parse(req.Buffer); }
        catch (SmbWireFormatException) { return BuildError(header, NtStatus.InvalidParameter); }

        var entries = parsed.Select(e => new ExtendedAttribute(e.Name, e.Value, e.Flags)).ToList();
        NtStatus status = await eaStore.SetExtendedAttributesAsync(open.LocalOpen!, entries).ConfigureAwait(false);
        if (status != NtStatus.Success)
            return BuildError(header, status);
        return MaybeSigned(session, RespHeader(header, session), SetInfoMessage.BuildResponseBody());
    }

    private async ValueTask<ResponseSegment> HandleFlushAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
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
    /// [M9.1] Splits an SMB CREATE name into its base path and (alternate-data-stream) name. The stream
    /// suffix has the form <c>:streamname[:$DATA]</c> on the leaf component; the stream <b>type</b> after
    /// the second colon is ignored (only <c>$DATA</c> streams are modeled). Returns <c>true</c> when a
    /// colon (stream suffix) is present — the returned <paramref name="streamName"/> is empty for the
    /// default unnamed stream (<c>file::$DATA</c>). Paths are backslash-separated and drive-less, so a
    /// colon can only introduce a stream.
    /// </summary>
    internal static bool TrySplitStreamName(string name, out string baseName, out string streamName)
    {
        baseName = name;
        streamName = string.Empty;

        int slash = name.LastIndexOf('\\');
        int colon = name.IndexOf(':', slash + 1);
        if (colon < 0)
            return false;

        baseName = name[..colon];
        string rest = name[(colon + 1)..];
        int typeColon = rest.IndexOf(':');            // ":$DATA" type suffix, if any
        streamName = typeColon >= 0 ? rest[..typeColon] : rest;
        return true;
    }

    /// <summary>
    /// Builds the caller's SID set for a DACL access check (M3.3): the primary user SID, all group SIDs
    /// and the well-known Everyone group; an authenticated (non-anonymous) caller additionally carries
    /// Authenticated Users. Unparseable SID strings are skipped rather than failing the whole check.
    /// </summary>
    /// <summary>
    /// [M11.1] QUERY_INFO with InfoType Quota (§2.2.37.1): returns the share's FILE_QUOTA_INFORMATION
    /// records (optionally filtered to the requested SIDs), capped to the client's output buffer. An
    /// unsupported provider → NOT_SUPPORTED; an empty result → NO_MORE_ENTRIES (scan exhausted).
    /// </summary>
    private ResponseSegment HandleQueryQuota(SmbSession session, Smb2Header header, SmbOpen open, QueryInfoMessage.Request req)
    {
        IQuotaProvider quota = _server.Options.QuotaProvider;
        if (!quota.IsSupported)
            return BuildError(header, NtStatus.NotSupported);

        QuotaMessage.QueryRequest qr = QuotaMessage.ParseQueryInfo(req.InputBuffer);
        IReadOnlyList<FileQuotaInformation> entries = quota.Query(open.TreeConnect.Share, qr.SidFilter);
        if (entries.Count == 0)
            return BuildError(header, NtStatus.NoMoreEntries);
        if (qr.ReturnSingle && entries.Count > 1)
            entries = [entries[0]];

        byte[] buffer = QuotaMessage.BuildQuotaInformation(entries, (int)req.OutputBufferLength);
        if (buffer.Length == 0)
            return BuildError(header, NtStatus.BufferTooSmall);

        return MaybeSigned(session, RespHeader(header, session), QueryInfoMessage.BuildResponseBody(buffer));
    }

    /// <summary>
    /// [M11.1] SET_INFO with InfoType Quota (§2.2.39): applies the supplied FILE_QUOTA_INFORMATION
    /// records (per-owner threshold/limit) to the share via the quota provider.
    /// </summary>
    private ResponseSegment HandleSetQuota(SmbSession session, Smb2Header header, SmbOpen open, SetInfoMessage.Request req)
    {
        IQuotaProvider quota = _server.Options.QuotaProvider;
        if (!quota.IsSupported)
            return BuildError(header, NtStatus.NotSupported);

        IReadOnlyList<FileQuotaInformation> entries = QuotaMessage.ParseQuotaInformation(req.Buffer);
        NtStatus status = quota.Set(open.TreeConnect.Share, entries);
        if (status != NtStatus.Success)
            return BuildError(header, status);

        return MaybeSigned(session, RespHeader(header, session), SetInfoMessage.BuildResponseBody());
    }

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
    /// <summary>
    /// Async teardown (docs/ENTERPRISE_HARDENING_ROADMAP.md, A4): the primary per-connection close path
    /// releases backend handles via <see cref="IFileHandle.DisposeAsync"/>, so an async backend never
    /// sync-over-async-blocks a pool thread while a connection tears down. The host calls this; the
    /// synchronous <see cref="OnConnectionClosed"/> remains for periodic sweeps and back-compat.
    /// </summary>
    public async ValueTask OnConnectionClosedAsync(SmbConnection connection)
    {
        foreach (SmbSession session in connection.Sessions.Values)
            foreach (IFileHandle handle in DetachOnConnectionClose(connection, session))
                await handle.DisposeAsync().ConfigureAwait(false);

        CancelNonSurvivingPending(connection);
        _server.WitnessRegistrations.RemoveAllForConnection(connection.ConnectionId); // [C1.4] drop witness registrations
    }

    public void OnConnectionClosed(SmbConnection connection)
    {
        foreach (SmbSession session in connection.Sessions.Values)
            foreach (IFileHandle handle in DetachOnConnectionClose(connection, session))
                handle.Dispose();

        CancelNonSurvivingPending(connection);
        _server.WitnessRegistrations.RemoveAllForConnection(connection.ConnectionId); // [C1.4] drop witness registrations
    }

    /// <summary>
    /// Detaches every open of <paramref name="session"/> from server-side state when the connection's last
    /// channel is gone, and returns the backend handles the caller must dispose (sync or async). Returns an
    /// empty list — and does not touch the session — while another bound channel keeps it alive.
    /// </summary>
    private List<IFileHandle> DetachOnConnectionClose(SmbConnection connection, SmbSession session)
    {
        // Multichannel (§3.3.7.1 applies per session, not per channel): drop only the channel this
        // connection provided. As long as another bound channel remains, the session and its opens
        // survive so the client keeps working over the surviving connection(s). Only when the last
        // channel goes are the opens released and the session removed. Sessions with no channel
        // table (2.x) collapse to the previous single-connection behaviour.
        session.Channels.TryRemove(connection.ConnectionId, out _);
        if (!session.Channels.IsEmpty)
            return [];

        List<IFileHandle> handles = DetachSessionOpens(session);
        _server.SessionGlobalList.TryRemove(session.SessionId, out _);
        return handles;
    }

    /// <summary>
    /// Pending async operations on this connection (blocking LOCK / CHANGE_NOTIFY): cancel only those whose
    /// session did NOT survive on another channel. The rest are left to complete and reroute their final
    /// response to a surviving channel (M6.3 failover, §3.3.5).
    /// </summary>
    private static void CancelNonSurvivingPending(SmbConnection connection)
    {
        foreach (PendingAsyncRequest pending in connection.PendingRequests.Values)
        {
            SmbSession? owner = pending.Owner?.Session;
            bool survives = owner is not null && !owner.Channels.IsEmpty;
            if (survives) continue;
            pending.Cancel();
            connection.PendingRequests.TryRemove(pending.MessageId, out _);
        }
    }

    /// <summary>
    /// Releases the server-side state of every open of <paramref name="session"/> (locks, oplocks,
    /// leases, share-mode reservations) and re-registers durable opens in the durable store, then clears
    /// the open table. Returns the non-durable backend handles for the caller to dispose (sync or async);
    /// the disposal is deliberately separated so the close path can await <see cref="IFileHandle.DisposeAsync"/>.
    /// </summary>
    private List<IFileHandle> DetachSessionOpens(SmbSession session)
    {
        var handles = new List<IFileHandle>();
        foreach (SmbOpen open in session.Opens.Values)
        {
            // [M4.1] A durable open is preserved across the transport drop: register it in the durable
            // store with a deadline and keep its backend handle, locks, oplock/lease and share-mode
            // reservation intact. It is restored on reconnect or released by the scavenger on expiry.
            if (open.IsDurable && open.LocalOpen is not null)
            {
                _server.Options.DurableHandleStore.Add(new DurableHandle
                {
                    PersistentId = open.PersistentFileId,
                    VolatileId = open.VolatileFileId,
                    Open = open,
                    Deadline = _server.Options.TimeProvider.GetUtcNow() + open.DurableTimeout,
                    OwnerKey = OwnerKey(session.Identity),
                    CreateGuid = open.DurableCreateGuid,
                    IsPersistent = open.IsPersistentHandle,
                });
                continue;
            }

            _server.Options.LockManager.ReleaseOwner(open);
            _server.Options.OplockManager.ReleaseOwner(open);
            _server.Options.LeaseManager.ReleaseOwner(open);
            if (open.ShareModeKey is { } shareKey) _server.Options.ShareModeManager.Close(shareKey, open);
            if (open.LocalOpen is { } handle) handles.Add(handle);
        }
        session.Opens.Clear();
        return handles;
    }

    /// <summary>
    /// Synchronous open release for the periodic sweeps (idle-session expiry) and LOGOFF, which are not on
    /// the async connection-close path. Disposes handles synchronously via <see cref="IDisposable.Dispose"/>.
    /// </summary>
    private void CloseSessionOpens(SmbSession session)
    {
        foreach (IFileHandle handle in DetachSessionOpens(session))
            handle.Dispose();
    }

    // --- Durable / persistent handles (Phase 4, M4.1) ---

    /// <summary>
    /// Restores a durable open (preserved across a transport drop) into the reconnecting session
    /// (§3.3.5.9.7). Validates the FileId is registered, not yet expired, and owned by the same
    /// principal, then re-attaches the existing open (backend handle, locks, oplock/lease, share-mode
    /// reservation are all intact) to the new session/tree and answers as an ordinary CREATE.
    /// </summary>
    private async ValueTask<ResponseSegment> HandleDurableReconnectAsync(
        Smb2Header header, SmbSession session, SmbTreeConnect tree, CreateContext reconnectCtx)
    {
        (ulong persistentId, ulong volatileId) = DurableHandleMessages.ParseReconnect(reconnectCtx.Data);
        (DurableHandle? dh, ResponseSegment? error) =
            await TryClaimForReconnectAsync(header, session, tree, persistentId, volatileId, expectedGuid: null).ConfigureAwait(false);
        if (dh is null)
            return error!.Value;
        return await RestoreDurableOpenAsync(header, session, tree, dh, DurableHandleMessages.BuildV1ResponseContext()).ConfigureAwait(false);
    }

    private async ValueTask<ResponseSegment> HandleDurableReconnectV2Async(
        Smb2Header header, SmbSession session, SmbTreeConnect tree, CreateContext reconnectCtx)
    {
        DurableHandleMessages.V2Reconnect rc = DurableHandleMessages.ParseV2Reconnect(reconnectCtx.Data);
        (DurableHandle? dh, ResponseSegment? error) =
            await TryClaimForReconnectAsync(header, session, tree, rc.PersistentId, rc.VolatileId, rc.CreateGuid).ConfigureAwait(false);
        if (dh is null)
            return error!.Value;
        CreateContext responseCtx = DurableHandleMessages.BuildV2ResponseContext(
            (uint)dh.Open.DurableTimeout.TotalMilliseconds, dh.IsPersistent);
        return await RestoreDurableOpenAsync(header, session, tree, dh, responseCtx).ConfigureAwait(false);
    }

    /// <summary>
    /// Claims a durable open for a reconnect and validates it: exists, not expired, matching create GUID
    /// (v2) and owned by the same principal. Two sources are tried in order — the <b>warm</b> in-process
    /// table (survives a TCP drop) and, for a persistent (CA) handle after a server restart, the <b>cold</b>
    /// restart-surviving record, which is rehydrated into a live open (C2). On any failure the claimed entry
    /// is left intact (re-added) and the returned <c>Error</c> carries the status; on success <c>Handle</c> is set.
    /// </summary>
    private async ValueTask<(DurableHandle? Handle, ResponseSegment? Error)> TryClaimForReconnectAsync(
        Smb2Header header, SmbSession session, SmbTreeConnect tree, ulong persistentId, ulong volatileId, Guid? expectedGuid)
    {
        // Warm path: a handle still live in this process (disconnected across a TCP drop).
        if (_server.Options.DurableHandleStore.TryClaim(persistentId, volatileId, out DurableHandle dh))
        {
            // Expired but not yet scavenged → release it now and report as gone.
            if (!dh.IsPersistent && dh.Deadline <= _server.Options.TimeProvider.GetUtcNow())
            {
                ReleaseDurable(dh);
                return (null, BuildError(header, NtStatus.ObjectNameNotFound));
            }
            if (expectedGuid is { } guid && dh.CreateGuid != guid)
            {
                _server.Options.DurableHandleStore.Add(dh);
                return (null, BuildError(header, NtStatus.ObjectNameNotFound));
            }
            if (!string.Equals(dh.OwnerKey, OwnerKey(session.Identity), StringComparison.Ordinal))
            {
                _server.Options.DurableHandleStore.Add(dh);
                return (null, BuildError(header, NtStatus.AccessDenied));
            }
            return (dh, null);
        }

        // [C2] Cold path: after a restart the warm table is empty, but a persistent handle's record survives.
        // Validate against the record metadata FIRST (no backend work), then rehydrate a live open.
        if (_server.Options.DurableHandleStore is IPersistentHandleStore persistent
            && persistent.TryClaimColdRecord(persistentId, volatileId, out PersistentHandleRecord record))
        {
            if (expectedGuid is { } guid && record.CreateGuid != guid)
            {
                persistent.ReturnColdRecord(record);
                return (null, BuildError(header, NtStatus.ObjectNameNotFound));
            }
            if (!string.Equals(record.OwnerKey, OwnerKey(session.Identity), StringComparison.Ordinal))
            {
                persistent.ReturnColdRecord(record);
                return (null, BuildError(header, NtStatus.AccessDenied));
            }

            DurableHandle? rehydrated = await RehydrateColdRecordAsync(tree, record).ConfigureAwait(false);
            if (rehydrated is null)
            {
                persistent.ReturnColdRecord(record);
                return (null, BuildError(header, NtStatus.ObjectNameNotFound));
            }
            return (rehydrated, null);
        }

        return (null, BuildError(header, NtStatus.ObjectNameNotFound)); // unknown or already scavenged
    }

    /// <summary>
    /// [C2] Rebuilds a live persistent open from a restart-surviving record: validates the reconnect share,
    /// re-reserves the share-mode and re-opens the backend handle so the dispatcher can resume I/O on it.
    /// Byte-range locks, oplocks and leases are not reconstructed (v1 scope). Returns null if the share is
    /// gone, the share-mode conflicts, or the backend re-open fails.
    /// </summary>
    private async ValueTask<DurableHandle?> RehydrateColdRecordAsync(SmbTreeConnect tree, PersistentHandleRecord record)
    {
        if (!string.Equals(record.ShareName, tree.Share.Name, StringComparison.OrdinalIgnoreCase) || tree.Share.FileStore is null)
            return null;

        var open = new SmbOpen
        {
            PersistentFileId = record.PersistentId,
            VolatileFileId = record.VolatileId,
            GrantedAccess = record.GrantedAccess,
            ShareAccess = record.ShareAccess,
            PathName = record.Path,
            IsDurable = true,
            IsPersistentHandle = true,
            DurableCreateGuid = record.CreateGuid,
            DurableTimeout = _server.Options.DurableHandleTimeout,
        };

        FileAccessIntent access = MapAccess(record.GrantedAccess);
        string shareKey = ShareModeKey(tree, record.Path);
        if (!_server.Options.ShareModeManager.TryOpen(shareKey, open, access, MapShare(record.ShareAccess)))
            return null;
        open.ShareModeKey = shareKey;

        FileStoreResult<FileCreateResult> result = await tree.Share.FileStore.CreateAsync(
            record.Path, access, CreateDispositionIntent.Open, directoryRequired: false, nonDirectoryRequired: false)
            .ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            _server.Options.ShareModeManager.Close(shareKey, open);
            return null;
        }
        open.LocalOpen = result.Value.Handle;

        return new DurableHandle
        {
            PersistentId = record.PersistentId,
            VolatileId = record.VolatileId,
            Open = open,
            Deadline = DateTimeOffset.MaxValue,
            OwnerKey = record.OwnerKey,
            CreateGuid = record.CreateGuid,
            IsPersistent = true,
        };
    }

    /// <summary>Re-attaches a validated durable open to the reconnecting session and answers as a CREATE.</summary>
    private async ValueTask<ResponseSegment> RestoreDurableOpenAsync(
        Smb2Header header, SmbSession session, SmbTreeConnect tree, DurableHandle dh, CreateContext responseContext)
    {
        SmbOpen open = dh.Open;
        open.Session = session;
        open.TreeConnect = tree;
        session.Opens[open.Key] = open;
        Interlocked.Increment(ref tree.OpenCount);

        FileEntryInfo info = await open.LocalOpen!.GetInfoAsync().ConfigureAwait(false);
        var response = new CreateResponse
        {
            OplockLevel = open.OplockLevel,
            CreateAction = CreateAction.Opened,
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
        byte[] responseContexts = CreateContextList.Serialize(new[] { responseContext });
        return MaybeSigned(session, RespHeader(header, session), response.ToBody(responseContexts));
    }

    /// <summary>Resolves a durable-v2 client's requested timeout (0 = server default, clamped to the max).</summary>
    private TimeSpan ResolveDurableTimeout(uint requestedMs)
    {
        if (requestedMs == 0)
            return _server.Options.DurableHandleTimeout;
        var requested = TimeSpan.FromMilliseconds(requestedMs);
        return requested > _server.Options.MaxDurableHandleTimeout ? _server.Options.MaxDurableHandleTimeout : requested;
    }

    /// <summary>Durability is only granted with a batch/exclusive oplock or a handle-caching lease (§3.3.5.9.6).</summary>
    private static bool DurabilityAllowed(OplockLevel oplock, LeaseState lease)
        => oplock is OplockLevel.Batch or OplockLevel.Exclusive || lease.HasFlag(LeaseState.Handle);

    /// <summary>Stable identity key used to bind a durable handle to its owner (SID preferred, else Domain\User).</summary>
    private static string OwnerKey(SecurityIdentity? identity)
        => identity?.UserSid ?? (identity is null ? "<none>" : $"{identity.DomainName}\\{identity.UserName}");

    /// <summary>
    /// Releases every durable open whose timeout has elapsed (the scavenger). A host calls this
    /// periodically; expiry is measured against <see cref="SmbServerOptions.TimeProvider"/>.
    /// </summary>
    public void ScavengeDurableHandles()
    {
        foreach (DurableHandle dh in _server.Options.DurableHandleStore.TakeExpired(_server.Options.TimeProvider.GetUtcNow()))
            ReleaseDurable(dh);
    }

    /// <summary>
    /// [M8.2] Sweeps idle/half-open state (host-driven, measured against
    /// <see cref="SmbServerOptions.TimeProvider"/>): expires valid sessions idle past
    /// <see cref="SmbServerOptions.SessionIdleTimeout"/>, and asks the host to close connections that
    /// have exceeded <see cref="SmbServerOptions.AuthenticationTimeout"/> without a valid session or
    /// <see cref="SmbServerOptions.ConnectionIdleTimeout"/> without any traffic. Each timeout is skipped
    /// when its option is <see cref="TimeSpan.Zero"/>.
    /// </summary>
    public void SweepIdleTimeouts()
    {
        SmbServerOptions opts = _server.Options;
        long now = opts.TimeProvider.GetUtcNow().Ticks;

        if (opts.SessionIdleTimeout > TimeSpan.Zero)
        {
            long sessionMax = opts.SessionIdleTimeout.Ticks;
            foreach (SmbSession session in _server.SessionGlobalList.Values)
            {
                if (session.State == SessionState.Valid && now - session.LastActivityTicks > sessionMax)
                    ExpireSession(session);
            }
        }

        long authMax = opts.AuthenticationTimeout.Ticks;
        long idleMax = opts.ConnectionIdleTimeout.Ticks;
        foreach (SmbConnection connection in _server.Connections.Values)
        {
            bool hasValidSession = connection.Sessions.Values.Any(s => s.State == SessionState.Valid);
            bool authExpired = !hasValidSession && opts.AuthenticationTimeout > TimeSpan.Zero
                && now - connection.CreatedTicks > authMax;
            bool idleExpired = opts.ConnectionIdleTimeout > TimeSpan.Zero
                && now - connection.LastActivityTicks > idleMax;
            if (authExpired || idleExpired)
                connection.RequestClose?.Invoke();
        }
    }

    /// <summary>[M8.2] Tears a session down out-of-band on idle timeout: releases its opens and removes it
    /// from the global list and every connection it was bound to (multichannel-safe).</summary>
    private void ExpireSession(SmbSession session)
    {
        Audit(SmbAuditEventType.SessionLogoff, SmbLogLevel.Information, null,
            user: DescribeIdentity(session.Identity), message: "idle timeout");
        _server.Options.Metrics.OnSessionClosed();
        CloseSessionOpens(session);
        _server.SessionGlobalList.TryRemove(session.SessionId, out _);
        foreach (SmbConnection connection in _server.Connections.Values)
            connection.Sessions.TryRemove(session.SessionId, out _);
        session.Channels.Clear();
        session.State = SessionState.Expired;
    }

    /// <summary>Fully releases a durable open's server-side state (backend handle, locks, oplock/lease, share mode).</summary>
    private void ReleaseDurable(DurableHandle dh)
    {
        SmbOpen open = dh.Open;
        _server.Options.LockManager.ReleaseOwner(open);
        _server.Options.OplockManager.ReleaseOwner(open);
        _server.Options.LeaseManager.ReleaseOwner(open);
        if (open.ShareModeKey is { } shareKey) _server.Options.ShareModeManager.Close(shareKey, open);
        open.LocalOpen?.Dispose();
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
