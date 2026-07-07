using Smb.Auth;
using Smb.FileSystem;
using Smb.FileSystem.Versioning;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Messages.Fscc;
using Smb.Protocol.Security;
using Smb.Protocol.Wire;
using Smb.Server.Durable;
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
        if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);
        if (!session.TreeConnects.TryGetValue(header.TreeId, out SmbTreeConnect? tree))
            return BuildError(header, NtStatus.NetworkNameDeleted);

        // Named-pipe share (IPC$): open a DCERPC pipe instead of using the file backend.
        if (tree.Share.Type == ShareType.Pipe)
            return HandlePipeCreate(connection, header, session, tree, segment.Span);

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
        var responseCtxList = new List<CreateContext>();

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
            DispatchOplockBreaks(grant.Breaks);
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
        }

        // A newly created entry changes its parent directory's listing → break any directory lease
        // cached on the parent so the holder re-enumerates (directory leasing, M1.3).
        if (outcome == CreateOutcome.Created)
            BreakParentDirectoryLease(handle.PhysicalPath);

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
                // No DFS namespace configured — the client falls back to the plain path (§3.3.5.15.2).
                return BuildError(header, NtStatus.NotFound);
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
        if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
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
        if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
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
            // Multichannel (§3.3.7.1 applies per session, not per channel): drop only the channel this
            // connection provided. As long as another bound channel remains, the session and its opens
            // survive so the client keeps working over the surviving connection(s). Only when the last
            // channel goes are the opens released and the session removed. Sessions with no channel
            // table (2.x) collapse to the previous single-connection behaviour.
            session.Channels.TryRemove(connection.ConnectionId, out _);
            if (!session.Channels.IsEmpty)
                continue;

            CloseSessionOpens(session);
            _server.SessionGlobalList.TryRemove(session.SessionId, out _);
        }

        // Pending async operations on this connection (blocking LOCK / CHANGE_NOTIFY): cancel only
        // those whose session did NOT survive on another channel. The rest are left to complete and
        // reroute their final response to a surviving channel (M6.3 failover, §3.3.5).
        foreach (PendingAsyncRequest pending in connection.PendingRequests.Values)
        {
            SmbSession? owner = pending.Owner?.Session;
            bool survives = owner is not null && !owner.Channels.IsEmpty;
            if (survives) continue;
            pending.Cancel();
            connection.PendingRequests.TryRemove(pending.MessageId, out _);
        }
    }

    private void CloseSessionOpens(SmbSession session)
    {
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
            open.LocalOpen?.Dispose();
        }
        session.Opens.Clear();
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
        if (!TryClaimForReconnect(header, session, persistentId, volatileId, expectedGuid: null, out DurableHandle dh, out ResponseSegment error))
            return error;
        return await RestoreDurableOpenAsync(header, session, tree, dh, DurableHandleMessages.BuildV1ResponseContext()).ConfigureAwait(false);
    }

    private async ValueTask<ResponseSegment> HandleDurableReconnectV2Async(
        Smb2Header header, SmbSession session, SmbTreeConnect tree, CreateContext reconnectCtx)
    {
        DurableHandleMessages.V2Reconnect rc = DurableHandleMessages.ParseV2Reconnect(reconnectCtx.Data);
        if (!TryClaimForReconnect(header, session, rc.PersistentId, rc.VolatileId, rc.CreateGuid, out DurableHandle dh, out ResponseSegment error))
            return error;
        CreateContext responseCtx = DurableHandleMessages.BuildV2ResponseContext(
            (uint)dh.Open.DurableTimeout.TotalMilliseconds, dh.IsPersistent);
        return await RestoreDurableOpenAsync(header, session, tree, dh, responseCtx).ConfigureAwait(false);
    }

    /// <summary>
    /// Claims a durable open for a reconnect and validates it: exists, not expired, matching create GUID
    /// (v2) and owned by the same principal. On any failure the handle is left intact (re-added when it
    /// was claimed) and <paramref name="error"/> carries the status to return.
    /// </summary>
    private bool TryClaimForReconnect(
        Smb2Header header, SmbSession session, ulong persistentId, ulong volatileId, Guid? expectedGuid,
        out DurableHandle dh, out ResponseSegment error)
    {
        error = default;
        if (!_server.Options.DurableHandleStore.TryClaim(persistentId, volatileId, out dh))
        {
            error = BuildError(header, NtStatus.ObjectNameNotFound); // unknown or already scavenged
            return false;
        }

        // Expired but not yet scavenged → release it now and report as gone.
        if (!dh.IsPersistent && dh.Deadline <= _server.Options.TimeProvider.GetUtcNow())
        {
            ReleaseDurable(dh);
            error = BuildError(header, NtStatus.ObjectNameNotFound);
            return false;
        }

        // A v2 reconnect must present the create GUID the handle was granted with (§3.3.5.9.12).
        if (expectedGuid is { } guid && dh.CreateGuid != guid)
        {
            _server.Options.DurableHandleStore.Add(dh);
            error = BuildError(header, NtStatus.ObjectNameNotFound);
            return false;
        }

        // The reconnect must come from the same principal; otherwise keep the handle and refuse.
        if (!string.Equals(dh.OwnerKey, OwnerKey(session.Identity), StringComparison.Ordinal))
        {
            _server.Options.DurableHandleStore.Add(dh);
            error = BuildError(header, NtStatus.AccessDenied);
            return false;
        }
        return true;
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
