using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Locking;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// Byte-range locking (Context §15, MS-SMB2 §2.2.26/§3.3.5.14) and CANCEL (§3.3.5.16).
/// Locks that cannot be granted immediately without <c>FAIL_IMMEDIATELY</c> are served
/// <b>asynchronously</b>: an interim response (<c>STATUS_PENDING</c>, ASYNC header) is sent
/// first; the final response follows out-of-band via <see cref="SmbConnection.SendRawAsync"/>
/// once the range becomes free or the operation is cancelled via CANCEL/Close.
/// </summary>
public sealed partial class Smb2Dispatcher
{
    private ResponseSegment HandleLock(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        LockMessage.Request req = LockMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);

        // Normalize elements: all unlocks OR all locks (MS-SMB2 §3.3.5.14.2), otherwise INVALID_PARAMETER.
        bool firstUnlock = req.Locks[0].IsUnlock;
        var elements = new LockElement[req.Locks.Count];
        for (int i = 0; i < req.Locks.Count; i++)
        {
            LockEntry e = req.Locks[i];
            if (e.IsUnlock != firstUnlock)
                return BuildError(header, NtStatus.InvalidParameter);
            elements[i] = new LockElement(e.Offset, e.Length, e.IsExclusive, e.IsUnlock);
        }

        bool failImmediately = req.Locks[0].FailImmediately;

        // Prepare AsyncId + pending entry; its token controls any potential blocking.
        ulong asyncId = connection.AllocateAsyncId();
        var pending = new PendingAsyncRequest { MessageId = header.MessageId, AsyncId = asyncId, Owner = open };

        Task<LockOutcome> task = _server.Options.LockManager.ApplyAsync(open, elements, failImmediately, pending.Token);

        if (task.IsCompleted)
        {
            // Decided synchronously → normal response, no async path needed.
            pending.Cancel();
            LockOutcome outcome = task.IsCompletedSuccessfully ? task.Result : LockOutcome.Conflict;
            return LockResultSegment(header, session, outcome);
        }

        // [AUDIT-2026-06] Cap outstanding async operations per connection (resource protection):
        // otherwise a client can keep unlimited blocking LOCKs open. See SECURITY_AUDIT (H1).
        if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests)
        {
            pending.Cancel(); // cancels the waiter that was just started
            return BuildError(header, NtStatus.InsufficientResources);
        }

        // Blocking: interim response now, final response follows out-of-band.
        connection.PendingRequests[header.MessageId] = pending;
        _ = SendFinalLockResponseAsync(connection, header, session, asyncId, task, pending);
        return InterimResponse(header, session, asyncId);
    }

    private ResponseSegment? HandleCancel(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        CancelMessage.ParseRequest(segment, Smb2Header.Size);

        // §3.3.5.16: how the target is identified depends on SMB2_FLAGS_ASYNC_COMMAND. An async CANCEL — the
        // only kind that can cancel an operation we already parked with a STATUS_PENDING interim — names its
        // target by AsyncId; only a sync CANCEL names it by MessageId. Matching on MessageId alone missed
        // every async CANCEL (Windows does not put the original MessageId in that field), so the pending
        // operation was never completed. For a CHANGE_NOTIFY parked on a directory handle that is a real
        // freeze: the client waits out its own ~65 s timeout, which is what closing an Explorer window on the
        // share cost. CANCEL carries no response either way — the cancelled op sends STATUS_CANCELLED itself.
        PendingAsyncRequest? pending = header.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand)
            ? FindPendingByAsyncId(connection, header.AsyncId)
            : connection.PendingRequests.TryGetValue(header.MessageId, out PendingAsyncRequest? byMid) ? byMid : null;

        pending?.Cancel();
        return null;
    }

    /// <summary>
    /// Finds a parked operation by the AsyncId handed out with its interim response. PendingRequests is keyed
    /// by MessageId (that is what CLOSE/teardown look up), so an async CANCEL scans instead — the collection
    /// holds only a connection's in-flight async ops, bounded by <see cref="SmbServerOptions.MaxOutstandingRequests"/>.
    /// </summary>
    private static PendingAsyncRequest? FindPendingByAsyncId(SmbConnection connection, ulong asyncId)
    {
        foreach (PendingAsyncRequest pending in connection.PendingRequests.Values)
            if (pending.AsyncId == asyncId)
                return pending;
        return null;
    }

    /// <summary>Maps a synchronously decided <see cref="LockOutcome"/> to the response segment.</summary>
    private ResponseSegment LockResultSegment(Smb2Header header, SmbSession session, LockOutcome outcome) => outcome switch
    {
        LockOutcome.Granted => MaybeSigned(session, RespHeader(header, session), LockMessage.BuildResponseBody()),
        LockOutcome.RangeNotLocked => BuildError(header, NtStatus.RangeNotLocked),
        LockOutcome.Cancelled => BuildError(header, NtStatus.Cancelled),
        _ => BuildError(header, NtStatus.LockNotGranted),
    };

    /// <summary>Interim response for a blocking LOCK: ASYNC header, STATUS_PENDING, unsigned (§3.3.4.1.1).</summary>
    private ResponseSegment InterimResponse(Smb2Header header, SmbSession session, ulong asyncId)
    {
        Smb2Header h = header.CreateResponse(NtStatus.Pending);
        h.Flags |= Smb2HeaderFlags.AsyncCommand;
        h.AsyncId = asyncId;
        h.SessionId = session.SessionId;
        h.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        return ResponseSegment.Unsigned(h, ErrorResponse.BuildBody());
    }

    /// <summary>Waits for the result of a blocking LOCK and sends the final response out-of-band.</summary>
    private async Task SendFinalLockResponseAsync(
        SmbConnection connection, Smb2Header header, SmbSession session, ulong asyncId,
        Task<LockOutcome> task, PendingAsyncRequest pending)
    {
        LockOutcome outcome;
        try { outcome = await task.ConfigureAwait(false); }
        catch { outcome = LockOutcome.Cancelled; }

        connection.PendingRequests.TryRemove(pending.MessageId, out _);

        NtStatus status = outcome switch
        {
            LockOutcome.Granted => NtStatus.Success,
            LockOutcome.RangeNotLocked => NtStatus.RangeNotLocked,
            LockOutcome.Cancelled => NtStatus.Cancelled,
            _ => NtStatus.LockNotGranted,
        };

        Smb2Header h = header.CreateResponse(status);
        h.Flags |= Smb2HeaderFlags.AsyncCommand;
        h.AsyncId = asyncId;
        h.SessionId = session.SessionId;
        h.CreditRequestResponse = 0; // Credits were already granted with the interim response.

        // The final response is signed (unlike the interim), and — since the F1 lesson — that includes the
        // failing statuses: a client that gets an unsigned STATUS_LOCK_NOT_GRANTED on a signed session
        // discards it (§3.2.5.1.3) and waits out its own timeout instead of seeing the refusal.
        ResponseSegment seg = SignedLikeRequest(session, header, h,
            outcome == LockOutcome.Granted ? LockMessage.BuildResponseBody() : ErrorResponse.BuildBody());

        // Failover (M6.3): if the originating channel dropped while the lock was blocked, deliver the
        // final response on a surviving channel of the session instead.
        await SendOutOfBandAsync(session, connection, seg, ResponseNeedsEncryption(session, pending.Owner)).ConfigureAwait(false);
    }

    /// <summary>At CLOSE, releases all locks of the open and cancels its pending (blocking) locks.</summary>
    private void ReleaseLocks(SmbConnection connection, SmbOpen open)
    {
        _server.Options.LockManager.ReleaseOwner(open);
        foreach (KeyValuePair<ulong, PendingAsyncRequest> kv in connection.PendingRequests)
            if (ReferenceEquals(kv.Value.Owner, open))
                kv.Value.Cancel();
    }
}
