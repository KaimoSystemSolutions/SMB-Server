using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Notification;
using Smb.Server.State;
using Smb.Server.Witness;

namespace Smb.Server;

/// <summary>
/// CHANGE_NOTIFY (Context §16, MS-SMB2 §3.3.5.19): watches a directory handle for
/// changes. Like a blocking LOCK, an interim response (<c>STATUS_PENDING</c>) is sent
/// first; the final response with FILE_NOTIFY_INFORMATION follows out-of-band once a
/// change occurs — or <c>STATUS_CANCELLED</c> on CANCEL/Close.
/// </summary>
public sealed partial class Smb2Dispatcher
{
    private ResponseSegment HandleChangeNotify(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        ChangeNotifyMessage.Request req = ChangeNotifyMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);
        if (open.LocalOpen is null || !open.LocalOpen.IsDirectory)
            return BuildError(header, NtStatus.InvalidParameter); // CHANGE_NOTIFY only on directory handles

        string? watchPath = open.LocalOpen.PhysicalPath;
        if (watchPath is null)
            return BuildError(header, NtStatus.NotSupported); // backend without a real path (e.g. virtual)

        // [AUDIT-2026-06] Cap outstanding async operations per connection (resource protection):
        // each parked CHANGE_NOTIFY holds a PendingRequest; the watch itself is per-open (W3.1), so a
        // re-registering client no longer churns a fresh watcher per request. See docs/SECURITY_AUDIT.md (H1).
        if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests)
            return BuildError(header, NtStatus.InsufficientResources);

        // [W3.1] The watch lives on the open, not on this request: established on the first CHANGE_NOTIFY,
        // reused (or restarted on a filter change) afterwards, torn down at CLOSE. Changes between two
        // requests are buffered by the registration instead of being lost.
        ChangeNotifyRegistration registration =
            open.ChangeNotify ??= new ChangeNotifyRegistration(_server.Options.ChangeNotifyBufferLimit);

        ulong asyncId = connection.AllocateAsyncId();
        bool encrypt = ResponseNeedsEncryption(session, open);

        Task Send(NtStatus status, byte[] body)
        {
            connection.PendingRequests.TryRemove(header.MessageId, out _);
            return SendAsyncFinalAsync(connection, header, session, asyncId, status, body, encrypt);
        }

        // Register the pending entry *before* handing the send callback to the registration: if a change
        // fires the moment the request parks, Send runs on the watcher thread and must find the entry to
        // remove. If the request is not parked (immediate answer below) it is removed again.
        var pending = new PendingAsyncRequest { MessageId = header.MessageId, AsyncId = asyncId, Owner = open };
        connection.PendingRequests[header.MessageId] = pending;

        ChangeNotifyRegistration.RequestOutcome outcome = registration.HandleRequest(
            watchPath, (ChangeNotifyFilter)req.CompletionFilter, req.WatchTree, req.OutputBufferLength,
            header.MessageId, _server.Options.DirectoryWatcher, Send);

        if (outcome.Disposition != ChangeNotifyRegistration.Disposition.Park)
            connection.PendingRequests.TryRemove(header.MessageId, out _);

        switch (outcome.Disposition)
        {
            case ChangeNotifyRegistration.Disposition.WatcherUnavailable:
                return BuildError(header, NtStatus.NotSupported); // watcher cannot watch this path

            case ChangeNotifyRegistration.Disposition.Immediate:
            {
                // Buffered changes (or a latched overflow) were available → answer in-band, no async round trip.
                Smb2Header h = header.CreateResponse(outcome.Status);
                h.SessionId = session.SessionId;
                h.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
                return MaybeSigned(session, h, outcome.Body);
            }

            default: // Park
                pending.Token.Register(() => registration.TryCancel(header.MessageId));
                return InterimResponse(header, session, asyncId);
        }
    }

    /// <summary>
    /// [C1.3] Begins a witness <c>WitnessrAsyncNotify</c> as a long-pending async op: sends the
    /// <c>STATUS_PENDING</c> interim now and arms the registration's notification channel. When a failover
    /// notification is queued (server trigger, C1.4) the final response is sent out-of-band as an IOCTL
    /// (FSCTL_PIPE_TRANSCEIVE) response carrying the RESP_ASYNC_NOTIFY PDU; CANCEL/CLOSE/teardown completes
    /// it with <c>STATUS_CANCELLED</c>. Mirrors the CHANGE_NOTIFY mechanism (shared <see cref="NotifyOnce"/>).
    /// </summary>
    private ResponseSegment BeginWitnessAsyncNotify(
        SmbConnection connection, Smb2Header header, SmbSession session, SmbOpen open,
        WitnessRegistration registration, uint callId, ulong persistentId, ulong volatileId)
    {
        // Cap outstanding async operations per connection (resource protection), as CHANGE_NOTIFY does.
        if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests)
            return BuildError(header, NtStatus.InsufficientResources);

        ulong asyncId = connection.AllocateAsyncId();
        var pending = new PendingAsyncRequest { MessageId = header.MessageId, AsyncId = asyncId, Owner = open };
        var once = new NotifyOnce();
        bool encrypt = ResponseNeedsEncryption(session, open);

        void Complete(NtStatus status, byte[] body)
        {
            if (!once.TryFire()) return;
            connection.PendingRequests.TryRemove(pending.MessageId, out _);
            _ = SendAsyncFinalAsync(connection, header, session, asyncId, status, body, encrypt);
        }

        IDisposable subscription = registration.Notifications.Wait(n =>
        {
            byte[] pdu = WitnessEndpoint.BuildAsyncNotifyPdu(callId, n);
            byte[] ioctlBody = IoctlMessage.BuildResponseBody(IoctlMessage.FsctlPipeTransceive, persistentId, volatileId, pdu);
            Complete(NtStatus.Success, ioctlBody);
        });

        once.Attach(subscription);                 // if a buffered notification already fired, disposed here
        connection.PendingRequests[header.MessageId] = pending;
        pending.Token.Register(() => Complete(NtStatus.Cancelled, ErrorResponse.BuildBody()));

        return InterimResponse(header, session, asyncId);
    }

    /// <summary>Sends the final response for an asynchronously pending operation out-of-band (ASYNC header).</summary>
    private async Task SendAsyncFinalAsync(
        SmbConnection connection, Smb2Header request, SmbSession session, ulong asyncId, NtStatus status, byte[] body, bool encrypt)
    {
        Smb2Header h = request.CreateResponse(status);
        h.Flags |= Smb2HeaderFlags.AsyncCommand;
        h.AsyncId = asyncId;
        h.SessionId = session.SessionId;
        h.CreditRequestResponse = 0; // Credits were granted with the interim response.

        // §3.3.4.1.1: the response to a signed request is signed — including error statuses. This path used
        // to leave errors unsigned, which is exactly the F1 failure mode one path over: a Windows client
        // *discards* a response whose signature does not verify on a signed session (§3.2.5.1.3) instead of
        // failing the call, so an unsigned STATUS_CANCELLED left the client waiting out its own timeout for a
        // CHANGE_NOTIFY it had itself cancelled. The in-band paths get this from SignIfRequestWasSigned;
        // out-of-band finals have to do it here, because nothing assembles them centrally.
        ResponseSegment seg = SignedLikeRequest(session, request, h, body);

        // Failover (M6.3): deliver on a surviving channel if the originating one dropped.
        await SendOutOfBandAsync(session, connection, seg, encrypt).ConfigureAwait(false);
    }

    /// <summary>
    /// One-shot guard for an asynchronous watch: ensures exactly one of
    /// "change occurred" and "cancelled" wins, and disposes the watcher handle
    /// race-safely (even if an event fires before the handle is attached).
    /// </summary>
    private sealed class NotifyOnce
    {
        private readonly object _gate = new();
        private int _fired;
        private IDisposable? _subscription;
        private bool _disposeRequested;

        public bool TryFire()
        {
            if (Interlocked.Exchange(ref _fired, 1) != 0) return false;
            lock (_gate)
            {
                _disposeRequested = true;
                _subscription?.Dispose();
                _subscription = null;
            }
            return true;
        }

        public void Attach(IDisposable? subscription)
        {
            lock (_gate)
            {
                if (_disposeRequested) { subscription?.Dispose(); return; }
                _subscription = subscription;
            }
        }
    }
}
