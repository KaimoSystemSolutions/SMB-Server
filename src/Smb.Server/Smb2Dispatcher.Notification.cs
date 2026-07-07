using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Notification;
using Smb.Server.State;

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
        // each CHANGE_NOTIFY subscription holds a PendingRequest and possibly a filesystem watcher.
        // See docs/SECURITY_AUDIT.md (Finding H1).
        if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests)
            return BuildError(header, NtStatus.InsufficientResources);

        ulong asyncId = connection.AllocateAsyncId();
        var pending = new PendingAsyncRequest { MessageId = header.MessageId, AsyncId = asyncId, Owner = open };
        var once = new NotifyOnce();

        void Complete(NtStatus status, byte[] body)
        {
            if (!once.TryFire()) return;
            connection.PendingRequests.TryRemove(pending.MessageId, out _);
            _ = SendAsyncFinalAsync(connection, header, session, asyncId, status, body, ResponseNeedsEncryption(session, open));
        }

        IDisposable? subscription;
        try
        {
            subscription = _server.Options.DirectoryWatcher.Watch(
                watchPath, req.WatchTree, (ChangeNotifyFilter)req.CompletionFilter,
                changes =>
                {
                    var list = new List<(uint, string)>(changes.Count);
                    foreach (FileNotifyEvent c in changes)
                        list.Add(((uint)c.Action, c.RelativeName));
                    (byte[] body, bool overflow) = ChangeNotifyMessage.BuildResponseBody(list, req.OutputBufferLength);
                    Complete(overflow ? NtStatus.NotifyEnumDir : NtStatus.Success, body);
                });
        }
        catch
        {
            return BuildError(header, NtStatus.NotSupported);
        }

        if (subscription is null)
            return BuildError(header, NtStatus.NotSupported); // watcher cannot watch this path

        once.Attach(subscription);                 // race-safe: if an event already fired, disposed immediately here
        connection.PendingRequests[header.MessageId] = pending;
        pending.Token.Register(() => Complete(NtStatus.Cancelled, ErrorResponse.BuildBody()));

        // Note: theoretically a change can arrive in the µs window between Watch() and sending
        // this interim response; in practice filesystem watchers deliver events ms later.
        // Correct buffering of changes between two requests remains an open issue.
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

        // Success/info is signed (if the session signs); errors remain unsigned — as usual.
        ResponseSegment seg = status.IsSuccess()
            ? MaybeSigned(session, h, body)
            : ResponseSegment.Unsigned(h, body);

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
