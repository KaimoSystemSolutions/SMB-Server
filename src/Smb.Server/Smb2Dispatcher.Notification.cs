using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Notification;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// CHANGE_NOTIFY (Context §16, MS-SMB2 §3.3.5.19): überwacht ein Verzeichnis-Handle auf
/// Änderungen. Wie beim blockierenden LOCK geht zuerst eine Interim-Antwort
/// (<c>STATUS_PENDING</c>) raus; die finale Antwort mit FILE_NOTIFY_INFORMATION folgt out-of-band,
/// sobald eine Änderung eintritt — oder <c>STATUS_CANCELLED</c> bei CANCEL/Close.
/// </summary>
public sealed partial class Smb2Dispatcher
{
    private ResponseSegment HandleChangeNotify(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        ChangeNotifyMessage.Request req = ChangeNotifyMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);
        if (open.LocalOpen is null || !open.LocalOpen.IsDirectory)
            return BuildError(header, NtStatus.InvalidParameter); // CHANGE_NOTIFY nur auf Verzeichnis-Handles

        string? watchPath = open.LocalOpen.PhysicalPath;
        if (watchPath is null)
            return BuildError(header, NtStatus.NotSupported); // Backend ohne realen Pfad (z.B. virtuell)

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
            return BuildError(header, NtStatus.NotSupported); // Watcher kann diesen Pfad nicht überwachen

        once.Attach(subscription);                 // race-sicher: feuerte schon ein Event, wird hier sofort entsorgt
        connection.PendingRequests[header.MessageId] = pending;
        pending.Token.Register(() => Complete(NtStatus.Cancelled, ErrorResponse.BuildBody()));

        // Hinweis: theoretisch kann eine Änderung im µs-Fenster zwischen Watch() und dem Versand
        // dieser Interim-Antwort eintreffen; in der Praxis liefern Dateisystem-Watcher Events erst
        // ms später. Eine korrekte Pufferung von Änderungen zwischen zwei Requests bleibt offen.
        return InterimResponse(header, session, asyncId);
    }

    /// <summary>Sendet eine finale Antwort einer asynchron ausstehenden Operation out-of-band (ASYNC-Header).</summary>
    private async Task SendAsyncFinalAsync(
        SmbConnection connection, Smb2Header request, SmbSession session, ulong asyncId, NtStatus status, byte[] body, bool encrypt)
    {
        Smb2Header h = request.CreateResponse(status);
        h.Flags |= Smb2HeaderFlags.AsyncCommand;
        h.AsyncId = asyncId;
        h.SessionId = session.SessionId;
        h.CreditRequestResponse = 0; // Credits wurden mit der Interim-Antwort gewährt.

        // Erfolg/Info wird signiert (falls die Session signiert), Fehler bleiben unsigniert — wie sonst.
        ResponseSegment seg = status.IsSuccess()
            ? MaybeSigned(session, h, body)
            : ResponseSegment.Unsigned(h, body);

        byte[] bytes = AssembleResponse([seg]);
        Func<byte[], bool, Task>? sender = connection.SendRawAsync;
        if (sender is null) return;
        try { await sender(bytes, encrypt).ConfigureAwait(false); }
        catch { /* Connection bereits weg */ }
    }

    /// <summary>
    /// One-shot-Wächter für eine asynchrone Überwachung: stellt sicher, dass genau einer von
    /// „Änderung eingetreten" und „abgebrochen" gewinnt, und entsorgt das Watcher-Handle
    /// race-sicher (auch wenn das Event feuert, bevor das Handle angehängt wurde).
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
