using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Locking;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// Byte-Range-Locking (Context §15, MS-SMB2 §2.2.26/§3.3.5.14) und CANCEL (§3.3.5.16).
/// Nicht sofort gewährbare Locks ohne <c>FAIL_IMMEDIATELY</c> werden <b>asynchron</b> bedient:
/// Es geht zuerst eine Interim-Antwort (<c>STATUS_PENDING</c>, ASYNC-Header) raus; die finale
/// Antwort folgt out-of-band über <see cref="SmbConnection.SendRawAsync"/>, sobald der Bereich
/// frei wird oder die Operation per CANCEL/Close abgebrochen wird.
/// </summary>
public sealed partial class Smb2Dispatcher
{
    private ResponseSegment HandleLock(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        LockMessage.Request req = LockMessage.ParseRequest(segment, Smb2Header.Size);
        if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);

        // Elemente normalisieren: alle Unlock ODER alle Lock (MS-SMB2 §3.3.5.14.2), sonst INVALID_PARAMETER.
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

        // AsyncId + Pending-Eintrag vorbereiten; dessen Token steuert ein evtl. Blockieren.
        ulong asyncId = connection.AllocateAsyncId();
        var pending = new PendingAsyncRequest { MessageId = header.MessageId, AsyncId = asyncId, Owner = open };

        Task<LockOutcome> task = _server.Options.LockManager.ApplyAsync(open, elements, failImmediately, pending.Token);

        if (task.IsCompleted)
        {
            // Synchron entschieden → normale Antwort, kein async-Pfad nötig.
            pending.Cancel();
            LockOutcome outcome = task.IsCompletedSuccessfully ? task.Result : LockOutcome.Conflict;
            return LockResultSegment(header, session, outcome);
        }

        // [AUDIT-2026-06] Ausstehende async-Operationen je Verbindung deckeln (Ressourcen-Schutz):
        // sonst kann ein Client unbegrenzt blockierende LOCKs offenhalten. Siehe SECURITY_AUDIT (H1).
        if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests)
        {
            pending.Cancel(); // bricht den eben gestarteten Waiter ab
            return BuildError(header, NtStatus.InsufficientResources);
        }

        // Blockierend: Interim-Antwort jetzt, finale Antwort folgt out-of-band.
        connection.PendingRequests[header.MessageId] = pending;
        _ = SendFinalLockResponseAsync(connection, header, session, asyncId, task, pending);
        return InterimResponse(header, session, asyncId);
    }

    private ResponseSegment? HandleCancel(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        CancelMessage.ParseRequest(segment, Smb2Header.Size);
        // CANCEL referenziert die ausstehende Operation über die MessageId und trägt selbst keine
        // Antwort (§3.3.5.16). Die abgebrochene Operation sendet ihrerseits STATUS_CANCELLED.
        if (connection.PendingRequests.TryGetValue(header.MessageId, out PendingAsyncRequest? pending))
            pending.Cancel();
        return null;
    }

    /// <summary>Mappt ein synchron entschiedenes <see cref="LockOutcome"/> auf die Antwort.</summary>
    private ResponseSegment LockResultSegment(Smb2Header header, SmbSession session, LockOutcome outcome) => outcome switch
    {
        LockOutcome.Granted => MaybeSigned(session, RespHeader(header, session), LockMessage.BuildResponseBody()),
        LockOutcome.RangeNotLocked => BuildError(header, NtStatus.RangeNotLocked),
        LockOutcome.Cancelled => BuildError(header, NtStatus.Cancelled),
        _ => BuildError(header, NtStatus.LockNotGranted),
    };

    /// <summary>Interim-Antwort eines blockierenden LOCK: ASYNC-Header, STATUS_PENDING, unsigniert (§3.3.4.1.1).</summary>
    private ResponseSegment InterimResponse(Smb2Header header, SmbSession session, ulong asyncId)
    {
        Smb2Header h = header.CreateResponse(NtStatus.Pending);
        h.Flags |= Smb2HeaderFlags.AsyncCommand;
        h.AsyncId = asyncId;
        h.SessionId = session.SessionId;
        h.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        return ResponseSegment.Unsigned(h, ErrorResponse.BuildBody());
    }

    /// <summary>Wartet auf das Ergebnis eines blockierenden LOCK und sendet die finale Antwort out-of-band.</summary>
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
        h.CreditRequestResponse = 0; // Credits wurden bereits mit der Interim-Antwort gewährt.

        // Die finale Antwort wird (anders als die Interim-Antwort) signiert, falls die Session signiert.
        ResponseSegment seg = outcome == LockOutcome.Granted
            ? MaybeSigned(session, h, LockMessage.BuildResponseBody())
            : ResponseSegment.Unsigned(h, ErrorResponse.BuildBody());

        byte[] bytes = AssembleResponse([seg]);

        Func<byte[], bool, Task>? sender = connection.SendRawAsync;
        if (sender is null) return;
        try { await sender(bytes, ResponseNeedsEncryption(session, pending.Owner)).ConfigureAwait(false); }
        catch { /* Connection bereits weg — nichts zu tun */ }
    }

    /// <summary>Gibt beim CLOSE alle Locks des Open frei und bricht dessen wartende (blockierende) Locks ab.</summary>
    private void ReleaseLocks(SmbConnection connection, SmbOpen open)
    {
        _server.Options.LockManager.ReleaseOwner(open);
        foreach (KeyValuePair<ulong, PendingAsyncRequest> kv in connection.PendingRequests)
            if (ReferenceEquals(kv.Value.Owner, open))
                kv.Value.Cancel();
    }
}
