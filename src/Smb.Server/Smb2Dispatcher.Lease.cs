using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Leases;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// Lease breaks (Context §15, MS-SMB2 §2.2.23.2/§2.2.24.2/§2.2.25.2, §3.3.4.7/§3.3.5.22.2). Leases
/// replace classic oplocks on modern clients (see <c>Smb2Dispatcher.Oplock.cs</c> for the
/// classic path). At CREATE a lease is granted via <see cref="ILeaseManager"/> (see
/// <c>HandleCreateAsync</c>); when another open conflicts, the current holder is sent a
/// LEASE_BREAK_NOTIFICATION (out-of-band, MessageId <c>0xFFFFFFFFFFFFFFFF</c>), which it confirms
/// with a LEASE_BREAK_ACKNOWLEDGMENT — handled here.
/// <para>
/// Same intentional simplification as the classic oplock path: the conflicting access does
/// <i>not</i> block waiting for the acknowledgment (the holder is downgraded in the manager
/// immediately). The acknowledgment is still processed and answered so the client's state machine
/// completes cleanly. Blocking break-before-grant (§3.3.5.9.8) is deferred to a later pass.
/// </para>
/// </summary>
public sealed partial class Smb2Dispatcher
{
    /// <summary>
    /// Dispatches the pending lease breaks (from <see cref="ILeaseManager.RequestLease"/>) to their
    /// holders. Like an oplock break the notification travels over the <i>holder's</i> connection —
    /// leases are file-wide and cross-connection.
    /// </summary>
    private void DispatchLeaseBreaks(IReadOnlyList<LeaseBreak> breaks)
    {
        foreach (LeaseBreak brk in breaks)
        {
            brk.Holder.LeaseState = brk.ToState;   // diagnostic mirror; the manager's state is authoritative.
            _ = SendLeaseBreakAsync(brk);
        }
    }

    /// <summary>
    /// After a child entry was added, removed or renamed inside a directory, breaks any directory
    /// lease held on that <i>parent</i> directory (directory leasing, §2.2.13.2.10) and dispatches the
    /// notifications. <paramref name="childPhysicalPath"/> is the backend path of the affected child;
    /// its parent directory is derived from it. No-op when the path has no parent or no directory lease
    /// is held there.
    /// </summary>
    private void BreakParentDirectoryLease(string? childPhysicalPath)
    {
        if (string.IsNullOrEmpty(childPhysicalPath)) return;
        string? parent = System.IO.Path.GetDirectoryName(childPhysicalPath);
        if (string.IsNullOrEmpty(parent)) return;

        IReadOnlyList<LeaseBreak> breaks = _server.Options.LeaseManager.BreakDirectoryLease(parent);
        if (breaks.Count != 0) DispatchLeaseBreaks(breaks);
    }

    /// <summary>Sends the LEASE_BREAK notification to a holder out-of-band (§2.2.23.2).</summary>
    private async Task SendLeaseBreakAsync(LeaseBreak brk)
    {
        SmbOpen open = brk.Holder;
        SmbSession session = open.Session;
        SmbConnection connection = session.Connection;

        var h = new Smb2Header
        {
            Command = SmbCommand.OplockBreak,
            MessageId = UnsolicitedMessageId,
            Flags = Smb2HeaderFlags.ServerToRedir,
            Status = NtStatus.Success,
            SessionId = session.SessionId,
            TreeId = (uint)open.TreeConnect.TreeId,
            CreditRequestResponse = 0,
        };

        // Losing write or handle caching requires the client to flush/close first → it must
        // acknowledge. A pure read-caching downgrade could be sent without ack, but requesting one
        // keeps the exchange symmetric with what the InMemoryLeaseManager expects.
        bool ackRequired = (brk.FromState & ~brk.ToState & (LeaseState.Write | LeaseState.Handle)) != 0;
        byte[] body = LeaseBreakMessage.BuildNotificationBody(brk.Key, brk.FromState, brk.ToState, brk.Epoch, ackRequired);
        byte[] bytes = AssembleResponse([MaybeSigned(session, h, body)]);

        Func<byte[], bool, Task>? sender = connection.SendRawAsync;
        if (sender is null) return;
        try { await sender(bytes, ResponseNeedsEncryption(session, open)).ConfigureAwait(false); }
        catch { /* connection already gone — nothing to do */ }
    }

    /// <summary>
    /// Processes a LEASE_BREAK acknowledgment from the client (§2.2.24.2/§3.3.5.22.2): the holder
    /// confirms the downgrade of the lease (identified by its <see cref="LeaseKey"/>, not a FileId).
    /// The server downgrades in the manager and answers with a LEASE_BREAK response (§2.2.25.2).
    /// </summary>
    private ResponseSegment HandleLeaseBreakAck(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        LeaseBreakMessage.Acknowledgment ack = LeaseBreakMessage.ParseAcknowledgment(segment, Smb2Header.Size);

        LeaseState newState = _server.Options.LeaseManager.Acknowledge(ack.Key, ack.State);

        byte[] body = LeaseBreakMessage.BuildResponseBody(ack.Key, newState);
        return MaybeSigned(session, RespHeader(header, session), body);
    }
}
