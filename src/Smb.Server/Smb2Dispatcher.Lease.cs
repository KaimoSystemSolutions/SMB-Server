using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Leases;
using Smb.Server.Oplocks;
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
/// [W1] Like the classic path, a lease break that costs the holder write or handle caching is
/// <b>waited on</b>: the conflicting CREATE parks until the acknowledgment arrives (§3.3.5.9.8). The one
/// deliberate exception is <see cref="BreakParentDirectoryLease"/> — a directory lease broken because a
/// child entry changed is a cache-invalidation hint about a <i>different</i> file than the one being
/// created, so the creating client has nothing to gain from waiting for it and Windows does not expect it
/// to (§3.3.4.18). Those breaks stay fire-and-forget.
/// </para>
/// </summary>
public sealed partial class Smb2Dispatcher
{
    /// <summary>
    /// [W1] Registers the acknowledgment-required breaks among <paramref name="breaks"/> with the break
    /// tracker and mirrors the new state onto the holders, without sending them yet (the CREATE's interim
    /// must go out first — see <c>Smb2Dispatcher.Oplock.cs</c>). <paramref name="track"/> = <c>false</c>
    /// arms breaks nobody waits on.
    /// </summary>
    private ArmedBreaks ArmLeaseBreaks(IReadOnlyList<LeaseBreak> breaks, bool track)
    {
        if (breaks.Count == 0) return ArmedBreaks.None;

        List<Task<BreakOutcome>>? waits = null;
        foreach (LeaseBreak brk in breaks)
        {
            brk.Holder.LeaseState = brk.ToState;   // diagnostic mirror; the manager's state is authoritative.
            if (track && LeaseAckRequired(brk) && _breaks is { } tracker)
                (waits ??= []).Add(tracker.RegisterLeaseBreak(brk.Key));
        }

        return new ArmedBreaks([], breaks, waits is null ? null : Task.WhenAll(waits));
    }

    /// <summary>
    /// §2.2.23.2: the holder must acknowledge a lease break only when it loses write or handle caching —
    /// it then has dirty data to flush / handles to close, and the conflicting access waits for that. A
    /// downgrade that only removes read caching leaves the holder nothing to do; the notification goes out
    /// without SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED and nobody waits for a reply that never comes.
    /// <para>Single source of truth on purpose: <see cref="SendLeaseBreakAsync"/> sets the wire flag from
    /// this same predicate, so "we told the client to acknowledge" and "we are waiting for an
    /// acknowledgment" cannot drift apart.</para>
    /// </summary>
    private static bool LeaseAckRequired(LeaseBreak brk)
        => (brk.FromState & ~brk.ToState & (LeaseState.Write | LeaseState.Handle)) != 0;

    /// <summary>
    /// Dispatches lease breaks that nobody waits on (fire-and-forget), mirroring the holder state as usual.
    /// </summary>
    private void DispatchLeaseBreaks(IReadOnlyList<LeaseBreak> breaks)
        => _ = SendArmedBreaksAsync(ArmLeaseBreaks(breaks, track: false));

    /// <summary>
    /// After a child entry was added, removed or renamed inside a directory, breaks any directory
    /// lease held on that <i>parent</i> directory (directory leasing, §2.2.13.2.10) and dispatches the
    /// notifications. <paramref name="childPhysicalPath"/> is the backend path of the affected child;
    /// its parent directory is derived from it. No-op when the path has no parent or no directory lease
    /// is held there. Never waited on — see the class summary.
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

        byte[] body = LeaseBreakMessage.BuildNotificationBody(
            brk.Key, brk.FromState, brk.ToState, brk.Epoch, LeaseAckRequired(brk));

        // Failover (M6.3): send on a surviving channel, preferring the session's primary connection.
        await SendOutOfBandAsync(session, session.Connection, MaybeSigned(session, h, body),
            ResponseNeedsEncryption(session, open)).ConfigureAwait(false);
    }

    /// <summary>
    /// Processes a LEASE_BREAK acknowledgment from the client (§2.2.24.2/§3.3.5.22.2): the holder
    /// confirms the downgrade of the lease (identified by its <see cref="LeaseKey"/>, not a FileId).
    /// The server downgrades in the manager, releases any CREATE parked behind this break (W1.1) and
    /// answers with a LEASE_BREAK response (§2.2.25.2).
    /// </summary>
    private ResponseSegment HandleLeaseBreakAck(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        LeaseBreakMessage.Acknowledgment ack = LeaseBreakMessage.ParseAcknowledgment(segment, Smb2Header.Size);

        LeaseState newState = _server.Options.LeaseManager.Acknowledge(ack.Key, ack.State);

        // [W1.1] Release the CREATE parked behind this break — the holder has flushed. A no-op when nobody
        // is waiting (see the classic path for the late-acknowledgment case).
        _breaks?.CompleteLeaseBreak(ack.Key);

        byte[] body = LeaseBreakMessage.BuildResponseBody(ack.Key, newState);
        return MaybeSigned(session, RespHeader(header, session), body);
    }
}
