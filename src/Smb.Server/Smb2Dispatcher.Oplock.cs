using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;
using Smb.Server.Leases;
using Smb.Server.Oplocks;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// Oplocks (Context §15, MS-SMB2 §3.3.4.6/§3.3.5.9/§3.3.5.22): at CREATE, an oplock level
/// is granted via <see cref="IOplockManager"/> (see HandleCreate). When another open accesses
/// the same file, the server sends the current holder an OPLOCK_BREAK notification
/// (out-of-band, MessageId <c>0xFFFFFFFFFFFFFFFF</c>); the holder confirms with an
/// OPLOCK_BREAK acknowledgment, which is handled here.
/// <para>
/// [W1] <b>Break-before-grant is implemented</b> (§3.3.5.9.8): a break that costs the holder its write
/// caching is <i>waited on</i> — the triggering CREATE is parked behind a STATUS_PENDING interim until the
/// holder acknowledges or <see cref="SmbServerOptions.OplockBreakTimeout"/> elapses. The pieces are split
/// across three steps on purpose, because their order is load-bearing: <see cref="ArmOplockBreaks"/>
/// registers the break with the <see cref="BreakWaitTracker"/>, the CREATE then sends its interim, and only
/// then does <see cref="SendArmedBreaksAsync"/> put the notification on the wire. Sending first would let a
/// fast holder acknowledge — and the final response go out — before the client has seen the AsyncId that
/// final is tagged with.
/// </para>
/// <para>
/// The lease equivalent (§2.2.23.2 ff.) lives in <c>Smb2Dispatcher.Lease.cs</c>; its acknowledgment
/// (StructureSize 36) is routed from <see cref="HandleOplockBreak"/>.
/// </para>
/// </summary>
public sealed partial class Smb2Dispatcher
{
    /// <summary>MessageId of an unsolicited server message (oplock break notification, §3.3.4.6).</summary>
    private const ulong UnsolicitedMessageId = 0xFFFFFFFFFFFFFFFF;

    /// <summary>
    /// [W1] Breaks that a CREATE triggered: registered with the break tracker and mirrored on their
    /// holders, but <b>not yet sent</b>. <see cref="Wait"/> is non-null exactly when at least one of them
    /// requires an acknowledgment — that is the signal for the CREATE to park (W1.1). Since a CREATE
    /// requests either a lease or a classic oplock, never both, only one of the two lists is ever populated.
    /// </summary>
    private readonly record struct ArmedBreaks(
        IReadOnlyList<OplockBreak> Oplocks,
        IReadOnlyList<LeaseBreak> Leases,
        Task<BreakOutcome[]>? Wait)
    {
        public static readonly ArmedBreaks None = new([], [], null);
    }

    /// <summary>
    /// [W1] Registers the acknowledgment-required breaks among <paramref name="breaks"/> with the break
    /// tracker and mirrors the new level onto the holders — without sending anything (see the class
    /// summary for why the send is a separate step). <paramref name="track"/> = <c>false</c> arms breaks
    /// nobody waits on, so they are sent but never parked behind.
    /// </summary>
    private ArmedBreaks ArmOplockBreaks(IReadOnlyList<OplockBreak> breaks, bool track)
    {
        if (breaks.Count == 0) return ArmedBreaks.None;

        List<Task<BreakOutcome>>? waits = null;
        foreach (OplockBreak brk in breaks)
        {
            // Read the holder's level BEFORE overwriting the mirror: the mirror tracks what the *client*
            // was granted, and the client decides whether to acknowledge based on exactly that.
            bool ackRequired = OplockAckRequired(brk.Holder.OplockLevel);
            brk.Holder.OplockLevel = brk.NewLevel;   // diagnostic mirror; the manager's state is authoritative.

            if (track && ackRequired && _breaks is { } tracker)
                (waits ??= []).Add(tracker.RegisterOplockBreak(brk.Holder));
        }

        return new ArmedBreaks(breaks, [], waits is null ? null : Task.WhenAll(waits));
    }

    /// <summary>
    /// §3.3.4.6/§2.2.23.1: a break away from Exclusive/Batch takes write caching (and, for Batch, handle
    /// caching) from the holder — it has dirty data to flush before the new opener may see the file, so it
    /// must acknowledge and the conflicting access waits for that. A LEVEL_II holder caches reads only:
    /// there is nothing to flush, it does not acknowledge a LEVEL_II→None break at all, and waiting for one
    /// would stall until the timeout for no benefit.
    /// </summary>
    private static bool OplockAckRequired(OplockLevel fromLevel)
        => fromLevel is OplockLevel.Exclusive or OplockLevel.Batch;

    /// <summary>
    /// Sends armed break notifications to their holders. The notification travels over the connection of
    /// the <i>holder</i> — not that of the triggering request, because oplocks/leases are file-wide
    /// (cross-connection). Awaiting the sends is what guarantees the notification is on the wire before the
    /// CREATE starts waiting for its acknowledgment.
    /// </summary>
    private async Task SendArmedBreaksAsync(ArmedBreaks armed)
    {
        foreach (OplockBreak brk in armed.Oplocks)
            await SendOplockBreakAsync(brk).ConfigureAwait(false);
        foreach (LeaseBreak brk in armed.Leases)
            await SendLeaseBreakAsync(brk).ConfigureAwait(false);
    }

    /// <summary>
    /// Dispatches breaks that nobody waits on (fire-and-forget), mirroring the holder state as usual.
    /// </summary>
    private void DispatchOplockBreaks(IReadOnlyList<OplockBreak> breaks)
        => _ = SendArmedBreaksAsync(ArmOplockBreaks(breaks, track: false));

    /// <summary>
    /// [M8.4] On graceful shutdown, notifies every caching holder to break to <c>None</c> before their
    /// handles are closed, so a client can flush cached writes (§3.3.7.1). Best-effort: sent out-of-band
    /// on a still-live channel; the drain window then gives the client time to react. Deliberately not
    /// tracked as a waited-on break (W1) — nothing is being granted here that coherency would depend on,
    /// and the drain window already bounds the wait.
    /// </summary>
    public async Task SendShutdownBreaksAsync()
    {
        var tasks = new List<Task>();
        foreach (SmbSession session in _server.SessionGlobalList.Values)
        {
            if (session.State != SessionState.Valid)
                continue;
            foreach (SmbOpen open in session.Opens.Values)
            {
                switch (open.OplockLevel)
                {
                    case OplockLevel.Exclusive:
                    case OplockLevel.Batch:
                    case OplockLevel.LevelII:
                        tasks.Add(SendOplockBreakAsync(new OplockBreak(open, OplockLevel.None)));
                        break;
                    case OplockLevel.Lease when open.LeaseState != LeaseState.None:
                        tasks.Add(SendLeaseBreakAsync(new LeaseBreak(
                            open.LeaseKey, open.LeaseState, LeaseState.None, (ushort)(open.LeaseEpoch + 1), open)));
                        break;
                }
            }
        }
        if (tasks.Count > 0)
            await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    /// <summary>Sends the OPLOCK_BREAK notification to a holder out-of-band (§2.2.23.1).</summary>
    private async Task SendOplockBreakAsync(OplockBreak brk)
    {
        SmbOpen open = brk.Holder;
        SmbSession session = open.Session;

        // §3.3.4.6: TreeId MUST be 0 in the notification header (the client locates the break by the
        // FileId in the body, not by tree); SessionId stays the holder's session. The frame is sent
        // UNSIGNED even on a signing-required session: §3.2.5.1.3 exempts MessageId 0xFFFF…FF from
        // client-side verification, and Windows servers never sign break notifications (a lease break's
        // SessionId-0 header has no signing key to begin with). Signing it — as MaybeSigned used to —
        // risks the F1-shaped failure one level up: a client that does verify unexpected signatures
        // discards the frame, the holder never acks, and the parked CREATE waits out the break timeout.
        var h = new Smb2Header
        {
            Command = SmbCommand.OplockBreak,
            MessageId = UnsolicitedMessageId,
            Flags = Smb2HeaderFlags.ServerToRedir,
            Status = NtStatus.Success,
            SessionId = session.SessionId,
            TreeId = 0,
            CreditRequestResponse = 0,
        };

        byte[] body = OplockBreakMessage.BuildBody(brk.NewLevel, open.PersistentFileId, open.VolatileFileId);

        // Failover (M6.3): send on a surviving channel, preferring the session's primary connection.
        await SendOutOfBandAsync(session, session.Connection, ResponseSegment.Unsigned(h, body),
            ResponseNeedsEncryption(session, open)).ConfigureAwait(false);
    }

    /// <summary>
    /// Processes an OPLOCK_BREAK acknowledgment from the client (§2.2.24.1/§3.3.5.22.1): the
    /// holder confirms the downgrade. The server downgrades in the manager, releases any CREATE parked
    /// behind this break (W1.1) and responds with an OPLOCK_BREAK response (§2.2.25.1).
    /// </summary>
    private ResponseSegment HandleOplockBreak(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
    {
        // Command 0x12 carries both the classic oplock break (StructureSize 24) and the lease break
        // (§2.2.24.2, StructureSize 36); route by the structure size before parsing.
        if (segment.Length >= Smb2Header.Size + 2
            && System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(segment.Slice(Smb2Header.Size, 2))
               == LeaseBreakMessage.AcknowledgmentStructureSize)
            return HandleLeaseBreakAck(connection, header, segment, frameEncrypted);

        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        OplockBreakMessage.Acknowledgment ack;
        try
        {
            ack = OplockBreakMessage.ParseAcknowledgment(segment, Smb2Header.Size);
        }
        catch (SmbWireFormatException)
        {
            // StructureSize neither 24 (oplock) nor 36 (lease) → unknown break variant.
            return BuildError(header, NtStatus.NotSupported);
        }

        if (!TryGetOpen(session, ack.PersistentId, ack.VolatileId, out SmbOpen open))
            return BuildError(header, NtStatus.FileClosed);

        OplockLevel newLevel = _server.Options.OplockManager.Acknowledge(open, ack.OplockLevel);
        open.OplockLevel = newLevel;

        // [W1.1] Release the CREATE parked behind this break — the holder has flushed. A no-op when nobody
        // is waiting (nothing registered, or the break already timed out and the CREATE went ahead: a late
        // acknowledgment is still answered normally, it just no longer releases anything).
        _breaks?.CompleteOplockBreak(open);

        byte[] body = OplockBreakMessage.BuildBody(newLevel, open.PersistentFileId, open.VolatileFileId);
        return MaybeSigned(session, RespHeader(header, session), body);
    }
}
