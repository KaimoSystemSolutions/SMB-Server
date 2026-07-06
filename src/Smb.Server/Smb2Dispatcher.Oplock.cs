using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;
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
/// Intentional simplification in this stage: the conflicting access does <i>not</i> wait for the
/// acknowledgment (the holder is immediately downgraded in state). The lease equivalent
/// (§2.2.23.2 ff.) lives in <c>Smb2Dispatcher.Lease.cs</c>; its acknowledgment (StructureSize
/// 36) is routed from <see cref="HandleOplockBreak"/>.
/// </para>
/// </summary>
public sealed partial class Smb2Dispatcher
{
    /// <summary>MessageId of an unsolicited server message (oplock break notification, §3.3.4.6).</summary>
    private const ulong UnsolicitedMessageId = 0xFFFFFFFFFFFFFFFF;

    /// <summary>
    /// Dispatches the pending oplock breaks (from <see cref="IOplockManager.RequestOplock"/>) to
    /// their holders. The notification goes via the connection of the <i>holder</i> — not the
    /// connection of the triggering request, because oplocks are file-wide (cross-connection).
    /// </summary>
    private void DispatchOplockBreaks(IReadOnlyList<OplockBreak> breaks)
    {
        foreach (OplockBreak brk in breaks)
        {
            brk.Holder.OplockLevel = brk.NewLevel;   // diagnostic mirror; the manager's state is authoritative.
            _ = SendOplockBreakAsync(brk);
        }
    }

    /// <summary>Sends the OPLOCK_BREAK notification to a holder out-of-band (§2.2.23.1).</summary>
    private async Task SendOplockBreakAsync(OplockBreak brk)
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

        byte[] body = OplockBreakMessage.BuildBody(brk.NewLevel, open.PersistentFileId, open.VolatileFileId);
        byte[] bytes = AssembleResponse([MaybeSigned(session, h, body)]);

        Func<byte[], bool, Task>? sender = connection.SendRawAsync;
        if (sender is null) return;
        try { await sender(bytes, ResponseNeedsEncryption(session, open)).ConfigureAwait(false); }
        catch { /* connection already gone — nothing to do */ }
    }

    /// <summary>
    /// Processes an OPLOCK_BREAK acknowledgment from the client (§2.2.24.1/§3.3.5.22.1): the
    /// holder confirms the downgrade. The server downgrades in the manager and responds with an
    /// OPLOCK_BREAK response (§2.2.25.1).
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
        if (!VerifyInboundSignature(session, header, segment, frameEncrypted))
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

        byte[] body = OplockBreakMessage.BuildBody(newLevel, open.PersistentFileId, open.VolatileFileId);
        return MaybeSigned(session, RespHeader(header, session), body);
    }
}
