using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;
using Smb.Server.Oplocks;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// Oplocks (Context §15, MS-SMB2 §3.3.4.6/§3.3.5.9/§3.3.5.22): Beim CREATE wird über den
/// <see cref="IOplockManager"/> ein Oplock-Level gewährt (siehe HandleCreate). Öffnet ein weiterer
/// Open dieselbe Datei, schickt der Server dem bisherigen Halter eine OPLOCK_BREAK-Notification
/// (out-of-band, MessageId <c>0xFFFFFFFFFFFFFFFF</c>); der Halter bestätigt mit einem
/// OPLOCK_BREAK-Acknowledgment, das hier beantwortet wird.
/// <para>
/// Bewusste Vereinfachungen dieser ersten Ausbaustufe: Der konfligierende Zugriff wartet <i>nicht</i>
/// auf das Acknowledgment (der Halter wird sofort im Zustand herabgestuft); Lease-Breaks
/// (§2.2.23.2 ff.) und das Signieren unsolicited Notifications bleiben einem späteren Schliff
/// vorbehalten.
/// </para>
/// </summary>
public sealed partial class Smb2Dispatcher
{
    /// <summary>MessageId einer unsolicited Server-Nachricht (Oplock-Break-Notification, §3.3.4.6).</summary>
    private const ulong UnsolicitedMessageId = 0xFFFFFFFFFFFFFFFF;

    /// <summary>
    /// Verschickt die fälligen Oplock-Breaks (aus <see cref="IOplockManager.RequestOplock"/>) an ihre
    /// Halter. Die Notification geht über die Verbindung des <i>Halters</i> — nicht über die des
    /// auslösenden Requests, da Oplocks dateiweit (verbindungsübergreifend) gelten.
    /// </summary>
    private void DispatchOplockBreaks(IReadOnlyList<OplockBreak> breaks)
    {
        foreach (OplockBreak brk in breaks)
        {
            brk.Holder.OplockLevel = brk.NewLevel;   // Diagnose-Spiegel; maßgeblich ist der Manager.
            _ = SendOplockBreakAsync(brk);
        }
    }

    /// <summary>Sendet einem Halter die OPLOCK_BREAK-Notification out-of-band (§2.2.23.1).</summary>
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
        catch { /* Connection bereits weg — nichts zu tun */ }
    }

    /// <summary>
    /// Verarbeitet ein OPLOCK_BREAK-Acknowledgment des Clients (§2.2.24.1/§3.3.5.22.1): der Halter
    /// bestätigt die Herabstufung. Der Server stuft im Manager herab und quittiert mit einer
    /// OPLOCK_BREAK-Response (§2.2.25.1).
    /// </summary>
    private ResponseSegment HandleOplockBreak(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        OplockBreakMessage.Acknowledgment ack;
        try
        {
            ack = OplockBreakMessage.ParseAcknowledgment(segment, Smb2Header.Size);
        }
        catch (SmbWireFormatException)
        {
            // StructureSize ≠ 24 → Lease-Break-Acknowledgment (§2.2.24.2), noch nicht unterstützt.
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
