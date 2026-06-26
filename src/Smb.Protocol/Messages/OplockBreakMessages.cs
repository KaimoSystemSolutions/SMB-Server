using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// OPLOCK_BREAK-Nachrichten (Context §15, MS-SMB2 §2.2.23.1/§2.2.24.1/§2.2.25.1). Alle drei
/// Varianten teilen dasselbe 24-Byte-Layout: <c>StructureSize=24</c>, <c>OplockLevel(1)</c>,
/// <c>Reserved(1)</c>, <c>Reserved2(4)</c>, <c>FileId(16)</c>.
/// <list type="bullet">
/// <item><b>Notification</b> (Server→Client, ASYNC): der Server fordert den Halter auf, seinen
/// Oplock auf <c>OplockLevel</c> herabzustufen.</item>
/// <item><b>Acknowledgment</b> (Client→Server): der Client bestätigt die Herabstufung.</item>
/// <item><b>Response</b> (Server→Client): der Server quittiert das Acknowledgment.</item>
/// </list>
/// Die Lease-Varianten (§2.2.23.2 ff., abweichende Größe) bleiben einem späteren Schliff vorbehalten.
/// </summary>
public static class OplockBreakMessage
{
    public const ushort StructureSize = 24;

    /// <summary>Geparstes OPLOCK_BREAK Acknowledgment (Client→Server, §2.2.24.1).</summary>
    public readonly record struct Acknowledgment(OplockLevel OplockLevel, ulong PersistentId, ulong VolatileId);

    /// <summary>
    /// Liest ein OPLOCK_BREAK Acknowledgment. Ein <c>StructureSize</c> ≠ 24 deutet auf ein
    /// <i>Lease</i>-Break-Acknowledgment (§2.2.24.2, StructureSize 36) hin — das wird (noch) nicht
    /// unterstützt und vom Aufrufer als <c>STATUS_NOT_SUPPORTED</c> abgewiesen.
    /// </summary>
    public static Acknowledgment ParseAcknowledgment(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != StructureSize)
            throw new SmbWireFormatException($"OPLOCK_BREAK Ack StructureSize {ss} ≠ {StructureSize} (Lease-Break?).");

        var level = (OplockLevel)r.ReadByte();
        r.Skip(1);              // Reserved
        r.Skip(4);              // Reserved2
        ulong persistent = r.ReadUInt64();
        ulong vol = r.ReadUInt64();
        return new Acknowledgment(level, persistent, vol);
    }

    /// <summary>Baut den Body einer OPLOCK_BREAK Notification bzw. Response (gleiches Layout).</summary>
    public static byte[] BuildBody(OplockLevel oplockLevel, ulong persistentId, ulong volatileId)
    {
        var body = new byte[StructureSize];
        var w = new SpanWriter(body);
        w.WriteUInt16(StructureSize);
        w.WriteByte((byte)oplockLevel);
        w.WriteByte(0);         // Reserved
        w.WriteUInt32(0);       // Reserved2
        w.WriteUInt64(persistentId);
        w.WriteUInt64(volatileId);
        return body;
    }
}
