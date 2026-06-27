using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// OPLOCK_BREAK messages (Context §15, MS-SMB2 §2.2.23.1/§2.2.24.1/§2.2.25.1). All three variants
/// share the same 24-byte layout: <c>StructureSize=24</c>, <c>OplockLevel(1)</c>, <c>Reserved(1)</c>,
/// <c>Reserved2(4)</c>, <c>FileId(16)</c>.
/// <list type="bullet">
/// <item><b>Notification</b> (server→client, ASYNC): the server asks the holder to downgrade its
/// oplock to <c>OplockLevel</c>.</item>
/// <item><b>Acknowledgment</b> (client→server): the client confirms the downgrade.</item>
/// <item><b>Response</b> (server→client): the server acknowledges the acknowledgment.</item>
/// </list>
/// The lease variants (§2.2.23.2 ff., different size) are left for a later pass.
/// </summary>
public static class OplockBreakMessage
{
    public const ushort StructureSize = 24;

    /// <summary>Parsed OPLOCK_BREAK acknowledgment (client→server, §2.2.24.1).</summary>
    public readonly record struct Acknowledgment(OplockLevel OplockLevel, ulong PersistentId, ulong VolatileId);

    /// <summary>
    /// Reads an OPLOCK_BREAK acknowledgment. A <c>StructureSize</c> ≠ 24 indicates a
    /// <i>lease</i> break acknowledgment (§2.2.24.2, StructureSize 36) — that is not supported
    /// (yet) and is rejected by the caller with <c>STATUS_NOT_SUPPORTED</c>.
    /// </summary>
    public static Acknowledgment ParseAcknowledgment(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != StructureSize)
            throw new SmbWireFormatException($"OPLOCK_BREAK Ack StructureSize {ss} ≠ {StructureSize} (lease break?).");

        var level = (OplockLevel)r.ReadByte();
        r.Skip(1);              // Reserved
        r.Skip(4);              // Reserved2
        ulong persistent = r.ReadUInt64();
        ulong vol = r.ReadUInt64();
        return new Acknowledgment(level, persistent, vol);
    }

    /// <summary>Builds the body of an OPLOCK_BREAK notification or response (same layout).</summary>
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
