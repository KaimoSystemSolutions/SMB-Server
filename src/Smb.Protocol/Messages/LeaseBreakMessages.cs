using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// Lease-break messages (MS-SMB2 §2.2.23.2/§2.2.24.2/§2.2.25.2). Unlike the classic oplock break
/// (§2.2.23.1 ff., 24 bytes, keyed by FileId) the lease variants are keyed by the 16-byte
/// <see cref="LeaseKey"/> and carry the caching-state flags directly:
/// <list type="bullet">
/// <item><b>Notification</b> (server→client, §2.2.23.2, <c>StructureSize=44</c>): the server asks the
/// holder to downgrade its lease from <c>CurrentLeaseState</c> to <c>NewLeaseState</c>.</item>
/// <item><b>Acknowledgment</b> (client→server, §2.2.24.2, <c>StructureSize=36</c>): the client
/// confirms the downgrade to <c>LeaseState</c>.</item>
/// <item><b>Response</b> (server→client, §2.2.25.2, <c>StructureSize=36</c>): the server acknowledges
/// the acknowledgment (same layout as the acknowledgment).</item>
/// </list>
/// All three share command <see cref="SmbCommand.OplockBreak"/> (0x12) — the StructureSize
/// distinguishes an oplock break (24) from a lease break (44/36).
/// </summary>
public static class LeaseBreakMessage
{
    public const ushort NotificationStructureSize = 44;
    public const ushort AcknowledgmentStructureSize = 36;
    public const ushort ResponseStructureSize = 36;   // identical layout to the acknowledgment

    /// <summary>Notification flag: the client MUST send a LEASE_BREAK_ACKNOWLEDGMENT (§2.2.23.2).</summary>
    public const uint FlagAckRequired = 0x00000001;

    /// <summary>Parsed LEASE_BREAK acknowledgment (client→server, §2.2.24.2).</summary>
    public readonly record struct Acknowledgment(uint Flags, LeaseKey Key, LeaseState State);

    /// <summary>
    /// Builds the body of a LEASE_BREAK notification (§2.2.23.2). <paramref name="newEpoch"/> is the
    /// server-incremented lease epoch (lease V2; 0 for V1 leases). <paramref name="ackRequired"/>
    /// sets <see cref="FlagAckRequired"/> so the client answers with an acknowledgment. The
    /// <c>BreakReason</c>/<c>AccessMaskHint</c>/<c>ShareMaskHint</c> hint fields are reserved (0).
    /// </summary>
    public static byte[] BuildNotificationBody(
        LeaseKey key, LeaseState currentState, LeaseState newState, ushort newEpoch, bool ackRequired)
    {
        var body = new byte[NotificationStructureSize];
        var w = new SpanWriter(body);
        w.WriteUInt16(NotificationStructureSize);
        w.WriteUInt16(newEpoch);
        w.WriteUInt32(ackRequired ? FlagAckRequired : 0u);
        w.WriteBytes(key.ToBytes());
        w.WriteUInt32((uint)currentState);
        w.WriteUInt32((uint)newState);
        w.WriteUInt32(0);   // BreakReason  — reserved
        w.WriteUInt32(0);   // AccessMaskHint — reserved
        w.WriteUInt32(0);   // ShareMaskHint  — reserved
        return body;
    }

    /// <summary>
    /// Reads a LEASE_BREAK acknowledgment (§2.2.24.2). A <c>StructureSize</c> ≠ 36 is rejected; the
    /// caller distinguishes an oplock break (24) from a lease break (36) by the StructureSize before
    /// dispatching here.
    /// </summary>
    public static Acknowledgment ParseAcknowledgment(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != AcknowledgmentStructureSize)
            throw new SmbWireFormatException($"LEASE_BREAK Ack StructureSize {ss} ≠ {AcknowledgmentStructureSize}.");

        r.Skip(2);                       // Reserved
        uint flags = r.ReadUInt32();
        LeaseKey key = LeaseKey.From(r.ReadBytes(LeaseKey.Size));
        var state = (LeaseState)r.ReadUInt32();
        r.ReadUInt64();                  // LeaseDuration — reserved
        return new Acknowledgment(flags, key, state);
    }

    /// <summary>Builds the body of a LEASE_BREAK response (§2.2.25.2), echoing the confirmed state.</summary>
    public static byte[] BuildResponseBody(LeaseKey key, LeaseState state)
    {
        var body = new byte[ResponseStructureSize];
        var w = new SpanWriter(body);
        w.WriteUInt16(ResponseStructureSize);
        w.WriteUInt16(0);                // Reserved
        w.WriteUInt32(0);                // Flags
        w.WriteBytes(key.ToBytes());
        w.WriteUInt32((uint)state);
        w.WriteUInt64(0);                // LeaseDuration — reserved
        return body;
    }
}
