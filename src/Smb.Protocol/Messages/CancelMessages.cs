using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 CANCEL Request (Context §19, MS-SMB2 §2.2.30). CANCEL carries <b>no</b> response of its
/// own: the server aborts the referenced outstanding (asynchronous) operation, which in turn sends
/// its final response with <c>STATUS_CANCELLED</c> (§3.3.5.16). The match is made via MessageId
/// (sync) or AsyncId (async) in the header.
/// </summary>
public static class CancelMessage
{
    public const ushort RequestStructureSize = 4;

    /// <summary>Validates the fixed structure (no usable content outside the header).</summary>
    public static void ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != RequestStructureSize)
            throw new SmbWireFormatException($"CANCEL Request StructureSize {ss} ≠ {RequestStructureSize}.");
    }
}
