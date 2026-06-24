using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 CANCEL Request (Context §19, MS-SMB2 §2.2.30). CANCEL trägt <b>keine</b> eigene
/// Response: Der Server bricht die referenzierte ausstehende (asynchrone) Operation ab, die
/// dann ihrerseits ihre finale Antwort mit <c>STATUS_CANCELLED</c> sendet (§3.3.5.16).
/// Die Zuordnung erfolgt über MessageId (sync) bzw. AsyncId (async) im Header.
/// </summary>
public static class CancelMessage
{
    public const ushort RequestStructureSize = 4;

    /// <summary>Validiert die feste Struktur (kein verwertbarer Inhalt außerhalb des Headers).</summary>
    public static void ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != RequestStructureSize)
            throw new SmbWireFormatException($"CANCEL Request StructureSize {ss} ≠ {RequestStructureSize}.");
    }
}
