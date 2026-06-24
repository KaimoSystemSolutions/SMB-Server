using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>SMB2 READ Request/Response (Context §14, MS-SMB2 §2.2.19/§2.2.20).</summary>
public static class ReadMessage
{
    public const ushort RequestStructureSize = 49;
    public const ushort ResponseStructureSize = 17;

    public readonly record struct Request(uint Length, ulong Offset, ulong PersistentId, ulong VolatileId, uint MinimumCount);

    public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != RequestStructureSize)
            throw new SmbWireFormatException($"READ Request StructureSize {ss} ≠ {RequestStructureSize}.");
        r.Skip(1);                  // Padding
        r.Skip(1);                  // Flags
        uint length = r.ReadUInt32();
        ulong offset = r.ReadUInt64();
        ulong persistent = r.ReadUInt64();
        ulong vol = r.ReadUInt64();
        uint minimumCount = r.ReadUInt32();
        return new Request(length, offset, persistent, vol, minimumCount);
    }

    /// <summary>Baut die READ-Response. DataOffset = Header(64) + fester Body (16) = 80.</summary>
    public static byte[] BuildResponseBody(ReadOnlySpan<byte> data)
    {
        const byte dataOffset = Smb2Header.Size + 16; // 80
        var body = new byte[16 + data.Length];
        var w = new SpanWriter(body);
        w.WriteUInt16(ResponseStructureSize);
        w.WriteByte(dataOffset);
        w.WriteByte(0);             // Reserved
        w.WriteUInt32((uint)data.Length);
        w.WriteUInt32(0);           // DataRemaining
        w.WriteUInt32(0);           // Reserved2
        w.WriteBytes(data);
        return body;
    }
}

/// <summary>SMB2 WRITE Request/Response (Context §14, MS-SMB2 §2.2.21/§2.2.22).</summary>
public static class WriteMessage
{
    public const ushort RequestStructureSize = 49;
    public const ushort ResponseStructureSize = 17;

    public readonly record struct Request(ulong Offset, ulong PersistentId, ulong VolatileId, byte[] Data);

    public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != RequestStructureSize)
            throw new SmbWireFormatException($"WRITE Request StructureSize {ss} ≠ {RequestStructureSize}.");
        ushort dataOffset = r.ReadUInt16();
        uint length = r.ReadUInt32();
        ulong offset = r.ReadUInt64();
        ulong persistent = r.ReadUInt64();
        ulong vol = r.ReadUInt64();

        byte[] data = [];
        if (length > 0)
        {
            if (dataOffset + length > message.Length)
                throw new SmbWireFormatException("WRITE Daten reichen über die Nachricht hinaus.");
            data = message.Slice(dataOffset, (int)length).ToArray();
        }
        return new Request(offset, persistent, vol, data);
    }

    public static byte[] BuildResponseBody(uint count)
    {
        var body = new byte[16];
        var w = new SpanWriter(body);
        w.WriteUInt16(ResponseStructureSize);
        w.WriteUInt16(0);           // Reserved
        w.WriteUInt32(count);       // Count
        w.WriteUInt32(0);           // Remaining
        w.WriteUInt16(0);           // WriteChannelInfoOffset
        w.WriteUInt16(0);           // WriteChannelInfoLength
        return body;
    }
}
