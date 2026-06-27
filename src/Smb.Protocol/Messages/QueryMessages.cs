using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>SMB2 QUERY_DIRECTORY Request/Response (Context §14, MS-SMB2 §2.2.33/§2.2.34).</summary>
public static class QueryDirectoryMessage
{
    public const ushort RequestStructureSize = 33;
    public const ushort ResponseStructureSize = 9;

    public const byte FlagRestartScan = 0x01;
    public const byte FlagReturnSingleEntry = 0x02;

    public readonly record struct Request(
        FileInformationClass InfoClass, byte Flags, ulong PersistentId, ulong VolatileId,
        string SearchPattern, uint OutputBufferLength);

    public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != RequestStructureSize)
            throw new SmbWireFormatException($"QUERY_DIRECTORY Request StructureSize {ss} ≠ {RequestStructureSize}.");
        var infoClass = (FileInformationClass)r.ReadByte();
        byte flags = r.ReadByte();
        r.ReadUInt32(); // FileIndex
        ulong persistent = r.ReadUInt64();
        ulong vol = r.ReadUInt64();
        ushort nameOffset = r.ReadUInt16();
        ushort nameLength = r.ReadUInt16();
        uint outputBufferLength = r.ReadUInt32();

        string pattern = string.Empty;
        if (nameLength > 0 && nameOffset + nameLength <= message.Length)
            pattern = System.Text.Encoding.Unicode.GetString(message.Slice(nameOffset, nameLength));

        return new Request(infoClass, flags, persistent, vol, pattern, outputBufferLength);
    }

    /// <summary>Builds the response. OutputBufferOffset = header(64) + fixed body(8) = 72.</summary>
    public static byte[] BuildResponseBody(ReadOnlySpan<byte> buffer)
    {
        const ushort outputBufferOffset = Smb2Header.Size + 8; // 72
        var body = new byte[8 + buffer.Length];
        var w = new SpanWriter(body);
        w.WriteUInt16(ResponseStructureSize);
        w.WriteUInt16(outputBufferOffset);
        w.WriteUInt32((uint)buffer.Length);
        w.WriteBytes(buffer);
        return body;
    }
}

/// <summary>SMB2 QUERY_INFO Request/Response (Context §14, MS-SMB2 §2.2.37/§2.2.38).</summary>
public static class QueryInfoMessage
{
    public const ushort RequestStructureSize = 41;
    public const ushort ResponseStructureSize = 9;

    public readonly record struct Request(
        InfoType InfoType, byte FileInfoClass, uint OutputBufferLength,
        uint AdditionalInformation, ulong PersistentId, ulong VolatileId);

    public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != RequestStructureSize)
            throw new SmbWireFormatException($"QUERY_INFO Request StructureSize {ss} ≠ {RequestStructureSize}.");
        var infoType = (InfoType)r.ReadByte();
        byte fileInfoClass = r.ReadByte();
        uint outputBufferLength = r.ReadUInt32();
        r.ReadUInt16(); // InputBufferOffset
        r.ReadUInt16(); // Reserved
        r.ReadUInt32(); // InputBufferLength
        uint additionalInformation = r.ReadUInt32();
        r.ReadUInt32(); // Flags
        ulong persistent = r.ReadUInt64();
        ulong vol = r.ReadUInt64();
        return new Request(infoType, fileInfoClass, outputBufferLength, additionalInformation, persistent, vol);
    }

    /// <summary>Builds the response. OutputBufferOffset = header(64) + fixed body(8) = 72.</summary>
    public static byte[] BuildResponseBody(ReadOnlySpan<byte> buffer)
    {
        const ushort outputBufferOffset = Smb2Header.Size + 8; // 72
        var body = new byte[8 + buffer.Length];
        var w = new SpanWriter(body);
        w.WriteUInt16(ResponseStructureSize);
        w.WriteUInt16(outputBufferOffset);
        w.WriteUInt32((uint)buffer.Length);
        w.WriteBytes(buffer);
        return body;
    }
}
