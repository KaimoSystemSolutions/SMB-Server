using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>SMB2 SET_INFO Request/Response (Context §14, MS-SMB2 §2.2.39/§2.2.40). <c>StructureSize=33/2</c>.</summary>
public static class SetInfoMessage
{
    public const ushort RequestStructureSize = 33;
    public const ushort ResponseStructureSize = 2;

    public readonly record struct Request(
        InfoType InfoType, byte FileInfoClass, uint AdditionalInformation,
        ulong PersistentId, ulong VolatileId, byte[] Buffer);

    public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != RequestStructureSize)
            throw new SmbWireFormatException($"SET_INFO Request StructureSize {ss} ≠ {RequestStructureSize}.");
        var infoType = (InfoType)r.ReadByte();
        byte fileInfoClass = r.ReadByte();
        uint bufferLength = r.ReadUInt32();
        ushort bufferOffset = r.ReadUInt16();
        r.ReadUInt16(); // Reserved
        uint additionalInformation = r.ReadUInt32();
        ulong persistent = r.ReadUInt64();
        ulong vol = r.ReadUInt64();

        byte[] buffer = [];
        if (bufferLength > 0)
        {
            if (bufferOffset + bufferLength > message.Length)
                throw new SmbWireFormatException("SET_INFO buffer extends past the message.");
            buffer = message.Slice(bufferOffset, (int)bufferLength).ToArray();
        }

        return new Request(infoType, fileInfoClass, additionalInformation, persistent, vol, buffer);
    }

    public static byte[] BuildResponseBody()
    {
        var body = new byte[2];
        new SpanWriter(body).WriteUInt16(ResponseStructureSize);
        return body;
    }

    /// <summary>Reads FileRenameInformation (§2.2.39 / MS-FSCC §2.4.x): ReplaceIfExists + target path.</summary>
    public static (bool replaceIfExists, string newPath) ParseRename(ReadOnlySpan<byte> buffer)
    {
        var r = new SpanReader(buffer);
        byte replace = r.ReadByte();
        r.Skip(7);            // Reserved
        r.Skip(8);            // RootDirectory
        int nameLen = (int)r.ReadUInt32();
        string name = nameLen > 0 ? System.Text.Encoding.Unicode.GetString(r.ReadBytes(nameLen)) : string.Empty;
        return (replace != 0, name.TrimStart('\\'));
    }
}
