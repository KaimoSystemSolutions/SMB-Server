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

    /// <summary>
    /// Reads FileBasicInformation (MS-FSCC §2.4.7): four FILETIMEs plus the DOS attributes, 40 bytes.
    /// <para>
    /// Per §2.4.7 a field the client does not want to change is sent as <b>0</b>, and a timestamp of
    /// <b>-1</b> means "stop updating this stamp for the remaining life of the handle". Both arrive here as
    /// <c>null</c>: the caller leaves the value alone. The -1 case is therefore honoured only for the SET
    /// itself — the suppress-future-updates part is not modelled.
    /// </para>
    /// </summary>
    public static FileBasicInfoUpdate ParseBasicInfo(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 36)
            throw new SmbWireFormatException($"FileBasicInformation requires 36 bytes, got {buffer.Length}.");

        var r = new SpanReader(buffer);
        return new FileBasicInfoUpdate
        {
            CreationTime = Stamp(r.ReadInt64()),
            LastAccessTime = Stamp(r.ReadInt64()),
            LastWriteTime = Stamp(r.ReadInt64()),
            ChangeTime = Stamp(r.ReadInt64()),
            Attributes = r.ReadUInt32() is var a && a != 0 ? a : null,
        };

        static long? Stamp(long v) => v is 0 or -1 ? null : v;
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

/// <summary>
/// A parsed FileBasicInformation SET (MS-FSCC §2.4.7). Every member is <c>null</c> when the client asked for
/// that field to stay as it is — see <see cref="SetInfoMessage.ParseBasicInfo"/>. Timestamps are FILETIME
/// (100-ns ticks since 1601-01-01 UTC); <see cref="Attributes"/> holds FILE_ATTRIBUTE_* bits.
/// </summary>
public sealed class FileBasicInfoUpdate
{
    public long? CreationTime { get; init; }
    public long? LastAccessTime { get; init; }
    public long? LastWriteTime { get; init; }
    public long? ChangeTime { get; init; }
    public uint? Attributes { get; init; }
}
