using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>SMB2 CREATE Request (Context §13, MS-SMB2 §2.2.13). <c>StructureSize=57</c>.</summary>
public sealed class CreateRequest
{
    public const ushort ExpectedStructureSize = 57;

    public OplockLevel RequestedOplockLevel { get; init; }
    public uint DesiredAccess { get; init; }
    public uint FileAttributes { get; init; }
    public uint ShareAccess { get; init; }
    public CreateDisposition Disposition { get; init; }
    public CreateOptions Options { get; init; }

    /// <summary>Share-relativer Name (UTF-16LE, ohne führenden Backslash). Leer = Share-Root.</summary>
    public string Name { get; init; } = string.Empty;

    public static CreateRequest Parse(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != ExpectedStructureSize)
            throw new SmbWireFormatException($"CREATE Request StructureSize {ss} ≠ {ExpectedStructureSize}.");

        r.Skip(1);                          // SecurityFlags
        var oplock = (OplockLevel)r.ReadByte();
        r.Skip(4);                          // ImpersonationLevel
        r.Skip(8);                          // SmbCreateFlags
        r.Skip(8);                          // Reserved
        uint desiredAccess = r.ReadUInt32();
        uint fileAttributes = r.ReadUInt32();
        uint shareAccess = r.ReadUInt32();
        var disposition = (CreateDisposition)r.ReadUInt32();
        var options = (CreateOptions)r.ReadUInt32();
        ushort nameOffset = r.ReadUInt16();
        ushort nameLength = r.ReadUInt16();
        r.ReadUInt32();                     // CreateContextsOffset
        r.ReadUInt32();                     // CreateContextsLength

        string name = string.Empty;
        if (nameLength > 0)
        {
            if (nameOffset + nameLength > message.Length)
                throw new SmbWireFormatException("CREATE Name reicht über die Nachricht hinaus.");
            name = System.Text.Encoding.Unicode.GetString(message.Slice(nameOffset, nameLength));
        }

        return new CreateRequest
        {
            RequestedOplockLevel = oplock,
            DesiredAccess = desiredAccess,
            FileAttributes = fileAttributes,
            ShareAccess = shareAccess,
            Disposition = disposition,
            Options = options,
            Name = name.TrimStart('\\'),
        };
    }
}

/// <summary>SMB2 CREATE Response (Context §13.3, MS-SMB2 §2.2.14). <c>StructureSize=89</c>.</summary>
public sealed class CreateResponse
{
    public const ushort StructureSize = 89;

    public OplockLevel OplockLevel { get; init; }
    public CreateAction CreateAction { get; init; }
    public long CreationTime { get; init; }
    public long LastAccessTime { get; init; }
    public long LastWriteTime { get; init; }
    public long ChangeTime { get; init; }
    public long AllocationSize { get; init; }
    public long EndOfFile { get; init; }
    public uint FileAttributes { get; init; }
    public ulong PersistentFileId { get; init; }
    public ulong VolatileFileId { get; init; }

    public byte[] ToBody()
    {
        var body = new byte[88];
        var w = new SpanWriter(body);
        w.WriteUInt16(StructureSize);
        w.WriteByte((byte)OplockLevel);
        w.WriteByte(0);                     // Flags
        w.WriteUInt32((uint)CreateAction);
        w.WriteInt64(CreationTime);
        w.WriteInt64(LastAccessTime);
        w.WriteInt64(LastWriteTime);
        w.WriteInt64(ChangeTime);
        w.WriteInt64(AllocationSize);
        w.WriteInt64(EndOfFile);
        w.WriteUInt32(FileAttributes);
        w.WriteUInt32(0);                   // Reserved2
        w.WriteUInt64(PersistentFileId);
        w.WriteUInt64(VolatileFileId);
        w.WriteUInt32(0);                   // CreateContextsOffset
        w.WriteUInt32(0);                   // CreateContextsLength
        return body;
    }
}

/// <summary>SMB2 CLOSE Request/Response (Context §14, MS-SMB2 §2.2.15/§2.2.16).</summary>
public static class CloseMessage
{
    public const ushort RequestStructureSize = 24;
    public const ushort ResponseStructureSize = 60;

    public const ushort FlagPostQueryAttributes = 0x0001;

    public static (ushort flags, ulong persistentId, ulong volatileId) ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != RequestStructureSize)
            throw new SmbWireFormatException($"CLOSE Request StructureSize {ss} ≠ {RequestStructureSize}.");
        ushort flags = r.ReadUInt16();
        r.Skip(4); // Reserved
        ulong persistent = r.ReadUInt64();
        ulong vol = r.ReadUInt64();
        return (flags, persistent, vol);
    }

    public static byte[] BuildResponseBody(bool postQuery = false, FileTimes? times = null,
        long allocationSize = 0, long endOfFile = 0, uint fileAttributes = 0)
    {
        var body = new byte[ResponseStructureSize];
        var w = new SpanWriter(body);
        w.WriteUInt16(ResponseStructureSize);
        w.WriteUInt16(postQuery ? FlagPostQueryAttributes : (ushort)0);
        w.WriteUInt32(0); // Reserved
        FileTimes t = times ?? default;
        w.WriteInt64(t.Creation);
        w.WriteInt64(t.LastAccess);
        w.WriteInt64(t.LastWrite);
        w.WriteInt64(t.Change);
        w.WriteInt64(allocationSize);
        w.WriteInt64(endOfFile);
        w.WriteUInt32(fileAttributes);
        return body;
    }
}

/// <summary>Vier FILETIME-Werte (Context §17).</summary>
public readonly record struct FileTimes(long Creation, long LastAccess, long LastWrite, long Change);
