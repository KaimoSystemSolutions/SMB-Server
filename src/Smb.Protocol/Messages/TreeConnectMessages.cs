using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>SMB2 TREE_CONNECT Request (Context §12, MS-SMB2 §2.2.9). <c>StructureSize=9</c>.</summary>
public sealed class TreeConnectRequest
{
    public const ushort ExpectedStructureSize = 9;

    /// <summary>UNC-Pfad <c>\\server\share</c> (UTF-16LE).</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>Extrahiert den Share-Namen aus dem UNC-Pfad (letztes Segment).</summary>
    public string ShareName
    {
        get
        {
            int idx = Path.LastIndexOf('\\');
            return idx >= 0 ? Path[(idx + 1)..] : Path;
        }
    }

    public static TreeConnectRequest Parse(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != ExpectedStructureSize)
            throw new SmbWireFormatException($"TREE_CONNECT Request StructureSize {ss} ≠ {ExpectedStructureSize}.");

        r.Skip(2); // Flags/Reserved (3.1.1 Tree-Connect Extension – Phase ≥2)
        ushort pathOffset = r.ReadUInt16();
        ushort pathLength = r.ReadUInt16();

        string path = string.Empty;
        if (pathLength > 0)
        {
            if (pathOffset + pathLength > message.Length)
                throw new SmbWireFormatException("TREE_CONNECT Pfad reicht über die Nachricht hinaus.");
            path = System.Text.Encoding.Unicode.GetString(message.Slice(pathOffset, pathLength));
        }

        return new TreeConnectRequest { Path = path };
    }
}

/// <summary>ShareFlags (MS-SMB2 §2.2.10) — Phase 1 minimal.</summary>
[Flags]
public enum ShareFlags : uint
{
    None = 0x00000000,
    ManualCaching = 0x00000000,
    AutoCaching = 0x00000010,
    VdoCaching = 0x00000020,
    NoCaching = 0x00000030,
    Dfs = 0x00000001,
    DfsRoot = 0x00000002,
    EncryptData = 0x00008000,
}

/// <summary>SMB2 TREE_CONNECT Response (Context §12, MS-SMB2 §2.2.10). <c>StructureSize=16</c>.</summary>
public sealed class TreeConnectResponse
{
    public const ushort StructureSize = 16;

    public byte ShareType { get; init; }
    public ShareFlags ShareFlags { get; init; }
    public uint Capabilities { get; init; }

    /// <summary>Effektive Rechte des Users auf dem Share (Access-Mask, Context §12, §13.1).</summary>
    public uint MaximalAccess { get; init; }

    public byte[] ToBody()
    {
        var body = new byte[16];
        var w = new SpanWriter(body);
        w.WriteUInt16(StructureSize);
        w.WriteByte(ShareType);
        w.WriteByte(0); // Reserved
        w.WriteUInt32((uint)ShareFlags);
        w.WriteUInt32(Capabilities);
        w.WriteUInt32(MaximalAccess);
        return body;
    }
}

/// <summary>TREE_DISCONNECT Request/Response (MS-SMB2 §2.2.11/§2.2.12). <c>StructureSize=4</c>.</summary>
public static class TreeDisconnectMessage
{
    public const ushort StructureSize = 4;

    public static byte[] BuildResponseBody()
    {
        var body = new byte[4];
        var w = new SpanWriter(body);
        w.WriteUInt16(StructureSize);
        w.WriteUInt16(0); // Reserved
        return body;
    }
}

/// <summary>LOGOFF Request/Response (MS-SMB2 §2.2.7/§2.2.8). <c>StructureSize=4</c>.</summary>
public static class LogoffMessage
{
    public const ushort StructureSize = 4;

    public static byte[] BuildResponseBody()
    {
        var body = new byte[4];
        var w = new SpanWriter(body);
        w.WriteUInt16(StructureSize);
        w.WriteUInt16(0); // Reserved
        return body;
    }
}
