using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>SESSION_SETUP Request-Flags (Context §8.1).</summary>
[Flags]
public enum SessionSetupFlags : byte
{
    None = 0x00,
    Binding = 0x01, // 3.x: Session-Binding an weitere Connection.
}

/// <summary>SESSION_SETUP Response SessionFlags (Context §8.1).</summary>
[Flags]
public enum SessionResponseFlags : ushort
{
    None = 0x0000,
    IsGuest = 0x0001,
    IsNull = 0x0002,       // anonymous
    EncryptData = 0x0004,
}

/// <summary>SMB2 SESSION_SETUP Request (Context §8.1, MS-SMB2 §2.2.5). <c>StructureSize=25</c>.</summary>
public sealed class SessionSetupRequest
{
    public const ushort ExpectedStructureSize = 25;

    public SessionSetupFlags Flags { get; init; }
    public SmbSecurityMode SecurityMode { get; init; }
    public Smb2Capabilities Capabilities { get; init; }
    public ulong PreviousSessionId { get; init; }

    /// <summary>GSS/SPNEGO-Token aus dem Security-Buffer.</summary>
    public byte[] SecurityBuffer { get; init; } = [];

    public static SessionSetupRequest Parse(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != ExpectedStructureSize)
            throw new SmbWireFormatException($"SESSION_SETUP Request StructureSize {ss} ≠ {ExpectedStructureSize}.");

        var flags = (SessionSetupFlags)r.ReadByte();
        var securityMode = (SmbSecurityMode)r.ReadByte();
        var capabilities = (Smb2Capabilities)r.ReadUInt32();
        r.Skip(4); // Channel (reserved)
        ushort secOffset = r.ReadUInt16();
        ushort secLength = r.ReadUInt16();
        ulong previousSessionId = r.ReadUInt64();

        byte[] token = [];
        if (secLength > 0)
        {
            if (secOffset + secLength > message.Length)
                throw new SmbWireFormatException("SESSION_SETUP Security-Buffer reicht über die Nachricht hinaus.");
            token = message.Slice(secOffset, secLength).ToArray();
        }

        return new SessionSetupRequest
        {
            Flags = flags,
            SecurityMode = securityMode,
            Capabilities = capabilities,
            PreviousSessionId = previousSessionId,
            SecurityBuffer = token,
        };
    }
}

/// <summary>SMB2 SESSION_SETUP Response (Context §8.1, MS-SMB2 §2.2.6). <c>StructureSize=9</c>.</summary>
public sealed class SessionSetupResponse
{
    public const ushort StructureSize = 9;

    public SessionResponseFlags SessionFlags { get; init; }
    public byte[] SecurityBuffer { get; init; } = [];

    /// <summary>Baut den Body. <paramref name="headerSize"/> = Offset des Bodys (für SecurityBufferOffset).</summary>
    public byte[] ToBody(int headerSize = Smb2Header.Size)
    {
        var w = new GrowableWriter(16 + SecurityBuffer.Length);
        w.WriteUInt16(StructureSize);
        w.WriteUInt16((ushort)SessionFlags);
        int secOffsetPos = w.Position;
        w.WriteUInt16(0); // SecurityBufferOffset – patch
        w.WriteUInt16((ushort)SecurityBuffer.Length);

        int bufStart = w.Position;
        if (SecurityBuffer.Length > 0)
        {
            w.WriteBytes(SecurityBuffer);
            w.PatchUInt16(secOffsetPos, (ushort)(headerSize + bufStart));
        }
        return w.ToArray();
    }
}
