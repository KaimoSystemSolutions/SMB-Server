using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 packet header, 64 bytes (Context §4, MS-SMB2 §2.2.1.1/§2.2.1.2).
/// Supports the SYNC and ASYNC variants. <c>StructureSize</c> MUST be 64.
/// Multi-byte fields are little-endian; <c>ProtocolId</c> is a fixed byte sequence.
/// </summary>
public sealed class Smb2Header
{
    /// <summary>Fixed header size in bytes.</summary>
    public const int Size = 64;

    /// <summary>Value of the <c>StructureSize</c> field — constant 64 per the spec.</summary>
    public const ushort HeaderStructureSize = 64;

    /// <summary>Sentinel for "previous FileId" in related compounds (Context §7, §23).</summary>
    public const ulong RelatedFileIdSentinel = 0xFFFFFFFFFFFFFFFF;

    public ushort CreditCharge { get; set; }

    /// <summary>
    /// Raw value of the field at offset 8. On requests (2.x) and on responses it is the NTSTATUS;
    /// on requests (3.x) it is ChannelSequence(2) ‖ Reserved(2). See <see cref="Status"/>.
    /// </summary>
    public uint StatusOrChannelSequence { get; set; }

    public SmbCommand Command { get; set; }
    public ushort CreditRequestResponse { get; set; }
    public Smb2HeaderFlags Flags { get; set; }

    /// <summary>Offset to the next header in the compound (0 = last, Context §7).</summary>
    public uint NextCommand { get; set; }

    public ulong MessageId { get; set; }

    /// <summary>ASYNC only (Flags contains <see cref="Smb2HeaderFlags.AsyncCommand"/>).</summary>
    public ulong AsyncId { get; set; }

    /// <summary>SYNC only.</summary>
    public uint TreeId { get; set; }

    public ulong SessionId { get; set; }

    /// <summary>16-byte signature (all zero when not signed).</summary>
    public byte[] Signature { get; set; } = new byte[16];

    /// <summary>True when the ASYNC header layout applies.</summary>
    public bool IsAsync => Flags.HasFlag(Smb2HeaderFlags.AsyncCommand);

    /// <summary>True when this is a server→client response.</summary>
    public bool IsResponse => Flags.HasFlag(Smb2HeaderFlags.ServerToRedir);

    /// <summary>Interprets <see cref="StatusOrChannelSequence"/> as an NTSTATUS (responses).</summary>
    public NtStatus Status
    {
        get => (NtStatus)StatusOrChannelSequence;
        set => StatusOrChannelSequence = (uint)value;
    }

    /// <summary>ChannelSequence (low 16 bits of offset 8) — 3.x requests only.</summary>
    public ushort ChannelSequence => (ushort)(StatusOrChannelSequence & 0xFFFF);

    /// <summary>Reads a 64-byte header from the start of the buffer.</summary>
    /// <exception cref="SmbWireFormatException">On wrong ProtocolId or StructureSize.</exception>
    public static Smb2Header Read(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < Size)
            throw new SmbWireFormatException($"SMB2 header requires {Size} bytes, has {buffer.Length}.");
        if (!SmbProtocolIds.IsSmb2(buffer))
            throw new SmbWireFormatException("Invalid SMB2 ProtocolId (expected FE 53 4D 42).");

        var r = new SpanReader(buffer);
        r.Skip(4); // ProtocolId

        ushort structureSize = r.ReadUInt16();
        if (structureSize != HeaderStructureSize)
            throw new SmbWireFormatException($"SMB2 header StructureSize {structureSize} ≠ {HeaderStructureSize}.");

        var header = new Smb2Header
        {
            CreditCharge = r.ReadUInt16(),
            StatusOrChannelSequence = r.ReadUInt32(),
            Command = (SmbCommand)r.ReadUInt16(),
            CreditRequestResponse = r.ReadUInt16(),
            Flags = (Smb2HeaderFlags)r.ReadUInt32(),
            NextCommand = r.ReadUInt32(),
            MessageId = r.ReadUInt64(),
        };

        if (header.IsAsync)
        {
            header.AsyncId = r.ReadUInt64(); // offsets 32–39
        }
        else
        {
            r.Skip(4);                       // Reserved (offset 32–35)
            header.TreeId = r.ReadUInt32();  // offset 36–39
        }

        header.SessionId = r.ReadUInt64();   // offset 40–47
        header.Signature = r.ReadByteArray(16); // offset 48–63
        return header;
    }

    /// <summary>Writes the header (64 bytes) to the start of the buffer.</summary>
    public void Write(Span<byte> destination)
    {
        if (destination.Length < Size)
            throw new SmbWireFormatException($"Destination requires {Size} bytes for the SMB2 header.");

        var w = new SpanWriter(destination);
        w.WriteBytes(SmbProtocolIds.Smb2);
        w.WriteUInt16(HeaderStructureSize);
        w.WriteUInt16(CreditCharge);
        w.WriteUInt32(StatusOrChannelSequence);
        w.WriteUInt16((ushort)Command);
        w.WriteUInt16(CreditRequestResponse);
        w.WriteUInt32((uint)Flags);
        w.WriteUInt32(NextCommand);
        w.WriteUInt64(MessageId);

        if (IsAsync)
        {
            w.WriteUInt64(AsyncId);
        }
        else
        {
            w.WriteZeros(4);     // Reserved
            w.WriteUInt32(TreeId);
        }

        w.WriteUInt64(SessionId);

        if (Signature.Length != 16)
            throw new SmbWireFormatException("Signature must be exactly 16 bytes.");
        w.WriteBytes(Signature);
    }

    /// <summary>Serializes the header into a new 64-byte array.</summary>
    public byte[] ToArray()
    {
        var buf = new byte[Size];
        Write(buf);
        return buf;
    }

    /// <summary>
    /// Builds the base of the response from a request header: carries over MessageId, SessionId,
    /// TreeId/AsyncId and Command, and sets <see cref="Smb2HeaderFlags.ServerToRedir"/>
    /// (Context §4). The signature is zeroed; status/credits are set by the caller.
    /// </summary>
    public Smb2Header CreateResponse(NtStatus status)
    {
        var flags = Smb2HeaderFlags.ServerToRedir;
        if (IsAsync) flags |= Smb2HeaderFlags.AsyncCommand;

        return new Smb2Header
        {
            Command = Command,
            MessageId = MessageId,
            SessionId = SessionId,
            TreeId = TreeId,
            AsyncId = AsyncId,
            CreditCharge = CreditCharge,
            Flags = flags,
            Status = status,
            Signature = new byte[16],
        };
    }
}
