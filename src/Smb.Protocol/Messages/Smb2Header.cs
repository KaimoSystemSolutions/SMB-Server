using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2-Paketheader, 64 Byte (Context §4, MS-SMB2 §2.2.1.1/§2.2.1.2).
/// Unterstützt SYNC- und ASYNC-Variante. <c>StructureSize</c> MUSS 64 sein.
/// Mehrbyte-Felder Little-Endian; <c>ProtocolId</c> ist eine feste Bytefolge.
/// </summary>
public sealed class Smb2Header
{
    /// <summary>Feste Header-Größe in Bytes.</summary>
    public const int Size = 64;

    /// <summary>Wert des <c>StructureSize</c>-Felds — laut Spec konstant 64.</summary>
    public const ushort HeaderStructureSize = 64;

    /// <summary>Sentinel für "voriges FileId" in Related-Compounds (Context §7, §23).</summary>
    public const ulong RelatedFileIdSentinel = 0xFFFFFFFFFFFFFFFF;

    public ushort CreditCharge { get; set; }

    /// <summary>
    /// Rohwert des Felds bei Offset 8. Bei Requests (2.x) bzw. Responses = NTSTATUS;
    /// bei Requests (3.x) = ChannelSequence(2) ‖ Reserved(2). Siehe <see cref="Status"/>.
    /// </summary>
    public uint StatusOrChannelSequence { get; set; }

    public SmbCommand Command { get; set; }
    public ushort CreditRequestResponse { get; set; }
    public Smb2HeaderFlags Flags { get; set; }

    /// <summary>Offset zum nächsten Header im Compound (0 = letzter, Context §7).</summary>
    public uint NextCommand { get; set; }

    public ulong MessageId { get; set; }

    /// <summary>Nur ASYNC (Flags enthält <see cref="Smb2HeaderFlags.AsyncCommand"/>).</summary>
    public ulong AsyncId { get; set; }

    /// <summary>Nur SYNC.</summary>
    public uint TreeId { get; set; }

    public ulong SessionId { get; set; }

    /// <summary>16-Byte-Signatur (alles 0, wenn nicht signiert).</summary>
    public byte[] Signature { get; set; } = new byte[16];

    /// <summary>True, wenn das ASYNC-Header-Layout gilt.</summary>
    public bool IsAsync => Flags.HasFlag(Smb2HeaderFlags.AsyncCommand);

    /// <summary>True, wenn dies eine Server→Client-Antwort ist.</summary>
    public bool IsResponse => Flags.HasFlag(Smb2HeaderFlags.ServerToRedir);

    /// <summary>Interpretiert <see cref="StatusOrChannelSequence"/> als NTSTATUS (Responses).</summary>
    public NtStatus Status
    {
        get => (NtStatus)StatusOrChannelSequence;
        set => StatusOrChannelSequence = (uint)value;
    }

    /// <summary>ChannelSequence (untere 16 Bit von Offset 8) — nur 3.x-Requests.</summary>
    public ushort ChannelSequence => (ushort)(StatusOrChannelSequence & 0xFFFF);

    /// <summary>Liest einen 64-Byte-Header aus dem Pufferanfang.</summary>
    /// <exception cref="SmbWireFormatException">Bei falschem ProtocolId oder StructureSize.</exception>
    public static Smb2Header Read(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < Size)
            throw new SmbWireFormatException($"SMB2-Header benötigt {Size} Bytes, hat {buffer.Length}.");
        if (!SmbProtocolIds.IsSmb2(buffer))
            throw new SmbWireFormatException("Ungültiger SMB2-ProtocolId (erwartet FE 53 4D 42).");

        var r = new SpanReader(buffer);
        r.Skip(4); // ProtocolId

        ushort structureSize = r.ReadUInt16();
        if (structureSize != HeaderStructureSize)
            throw new SmbWireFormatException($"SMB2-Header StructureSize {structureSize} ≠ {HeaderStructureSize}.");

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
            header.AsyncId = r.ReadUInt64(); // Offsets 32–39
        }
        else
        {
            r.Skip(4);                       // Reserved (Offset 32–35)
            header.TreeId = r.ReadUInt32();  // Offset 36–39
        }

        header.SessionId = r.ReadUInt64();   // Offset 40–47
        header.Signature = r.ReadByteArray(16); // Offset 48–63
        return header;
    }

    /// <summary>Schreibt den Header (64 Byte) an den Pufferanfang.</summary>
    public void Write(Span<byte> destination)
    {
        if (destination.Length < Size)
            throw new SmbWireFormatException($"Ziel benötigt {Size} Bytes für den SMB2-Header.");

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
            throw new SmbWireFormatException("Signature muss exakt 16 Byte sein.");
        w.WriteBytes(Signature);
    }

    /// <summary>Serialisiert den Header in ein neues 64-Byte-Array.</summary>
    public byte[] ToArray()
    {
        var buf = new byte[Size];
        Write(buf);
        return buf;
    }

    /// <summary>
    /// Erzeugt aus einem Request-Header die Basis der Antwort: übernimmt MessageId,
    /// SessionId, TreeId/AsyncId, Command und setzt <see cref="Smb2HeaderFlags.ServerToRedir"/>
    /// (Context §4). Signatur wird genullt; Status/Credits setzt der Aufrufer.
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
