using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Compression;

/// <summary>
/// SMB2_COMPRESSION_TRANSFORM_HEADER (MS-SMB2 §2.2.42) — the frame of a compressed SMB2 message.
/// Two layouts share the same 8-byte prefix (ProtocolId <c>FC 53 4D 42</c> ‖ OriginalCompressedSegmentSize):
/// <list type="bullet">
/// <item><b>Unchained</b> (§2.2.42.1, <see cref="SmbCompressionFlags.None"/>): a single algorithm.
/// After the prefix come CompressionAlgorithm(2), Flags(2) and Offset(4); the <c>Offset</c> bytes that
/// follow the 16-byte header are sent verbatim (uncompressed prefix) and the remainder is the
/// compressed segment whose decompressed size is <see cref="OriginalCompressedSegmentSize"/>.</item>
/// <item><b>Chained</b> (§2.2.42.2, <see cref="SmbCompressionFlags.Chained"/>): the prefix is followed
/// by a sequence of <see cref="CompressionPayloadHeader"/> links.</item>
/// </list>
/// The receiver knows which layout to expect from the negotiated
/// SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED, so the two are never ambiguous on the wire.
/// </summary>
public sealed class CompressionTransformHeader
{
    /// <summary>Size of the unchained header (§2.2.42.1).</summary>
    public const int UnchainedSize = 16;

    /// <summary>Size of the fixed prefix shared by both layouts (ProtocolId + OriginalCompressedSegmentSize).</summary>
    public const int PrefixSize = 8;

    /// <summary>Decompressed size of the compressed segment (unchained) resp. the whole message (chained).</summary>
    public uint OriginalCompressedSegmentSize { get; init; }

    /// <summary>Unchained only: the algorithm of the single payload.</summary>
    public SmbCompressionAlgorithm CompressionAlgorithm { get; init; }

    public SmbCompressionFlags Flags { get; init; }

    /// <summary>Unchained only: bytes of uncompressed prefix between the 16-byte header and the compressed segment.</summary>
    public uint Offset { get; init; }

    /// <summary>Writes the 16-byte unchained header.</summary>
    public void WriteUnchained(Span<byte> destination)
    {
        if (destination.Length < UnchainedSize)
            throw new SmbWireFormatException($"Unchained compression header requires {UnchainedSize} bytes.");
        var w = new SpanWriter(destination);
        w.WriteBytes(SmbProtocolIds.Smb2Compression);
        w.WriteUInt32(OriginalCompressedSegmentSize);
        w.WriteUInt16((ushort)CompressionAlgorithm);
        w.WriteUInt16((ushort)Flags);
        w.WriteUInt32(Offset);
    }

    /// <summary>Reads the 16-byte unchained header.</summary>
    public static CompressionTransformHeader ReadUnchained(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < UnchainedSize)
            throw new SmbWireFormatException($"Unchained compression header requires {UnchainedSize} bytes.");
        if (!SmbProtocolIds.IsCompression(buffer))
            throw new SmbWireFormatException("Invalid compression ProtocolId (expected FC 53 4D 42).");

        var r = new SpanReader(buffer);
        r.Skip(4); // ProtocolId
        uint originalSize = r.ReadUInt32();
        var algorithm = (SmbCompressionAlgorithm)r.ReadUInt16();
        var flags = (SmbCompressionFlags)r.ReadUInt16();
        uint offset = r.ReadUInt32();
        return new CompressionTransformHeader
        {
            OriginalCompressedSegmentSize = originalSize,
            CompressionAlgorithm = algorithm,
            Flags = flags,
            Offset = offset,
        };
    }
}

/// <summary>
/// SMB2_COMPRESSION_PAYLOAD_HEADER (MS-SMB2 §2.2.42.1 payload, chained framing §2.2.42.2): one link
/// in a chained compression frame. <see cref="Length"/> is the size in bytes of the link data that
/// immediately follows the 8-byte header. For a compressing algorithm the link data begins with a
/// 4-byte original (uncompressed) size; <see cref="SmbCompressionAlgorithm.None"/> carries raw bytes
/// and <see cref="SmbCompressionAlgorithm.PatternV1"/> an 8-byte pattern payload (§2.2.42.2.1).
/// </summary>
public sealed class CompressionPayloadHeader
{
    public const int Size = 8;

    public SmbCompressionAlgorithm CompressionAlgorithm { get; init; }
    public SmbCompressionFlags Flags { get; init; }
    public uint Length { get; init; }

    public void Write(GrowableWriter w)
    {
        w.WriteUInt16((ushort)CompressionAlgorithm);
        w.WriteUInt16((ushort)Flags);
        w.WriteUInt32(Length);
    }

    public static CompressionPayloadHeader Read(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < Size)
            throw new SmbWireFormatException($"Compression payload header requires {Size} bytes.");
        var r = new SpanReader(buffer);
        return new CompressionPayloadHeader
        {
            CompressionAlgorithm = (SmbCompressionAlgorithm)r.ReadUInt16(),
            Flags = (SmbCompressionFlags)r.ReadUInt16(),
            Length = r.ReadUInt32(),
        };
    }
}
