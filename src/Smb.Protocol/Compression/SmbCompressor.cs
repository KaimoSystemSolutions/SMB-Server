using System.Buffers.Binary;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Compression;

/// <summary>
/// Orchestrates SMB2 message compression (MS-SMB2 §3.1.4.4) on top of the per-algorithm codecs.
/// Builds an <b>unchained</b> compression transform frame for outbound messages (the framing the
/// server negotiates by default) and decodes any inbound compression transform frame — unchained,
/// or chained with <see cref="SmbCompressionAlgorithm.None"/>, <see cref="SmbCompressionAlgorithm.PatternV1"/>
/// and a single compressing link.
/// <para>
/// Capability is split into two sets. <see cref="DecodableAlgorithms"/> are the algorithms this build
/// can <b>decode</b> — the negotiate layer advertises only these, because an advertised algorithm can
/// arrive inbound and must decode correctly. <see cref="EncodableAlgorithms"/> are the subset it can
/// also <b>produce</b>; the outbound choice must stay within it. <see cref="SmbCompressionAlgorithm.Lz77"/>
/// (interoperable default) and <see cref="SmbCompressionAlgorithm.Lznt1"/> are fully symmetric.
/// <see cref="SmbCompressionAlgorithm.Lz77Huffman"/> is <b>decode-only</b> here: the server accepts
/// LZ77+Huffman frames from a peer (e.g. Windows) but never emits them — a spec-conformant encoder
/// (byte-exact interleaved length bytes + block flush, validated against a live Windows decoder) is a
/// documented follow-up.
/// </para>
/// </summary>
public static class SmbCompressor
{
    /// <summary>Algorithms this build can decode. Negotiation advertises only these (inbound must decode).</summary>
    public static readonly IReadOnlyList<SmbCompressionAlgorithm> DecodableAlgorithms =
        [SmbCompressionAlgorithm.Lz77, SmbCompressionAlgorithm.Lznt1, SmbCompressionAlgorithm.Lz77Huffman];

    /// <summary>Algorithms this build can produce. The negotiated outbound algorithm must be one of these.</summary>
    public static readonly IReadOnlyList<SmbCompressionAlgorithm> EncodableAlgorithms =
        [SmbCompressionAlgorithm.Lz77, SmbCompressionAlgorithm.Lznt1];

    /// <summary>True when the given algorithm has a decoder in this build (may be advertised).</summary>
    public static bool IsDecodable(SmbCompressionAlgorithm algorithm) => Contains(DecodableAlgorithms, algorithm);

    /// <summary>True when the given algorithm has an encoder in this build (may be the outbound choice).</summary>
    public static bool IsEncodable(SmbCompressionAlgorithm algorithm) => Contains(EncodableAlgorithms, algorithm);

    private static bool Contains(IReadOnlyList<SmbCompressionAlgorithm> set, SmbCompressionAlgorithm algorithm)
    {
        for (int i = 0; i < set.Count; i++)
            if (set[i] == algorithm) return true;
        return false;
    }

    /// <summary>
    /// Compresses a complete SMB2 message into an unchained compression transform frame, or returns
    /// <c>null</c> when compression is not worthwhile: the message is below <paramref name="minSize"/>,
    /// the algorithm has no encoder, or the frame would not be smaller than the plaintext.
    /// </summary>
    public static byte[]? TryCompressUnchained(SmbCompressionAlgorithm algorithm, ReadOnlySpan<byte> message, int minSize)
    {
        if (message.Length < minSize || message.Length == 0 || !IsEncodable(algorithm))
            return null;

        byte[] compressed = CompressPayload(algorithm, message);

        // Only worth it if the whole frame (16-byte header + compressed segment) beats the plaintext.
        int frameSize = CompressionTransformHeader.UnchainedSize + compressed.Length;
        if (frameSize >= message.Length)
            return null;

        var frame = new byte[frameSize];
        new CompressionTransformHeader
        {
            OriginalCompressedSegmentSize = (uint)message.Length,
            CompressionAlgorithm = algorithm,
            Flags = SmbCompressionFlags.None,
            Offset = 0, // whole message is compressed (no verbatim prefix)
        }.WriteUnchained(frame);
        compressed.CopyTo(frame.AsSpan(CompressionTransformHeader.UnchainedSize));
        return frame;
    }

    /// <summary>
    /// Decodes a compression transform frame (ProtocolId <c>FC 53 4D 42</c>) back into the original
    /// SMB2 message. Handles the unchained layout and a chained layout of None/Pattern_V1/single
    /// compressed links.
    /// </summary>
    /// <exception cref="SmbWireFormatException">On a malformed or unsupported frame.</exception>
    public static byte[] Decompress(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < CompressionTransformHeader.PrefixSize || !SmbProtocolIds.IsCompression(frame))
            throw new SmbWireFormatException("Not a compression transform frame.");

        // Distinguish unchained vs chained by the Flags field at offset 10 (only meaningful for the
        // unchained layout, where a chained sender sets it on the first payload header instead). The
        // sender picks the layout per the negotiated CHAINED capability; we accept either.
        var flags = (SmbCompressionFlags)BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(10, 2));
        return flags.HasFlag(SmbCompressionFlags.Chained)
            ? DecompressChained(frame)
            : DecompressUnchained(frame);
    }

    private static byte[] DecompressUnchained(ReadOnlySpan<byte> frame)
    {
        CompressionTransformHeader header = CompressionTransformHeader.ReadUnchained(frame);
        int prefixLen = checked((int)header.Offset);
        int originalCompressed = checked((int)header.OriginalCompressedSegmentSize);

        ReadOnlySpan<byte> body = frame[CompressionTransformHeader.UnchainedSize..];
        if (prefixLen > body.Length)
            throw new SmbWireFormatException("Compression Offset beyond frame body.");

        ReadOnlySpan<byte> verbatim = body[..prefixLen];        // uncompressed prefix
        ReadOnlySpan<byte> compressed = body[prefixLen..];      // compressed segment

        byte[] decompressed = DecompressPayload(header.CompressionAlgorithm, compressed, originalCompressed);

        var message = new byte[verbatim.Length + decompressed.Length];
        verbatim.CopyTo(message);
        decompressed.CopyTo(message.AsSpan(verbatim.Length));
        return message;
    }

    private static byte[] DecompressChained(ReadOnlySpan<byte> frame)
    {
        uint totalSize = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(4, 4));
        var output = new GrowableWriter(checked((int)totalSize));

        int pos = CompressionTransformHeader.PrefixSize;
        while (pos < frame.Length)
        {
            if (pos + CompressionPayloadHeader.Size > frame.Length)
                throw new SmbWireFormatException("Truncated chained compression payload header.");
            CompressionPayloadHeader link = CompressionPayloadHeader.Read(frame.Slice(pos, CompressionPayloadHeader.Size));
            pos += CompressionPayloadHeader.Size;

            int linkLen = checked((int)link.Length);
            if (pos + linkLen > frame.Length)
                throw new SmbWireFormatException("Truncated chained compression payload data.");
            ReadOnlySpan<byte> data = frame.Slice(pos, linkLen);
            pos += linkLen;

            switch (link.CompressionAlgorithm)
            {
                case SmbCompressionAlgorithm.None:
                    output.WriteBytes(data);
                    break;
                case SmbCompressionAlgorithm.PatternV1:
                    WritePattern(output, data);
                    break;
                default:
                    // Compressing link: [uint32 original size][compressed data] (§2.2.42.2 chained payload).
                    if (data.Length < 4)
                        throw new SmbWireFormatException("Chained compressed link missing original size.");
                    int original = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4)));
                    output.WriteBytes(DecompressPayload(link.CompressionAlgorithm, data[4..], original));
                    break;
            }
        }

        if (output.Position != totalSize)
            throw new SmbWireFormatException("Chained compression output size mismatch.");
        return output.ToArray();
    }

    /// <summary>Expands an SMB2_COMPRESSION_PATTERN_PAYLOAD_V1 (§2.2.42.2.1): Pattern ‖ Reserved(3) ‖ Repetitions(4).</summary>
    private static void WritePattern(GrowableWriter output, ReadOnlySpan<byte> data)
    {
        if (data.Length < 8)
            throw new SmbWireFormatException("Pattern_V1 payload requires 8 bytes.");
        byte pattern = data[0];
        int repetitions = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4)));
        for (int i = 0; i < repetitions; i++)
            output.WriteByte(pattern);
    }

    private static byte[] CompressPayload(SmbCompressionAlgorithm algorithm, ReadOnlySpan<byte> data) => algorithm switch
    {
        SmbCompressionAlgorithm.Lz77 => PlainLz77.Compress(data),
        SmbCompressionAlgorithm.Lznt1 => Lznt1.Compress(data),
        _ => throw new SmbWireFormatException($"No compressor for {algorithm}."),
    };

    private static byte[] DecompressPayload(SmbCompressionAlgorithm algorithm, ReadOnlySpan<byte> data, int originalSize) => algorithm switch
    {
        SmbCompressionAlgorithm.Lz77 => PlainLz77.Decompress(data, originalSize),
        SmbCompressionAlgorithm.Lznt1 => Lznt1.Decompress(data, originalSize),
        SmbCompressionAlgorithm.Lz77Huffman => Lz77Huffman.Decompress(data, originalSize),
        SmbCompressionAlgorithm.None => data.ToArray(),
        _ => throw new SmbWireFormatException($"No decompressor for {algorithm}."),
    };
}
