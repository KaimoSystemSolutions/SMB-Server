using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Compression;

/// <summary>
/// LZNT1 (MS-XCA §2.5), the chunk-oriented LZ77 variant used by SMB2 compression
/// (<see cref="Smb.Protocol.Enums.SmbCompressionAlgorithm.Lznt1"/>).
/// <para>
/// The stream is a sequence of independent chunks, each covering at most 4096 bytes of plaintext and
/// prefixed by a 16-bit little-endian header: bit&#160;15 = compressed flag, bits&#160;14–12 = signature
/// (always <c>0b011</c>), bits&#160;11–0 = (chunk data size − 1). A compressed chunk is a run of flag
/// groups — one flag byte followed by up to eight tokens, LSB first, where a set bit marks a 16-bit
/// back-reference token and a clear bit a literal. The token's split between length (low bits) and
/// displacement (high bits) is <b>position-dependent</b>: it starts at 12 length bits / 4 displacement
/// bits and shifts one bit toward displacement each time the chunk output length crosses 16, 32, 64, …
/// (MS-XCA §2.5). Back-references never cross a chunk boundary.
/// </para>
/// The decompressor follows the exact spec split so a stock Windows compressor's output decodes
/// correctly; the compressor emits the same split so its output decodes on Windows.
/// </summary>
public static class Lznt1
{
    /// <summary>Minimum encodable match length.</summary>
    public const int MinMatch = 3;

    /// <summary>Maximum plaintext bytes per chunk (§2.5).</summary>
    public const int ChunkSize = 4096;

    // Chunk-header bits (§2.5): signature 0b011 in bits 14–12, compressed flag in bit 15.
    private const ushort SignatureBits = 0x3000;
    private const ushort CompressedBit = 0x8000;
    private const ushort SizeMask = 0x0FFF;

    private const int HashBits = 13;
    private const int HashSize = 1 << HashBits;
    private const int MaxChain = 64;

    /// <summary>
    /// Decompresses an LZNT1 stream into an output buffer of the exact expected size (carried
    /// out-of-band by the SMB compression transform header).
    /// </summary>
    /// <exception cref="SmbWireFormatException">On a truncated or malformed stream.</exception>
    public static byte[] Decompress(ReadOnlySpan<byte> input, int originalSize)
    {
        if (originalSize < 0)
            throw new SmbWireFormatException("Negative original size.");

        var output = new byte[originalSize];
        int inPos = 0;
        int outPos = 0;

        while (outPos < originalSize)
        {
            if (inPos + 2 > input.Length)
                throw new SmbWireFormatException("Truncated LZNT1 chunk header.");
            ushort header = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(inPos));
            inPos += 2;
            if (header == 0)
                break; // end marker / trailing padding

            int chunkDataSize = (header & SizeMask) + 1;
            bool compressed = (header & CompressedBit) != 0;
            if (inPos + chunkDataSize > input.Length)
                throw new SmbWireFormatException("Truncated LZNT1 chunk.");
            ReadOnlySpan<byte> chunk = input.Slice(inPos, chunkDataSize);
            inPos += chunkDataSize;

            if (!compressed)
            {
                if (outPos + chunkDataSize > originalSize)
                    throw new SmbWireFormatException("LZNT1 uncompressed chunk overruns declared size.");
                chunk.CopyTo(output.AsSpan(outPos));
                outPos += chunkDataSize;
            }
            else
            {
                outPos = DecompressChunk(chunk, output, outPos, originalSize);
            }
        }

        return output;
    }

    private static int DecompressChunk(ReadOnlySpan<byte> chunk, byte[] output, int outStart, int originalSize)
    {
        int inPos = 0;
        int outPos = outStart;
        int chunkOut = 0; // bytes produced within this chunk (drives the split)

        while (inPos < chunk.Length)
        {
            byte flags = chunk[inPos++];
            for (int bit = 0; bit < 8 && inPos < chunk.Length; bit++)
            {
                if ((flags & (1 << bit)) == 0)
                {
                    if (outPos >= originalSize)
                        throw new SmbWireFormatException("LZNT1 literal overruns declared size.");
                    output[outPos++] = chunk[inPos++];
                    chunkOut++;
                }
                else
                {
                    if (inPos + 2 > chunk.Length)
                        throw new SmbWireFormatException("Truncated LZNT1 match token.");
                    ushort token = BinaryPrimitives.ReadUInt16LittleEndian(chunk.Slice(inPos));
                    inPos += 2;

                    int split = SplitFor(chunkOut);
                    int length = (token & ((1 << split) - 1)) + MinMatch;
                    int distance = (token >> split) + 1;

                    if (distance > chunkOut)
                        throw new SmbWireFormatException("LZNT1 back-reference before start of chunk.");
                    if (outPos + length > originalSize)
                        throw new SmbWireFormatException("LZNT1 match overruns declared size.");

                    int src = outPos - distance;
                    for (int k = 0; k < length; k++)
                        output[outPos + k] = output[src + k]; // byte-wise: overlapping copies are intentional
                    outPos += length;
                    chunkOut += length;
                }
            }
        }

        return outPos;
    }

    /// <summary>Compresses <paramref name="input"/> into an LZNT1 stream.</summary>
    public static byte[] Compress(ReadOnlySpan<byte> input)
    {
        var output = new GrowableWriter(input.Length + input.Length / 8 + 16);
        int pos = 0;
        while (pos < input.Length)
        {
            int chunkLen = Math.Min(ChunkSize, input.Length - pos);
            ReadOnlySpan<byte> chunk = input.Slice(pos, chunkLen);
            byte[]? compressed = CompressChunk(chunk);

            if (compressed is not null && compressed.Length < chunkLen)
            {
                output.WriteUInt16((ushort)(CompressedBit | SignatureBits | (compressed.Length - 1)));
                output.WriteBytes(compressed);
            }
            else
            {
                output.WriteUInt16((ushort)(SignatureBits | (chunkLen - 1)));
                output.WriteBytes(chunk);
            }
            pos += chunkLen;
        }
        return output.ToArray();
    }

    /// <summary>
    /// Compresses a single chunk, or returns <c>null</c> as soon as the compressed form can no longer
    /// beat the raw chunk (the caller then stores the chunk uncompressed).
    /// </summary>
    private static byte[]? CompressChunk(ReadOnlySpan<byte> chunk)
    {
        int n = chunk.Length;
        var w = new GrowableWriter(n);
        var head = new int[HashSize];
        var prev = new int[n];
        Array.Fill(head, -1);

        int i = 0;
        while (i < n)
        {
            int flagPos = w.Position;
            w.WriteByte(0); // flag byte, patched once the group fills
            byte flags = 0;

            for (int bit = 0; bit < 8 && i < n; bit++)
            {
                int split = SplitFor(i);
                int maxDistance = 1 << (16 - split);
                int maxLength = Math.Min(((1 << split) - 1) + MinMatch, n - i);

                (int length, int distance) = FindMatch(chunk, i, maxDistance, maxLength, head, prev);
                if (length >= MinMatch)
                {
                    flags |= (byte)(1 << bit);
                    w.WriteUInt16((ushort)(((distance - 1) << split) | (length - MinMatch)));
                    Insert(chunk, head, prev, i, length);
                    i += length;
                }
                else
                {
                    w.WriteByte(chunk[i]);
                    Insert(chunk, head, prev, i, 1);
                    i++;
                }

                if (w.Position >= n)
                    return null; // can no longer win — store the chunk raw
            }
            w.PatchByte(flagPos, flags);
        }

        return w.ToArray();
    }

    /// <summary>
    /// Number of low bits carrying the match length (the remaining <c>16 − split</c> carry the
    /// displacement). Starts at 12 and drops one bit each time the chunk output length passes
    /// 16, 32, 64, … (MS-XCA §2.5).
    /// </summary>
    private static int SplitFor(int chunkOutputLength)
    {
        int split = 12;
        int threshold = 16;
        while (chunkOutputLength > threshold)
        {
            split--;
            threshold <<= 1;
        }
        return split;
    }

    private static int Hash(ReadOnlySpan<byte> d, int pos)
    {
        uint h = (uint)((d[pos] << 16) | (d[pos + 1] << 8) | d[pos + 2]);
        return (int)((h * 2654435761u) >> (32 - HashBits));
    }

    private static void Insert(ReadOnlySpan<byte> data, int[] head, int[] prev, int pos, int length)
    {
        int end = pos + length;
        for (int p = pos; p < end && p + 2 < data.Length; p++)
        {
            int h = Hash(data, p);
            prev[p] = head[h];
            head[h] = p;
        }
    }

    private static (int Length, int Distance) FindMatch(
        ReadOnlySpan<byte> data, int pos, int maxDistance, int maxLength, int[] head, int[] prev)
    {
        if (maxLength < MinMatch)
            return (0, 0);

        int minPos = Math.Max(0, pos - maxDistance);
        int candidate = head[Hash(data, pos)];
        int bestLen = 0;
        int bestDist = 0;
        int chain = MaxChain;

        while (candidate >= minPos && chain-- > 0)
        {
            int len = MatchLength(data, candidate, pos, maxLength);
            if (len > bestLen)
            {
                bestLen = len;
                bestDist = pos - candidate;
                if (len >= maxLength) break;
            }
            candidate = prev[candidate];
        }

        return bestLen >= MinMatch ? (bestLen, bestDist) : (0, 0);
    }

    private static int MatchLength(ReadOnlySpan<byte> data, int a, int b, int maxLength)
    {
        int len = 0;
        while (len < maxLength && data[a + len] == data[b + len]) len++;
        return len;
    }
}
