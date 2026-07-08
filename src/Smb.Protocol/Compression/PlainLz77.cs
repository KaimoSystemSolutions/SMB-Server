using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Compression;

/// <summary>
/// Plain LZ77 (MS-XCA §2.4), the byte-oriented LZ77 variant used by SMB2 compression
/// (<see cref="Smb.Protocol.Enums.SmbCompressionAlgorithm.Lz77"/>). A 32-bit flag group (read
/// little-endian, consumed MSB-first) tags each token as a literal (0) or a match (1); a match is a
/// 16-bit value splitting into a 13-bit distance-1 and a 3-bit length-3, with the classic escape
/// chain (extra byte, then u16, then u32) for longer runs.
/// <para>
/// The window is 8 KiB (13-bit distance) and the minimum match is 3 bytes. The compressor caps a
/// single match at <see cref="MaxMatch"/> (264) bytes so it only ever emits the unambiguous
/// single-extra-byte length escape — keeping its output decodable by a stock Windows decompressor —
/// while the decompressor handles the full escape chain for inbound frames.
/// </para>
/// </summary>
public static class PlainLz77
{
    /// <summary>Minimum encodable match length.</summary>
    public const int MinMatch = 3;

    /// <summary>Maximum match length the compressor emits (single extra length byte: 254 + 10).</summary>
    public const int MaxMatch = 264;

    /// <summary>Maximum back-reference distance (13-bit field + 1).</summary>
    public const int MaxDistance = 8192;

    /// <summary>
    /// Decompresses a plain-LZ77 stream into an output buffer of the exact expected size
    /// (the size is carried out-of-band by the SMB compression transform header).
    /// </summary>
    /// <exception cref="SmbWireFormatException">On a truncated or malformed stream.</exception>
    public static byte[] Decompress(ReadOnlySpan<byte> input, int originalSize)
    {
        if (originalSize < 0)
            throw new SmbWireFormatException("Negative original size.");
        var output = new byte[originalSize];
        int inPos = 0;
        int outPos = 0;
        uint flags = 0;
        int flagCount = 0;

        while (outPos < output.Length)
        {
            if (flagCount == 0)
            {
                if (inPos + 4 > input.Length)
                    throw new SmbWireFormatException("Truncated LZ77 flag group.");
                flags = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(inPos));
                inPos += 4;
                flagCount = 32;
            }

            flagCount--;
            bool isMatch = ((flags >> flagCount) & 1) != 0;

            if (!isMatch)
            {
                if (inPos >= input.Length)
                    throw new SmbWireFormatException("Truncated LZ77 literal.");
                output[outPos++] = input[inPos++];
                continue;
            }

            if (inPos + 2 > input.Length)
                throw new SmbWireFormatException("Truncated LZ77 match.");
            ushort matchBytes = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(inPos));
            inPos += 2;

            int length = matchBytes & 0x7;
            int distance = (matchBytes >> 3) + 1;

            if (length == 7)
            {
                if (inPos >= input.Length)
                    throw new SmbWireFormatException("Truncated LZ77 extended length.");
                int extra = input[inPos++];
                if (extra == 255)
                {
                    if (inPos + 2 > input.Length)
                        throw new SmbWireFormatException("Truncated LZ77 extended length (u16).");
                    int wide = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(inPos));
                    inPos += 2;
                    if (wide == 0)
                    {
                        if (inPos + 4 > input.Length)
                            throw new SmbWireFormatException("Truncated LZ77 extended length (u32).");
                        wide = (int)BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(inPos));
                        inPos += 4;
                    }
                    length = wide - 7;
                }
                else
                {
                    length = extra;
                }
                length += 7;
            }
            length += MinMatch;

            if (distance > outPos)
                throw new SmbWireFormatException("LZ77 distance before start of output.");
            if (outPos + length > output.Length)
                throw new SmbWireFormatException("LZ77 match overruns the declared original size.");

            int src = outPos - distance;
            for (int i = 0; i < length; i++)
                output[outPos + i] = output[src + i]; // byte-wise: overlapping copies are intentional
            outPos += length;
        }

        return output;
    }

    /// <summary>Compresses <paramref name="input"/> into a plain-LZ77 stream.</summary>
    public static byte[] Compress(ReadOnlySpan<byte> input)
    {
        var output = new GrowableWriter(input.Length);
        int flagSlot = -1;
        uint flags = 0;
        int flagCount = 0;

        void BeginGroup()
        {
            flagSlot = output.Position;
            output.WriteUInt32(0); // patched when the group fills or at the end
            flags = 0;
            flagCount = 32;
        }

        void PushFlag(bool isMatch)
        {
            flagCount--;
            if (isMatch) flags |= 1u << flagCount;
            if (flagCount == 0)
            {
                output.PatchUInt32(flagSlot, flags);
                flagSlot = -1;
            }
        }

        var matcher = new HashMatcher(input);
        int i = 0;
        while (i < input.Length)
        {
            if (flagCount == 0) BeginGroup();

            (int len, int distance) = matcher.FindMatch(i);
            if (len >= MinMatch)
            {
                PushFlag(true);
                WriteMatch(output, len, distance);
                matcher.Insert(i, len);
                i += len;
            }
            else
            {
                PushFlag(false);
                output.WriteByte(input[i]);
                matcher.Insert(i, 1);
                i++;
            }
        }

        // Patch a partially filled final flag group (unused low bits stay 0 = literal, never read
        // because the decompressor stops at the declared original size).
        if (flagSlot >= 0)
            output.PatchUInt32(flagSlot, flags);

        return output.ToArray();
    }

    private static void WriteMatch(GrowableWriter output, int length, int distance)
    {
        int len3 = length - MinMatch;
        ushort head = (ushort)((distance - 1) << 3);
        if (len3 < 7)
        {
            head |= (ushort)len3;
            output.WriteUInt16(head);
        }
        else
        {
            head |= 7;
            output.WriteUInt16(head);
            // MaxMatch guarantees the single-byte escape suffices (len3 - 7 ≤ 254).
            output.WriteByte((byte)(len3 - 7));
        }
    }

    /// <summary>
    /// Greedy 3-byte-hash-chain matcher over the 8 KiB window. Bounded chain walks keep compression
    /// O(n) for the payload sizes SMB compresses (a single READ/WRITE segment).
    /// </summary>
    private ref struct HashMatcher
    {
        private const int HashBits = 15;
        private const int HashSize = 1 << HashBits;
        private const int MaxChain = 32;

        private readonly ReadOnlySpan<byte> _data;
        private readonly int[] _head;
        private readonly int[] _prev;

        public HashMatcher(ReadOnlySpan<byte> data)
        {
            _data = data;
            _head = new int[HashSize];
            _prev = new int[data.Length];
            Array.Fill(_head, -1);
        }

        private static int Hash(ReadOnlySpan<byte> d, int pos)
        {
            // 3-byte hash.
            uint h = (uint)((d[pos] << 16) | (d[pos + 1] << 8) | d[pos + 2]);
            return (int)((h * 2654435761u) >> (32 - HashBits));
        }

        /// <summary>Inserts the positions covered by the token just emitted (length bytes from pos).</summary>
        public void Insert(int pos, int length)
        {
            int end = pos + length;
            for (int p = pos; p < end && p + 2 < _data.Length; p++)
            {
                int h = Hash(_data, p);
                _prev[p] = _head[h];
                _head[h] = p;
            }
        }

        public (int Length, int Distance) FindMatch(int pos)
        {
            if (pos + MinMatch > _data.Length)
                return (0, 0);

            int h = Hash(_data, pos);
            int candidate = _head[h];
            int minPos = Math.Max(0, pos - MaxDistance);
            int maxLen = Math.Min(MaxMatch, _data.Length - pos);

            int bestLen = 0;
            int bestDist = 0;
            int chain = MaxChain;
            while (candidate >= minPos && chain-- > 0)
            {
                int len = MatchLength(candidate, pos, maxLen);
                if (len > bestLen)
                {
                    bestLen = len;
                    bestDist = pos - candidate;
                    if (len >= maxLen) break;
                }
                candidate = _prev[candidate];
            }

            return bestLen >= MinMatch ? (bestLen, bestDist) : (0, 0);
        }

        private readonly int MatchLength(int a, int b, int maxLen)
        {
            int len = 0;
            while (len < maxLen && _data[a + len] == _data[b + len]) len++;
            return len;
        }
    }
}
