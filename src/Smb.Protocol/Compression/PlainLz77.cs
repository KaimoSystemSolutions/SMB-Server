using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Compression;

/// <summary>
/// Plain LZ77 (MS-XCA §2.4), the byte-oriented LZ77 variant used by SMB2 compression
/// (<see cref="Smb.Protocol.Enums.SmbCompressionAlgorithm.Lz77"/>). A 32-bit flag group (read
/// little-endian, consumed MSB-first) tags each token as a literal (0) or a match (1); a match is a
/// 16-bit value splitting into a 13-bit distance-1 and a 3-bit length-3.
/// <para>
/// Lengths past the 3-bit field escalate through the MS-XCA escape chain, whose first stage is a
/// <b>shared half-byte</b>: the first long match writes a nibble byte and the <i>next</i> long match
/// reuses that byte's high nibble (<c>LastLengthHalfByte</c> in the spec pseudocode) — two long
/// matches share one byte. A nibble of 15 escalates to an extra byte (value <c>length-3-22</c>), a
/// byte of 255 to a u16 holding <c>length-3</c> directly, and a u16 of 0 to a u32. Getting this
/// nibble stage wrong is invisible to a symmetric round-trip test and fatal against Windows: the
/// real client tears down the connection on the malformed stream, which Explorer surfaces as
/// "unexpected network error" on any compressible response &gt; the compression threshold — the
/// 500-entry directory listing was the reproducer (see <c>WindowsInteropBattery</c>).
/// </para>
/// <para>
/// The window is 8 KiB (13-bit distance) and the minimum match is 3 bytes. The compressor caps a
/// single match at <see cref="MaxMatch"/> (264) bytes so its escape chain always terminates at the
/// single extra byte (264-3-22 = 239 &lt; 255); the decompressor handles the full chain for inbound
/// frames.
/// </para>
/// </summary>
public static class PlainLz77
{
    /// <summary>Minimum encodable match length.</summary>
    public const int MinMatch = 3;

    /// <summary>Maximum match length the compressor emits (nibble 15 + extra byte 239: 3+7+15+239).</summary>
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
        int lastLengthHalfBytePos = -1;   // §2.4.4 LastLengthHalfByte: shared nibble of the length escape

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
                // First stage of the escape chain: a half-byte shared between two long matches. The
                // first long match reads a fresh byte and uses its low nibble; the second uses the
                // high nibble of that same byte (§2.4.4 LastLengthHalfByte).
                if (lastLengthHalfBytePos < 0)
                {
                    if (inPos >= input.Length)
                        throw new SmbWireFormatException("Truncated LZ77 length nibble.");
                    lastLengthHalfBytePos = inPos;
                    length = input[inPos++] & 0xF;
                }
                else
                {
                    length = input[lastLengthHalfBytePos] >> 4;
                    lastLengthHalfBytePos = -1;
                }

                if (length == 15)
                {
                    if (inPos >= input.Length)
                        throw new SmbWireFormatException("Truncated LZ77 extended length.");
                    int extra = input[inPos++];
                    if (extra == 255)
                    {
                        if (inPos + 2 > input.Length)
                            throw new SmbWireFormatException("Truncated LZ77 extended length (u16).");
                        long wide = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(inPos));
                        inPos += 2;
                        if (wide == 0)
                        {
                            if (inPos + 4 > input.Length)
                                throw new SmbWireFormatException("Truncated LZ77 extended length (u32).");
                            wide = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(inPos));
                            inPos += 4;
                        }
                        // The u16/u32 stages carry length-3 directly (must cover at least the escapes below).
                        if (wide < 15 + 7 || wide > int.MaxValue - MinMatch)
                            throw new SmbWireFormatException("LZ77 extended length out of range.");
                        extra = (int)(wide - (15 + 7));
                    }
                    length = extra + 15;
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
        int nibbleSlot = -1;   // position of a length byte whose high nibble is still free (LastLengthHalfByte)
        byte nibbleLow = 0;    // the low nibble already written there, for the read-modify-write patch

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

        // Mirrors the decoder's LastLengthHalfByte: the first long match writes a fresh byte (low
        // nibble), the second long match patches that byte's high nibble instead of writing anything.
        void WriteMatch(int length, int distance)
        {
            int len3 = length - MinMatch;
            ushort head = (ushort)((distance - 1) << 3);
            if (len3 < 7)
            {
                head |= (ushort)len3;
                output.WriteUInt16(head);
                return;
            }

            head |= 7;
            output.WriteUInt16(head);

            int nibble = Math.Min(len3 - 7, 15);
            if (nibbleSlot < 0)
            {
                nibbleSlot = output.Position;
                nibbleLow = (byte)nibble;
                output.WriteByte(nibbleLow);
            }
            else
            {
                output.PatchByte(nibbleSlot, (byte)(nibbleLow | (nibble << 4)));
                nibbleSlot = -1;
            }

            // MaxMatch guarantees the single-byte second stage suffices (len3 - 7 - 15 ≤ 239 < 255).
            if (nibble == 15)
                output.WriteByte((byte)(len3 - 7 - 15));
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
                WriteMatch(len, distance);
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

        // End-of-stream marker. The Windows decompressor (RtlDecompressBufferEx, XPRESS — validated
        // 2026-07-16 against ntdll) is input-driven, not output-size-driven: it keeps consuming flag
        // bits past the last real token and terminates only when a MATCH flag (1) coincides with an
        // exhausted input. Unused flag bits must therefore be 1s — padding them with 0s makes the
        // decoder read a literal past the end and fail with STATUS_BAD_COMPRESSION_BUFFER, which the
        // SMB client turns into a dropped connection. A final group that filled exactly needs a fresh
        // all-1s group appended; Windows' own compressor emits exactly that.
        if (flagSlot >= 0)
            output.PatchUInt32(flagSlot, flags | ((1u << flagCount) - 1)); // flagCount is 1..31 here
        else
            output.WriteUInt32(0xFFFFFFFF);

        return output.ToArray();
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
