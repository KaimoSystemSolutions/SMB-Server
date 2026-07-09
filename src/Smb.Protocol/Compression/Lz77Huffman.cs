using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Compression;

/// <summary>
/// LZ77 + Huffman, a.k.a. Xpress Huffman (MS-XCA §2.1–2.2), used by SMB2 compression
/// (<see cref="Smb.Protocol.Enums.SmbCompressionAlgorithm.Lz77Huffman"/>).
/// <para>
/// <b>This build implements the decoder only.</b> The output is a series of ≤64&#160;KiB blocks; each
/// block is a 256-byte Huffman table (512 symbols, one 4-bit canonical code length per symbol — symbol
/// <c>2i</c> in the low nibble of byte <c>i</c>, symbol <c>2i+1</c> in the high nibble) followed by a
/// Huffman-coded LZ77 bitstream read in 16-bit little-endian units through a 32-bit register. Symbols
/// 0–255 are literals; 256–511 encode a match — <c>(symbol-256) mod 16</c> is the length code (15 =
/// escape to extra bytes), <c>(symbol-256) / 16</c> is the number of offset bits that follow; the
/// minimum match is 3. Extra length bytes are spliced into the byte stream at the reader's current
/// position (interleaved with the bitstream words), exactly as MS-XCA specifies.
/// </para>
/// Decoding lets the server accept LZ77+Huffman frames produced by Windows. A spec-conformant
/// <b>encoder</b> (the interleaved length bytes + end-of-block flush must be byte-exact, validated
/// against a live Windows decoder) is a documented follow-up; until then the server advertises
/// LZ77+Huffman only to <i>receive</i> it and never produces it (see <see cref="SmbCompressor"/>).
/// </summary>
public static class Lz77Huffman
{
    /// <summary>Minimum encodable match length (§2.2).</summary>
    public const int MinMatch = 3;

    /// <summary>Decompressed bytes per Huffman block (§2.2).</summary>
    public const int BlockSize = 65536;

    private const int TableSize = 256;   // bytes of code-length nibbles per block
    private const int SymbolCount = 512;
    private const int MaxCodeBits = 15;
    private const int DecodeTableSize = 1 << MaxCodeBits;

    /// <summary>
    /// Decompresses an LZ77+Huffman stream into an output buffer of the exact expected size (carried
    /// out-of-band by the SMB compression transform header).
    /// </summary>
    /// <exception cref="SmbWireFormatException">On a truncated or malformed stream.</exception>
    public static byte[] Decompress(ReadOnlySpan<byte> input, int originalSize)
    {
        if (originalSize < 0)
            throw new SmbWireFormatException("Negative original size.");

        var output = new byte[originalSize];
        var codeLengths = new byte[SymbolCount];
        var decodeTable = new short[DecodeTableSize];

        int outPos = 0;
        int tablePos = 0; // byte offset of the current block's Huffman table

        while (outPos < originalSize)
        {
            if (tablePos + TableSize > input.Length)
                throw new SmbWireFormatException("Truncated LZ77+Huffman Huffman table.");

            BuildDecodeTable(input.Slice(tablePos, TableSize), codeLengths, decodeTable);
            var reader = new BitReader(input, tablePos + TableSize);
            reader.StartBlock();

            int blockEnd = outPos + BlockSize; // block boundaries follow the block's start position (§2.2)
            while (outPos < blockEnd && outPos < originalSize)
            {
                int symbol = reader.DecodeSymbol(decodeTable, codeLengths);
                if (symbol < 256)
                {
                    output[outPos++] = (byte)symbol;
                    continue;
                }

                symbol -= 256;
                int length = symbol & 0x0F;
                int offsetBits = symbol >> 4;

                if (length == 15)
                {
                    int extra = reader.ReadByte();
                    if (extra == 255)
                    {
                        int wide = reader.ReadUInt16();
                        if (wide < 15)
                            throw new SmbWireFormatException("Invalid LZ77+Huffman extended length.");
                        length = wide - 15;
                    }
                    else
                    {
                        length = extra;
                    }
                    length += 15;
                }
                length += MinMatch;

                int distance = (int)(reader.TakeBits(offsetBits) + (1u << offsetBits));
                if (distance > outPos)
                    throw new SmbWireFormatException("LZ77+Huffman back-reference before start of output.");
                if (outPos + length > originalSize)
                    throw new SmbWireFormatException("LZ77+Huffman match overruns declared size.");

                int src = outPos - distance;
                for (int i = 0; i < length; i++)
                    output[outPos + i] = output[src + i]; // byte-wise: overlapping copies are intentional
                outPos += length;
            }

            // The next block's 256-byte table follows block N's bitstream, which the encoder pads to a
            // whole number of 16-bit words. The reader keeps a 16-bit look-ahead, so its raw byte pointer
            // has over-read past that boundary; back out the fully-buffered (unconsumed) whole words so
            // the next table is located exactly. Without this, multi-block (>64 KiB) frames desync.
            tablePos = reader.NextTablePosition;
        }

        return output;
    }

    /// <summary>
    /// Builds the canonical Huffman decoding table (§2.2): symbols are ordered by (bit length, symbol
    /// value); a symbol of bit length X occupies <c>2^(15-X)</c> consecutive table entries.
    /// </summary>
    private static void BuildDecodeTable(ReadOnlySpan<byte> table, byte[] codeLengths, short[] decodeTable)
    {
        for (int i = 0; i < TableSize; i++)
        {
            codeLengths[2 * i] = (byte)(table[i] & 0x0F);
            codeLengths[2 * i + 1] = (byte)(table[i] >> 4);
        }

        int entry = 0;
        for (int bitLength = 1; bitLength <= MaxCodeBits; bitLength++)
        {
            int count = 1 << (MaxCodeBits - bitLength);
            for (int symbol = 0; symbol < SymbolCount; symbol++)
            {
                if (codeLengths[symbol] != bitLength)
                    continue;
                if (entry + count > DecodeTableSize)
                    throw new SmbWireFormatException("Over-subscribed LZ77+Huffman code table.");
                decodeTable.AsSpan(entry, count).Fill((short)symbol);
                entry += count;
            }
        }

        if (entry != DecodeTableSize)
            throw new SmbWireFormatException("Incomplete LZ77+Huffman code table.");
    }

    /// <summary>
    /// The MS-XCA bit reader (§2.2): a 32-bit register fed 16 bits at a time from a monotonic byte
    /// pointer. Extra match-length bytes are read from that same pointer, interleaved with the words.
    /// </summary>
    private ref struct BitReader
    {
        private readonly ReadOnlySpan<byte> _input;
        private int _pos;
        private uint _nextBits;
        private int _extraBitCount;

        public BitReader(ReadOnlySpan<byte> input, int start)
        {
            _input = input;
            _pos = start;
            _nextBits = 0;
            _extraBitCount = 0;
        }

        public readonly int Position => _pos;

        /// <summary>
        /// Byte offset where the next block's Huffman table begins: the raw pointer minus the fully
        /// buffered, unconsumed whole 16-bit words (the look-ahead the reader over-read past the current
        /// block's word-aligned bitstream). Unconsumed bits = 16 + <see cref="_extraBitCount"/>.
        /// </summary>
        public readonly int NextTablePosition => _pos - 2 * ((16 + _extraBitCount) / 16);

        public void StartBlock()
        {
            _nextBits = (uint)ReadUInt16() << 16;
            _nextBits |= ReadUInt16();
            _extraBitCount = 16;
        }

        public ushort ReadUInt16()
        {
            if (_pos + 2 > _input.Length)
                throw new SmbWireFormatException("Truncated LZ77+Huffman bitstream.");
            ushort v = BinaryPrimitives.ReadUInt16LittleEndian(_input.Slice(_pos));
            _pos += 2;
            return v;
        }

        public byte ReadByte()
        {
            if (_pos >= _input.Length)
                throw new SmbWireFormatException("Truncated LZ77+Huffman length byte.");
            return _input[_pos++];
        }

        public int DecodeSymbol(short[] decodeTable, byte[] codeLengths)
        {
            int symbol = decodeTable[_nextBits >> (32 - MaxCodeBits)];
            Consume(codeLengths[symbol]);
            return symbol;
        }

        /// <summary>Consumes <paramref name="bits"/> offset bits and returns their value (0 for a 0-bit field).</summary>
        public uint TakeBits(int bits)
        {
            uint value = bits == 0 ? 0u : _nextBits >> (32 - bits);
            Consume(bits);
            return value;
        }

        private void Consume(int bits)
        {
            _nextBits <<= bits;
            _extraBitCount -= bits;
            if (_extraBitCount < 0)
            {
                _nextBits |= (uint)ReadUInt16() << (-_extraBitCount);
                _extraBitCount += 16;
            }
        }
    }
}
