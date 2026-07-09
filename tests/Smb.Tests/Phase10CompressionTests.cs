using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Smb.Auth;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Host;
using Smb.Protocol.Compression;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Smb.Protocol.Wire;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 10 / M10.3 — SMB2 compression. Covers the Plain LZ77 codec (MS-XCA §2.4), the
/// SMB2_COMPRESSION_TRANSFORM_HEADER framing (unchained + chained decode incl. Pattern_V1),
/// the orchestrator's threshold behavior, negotiation, and the host compressing/decoding on the wire.
/// </summary>
public class Phase10CompressionTests
{
    // ---- Plain LZ77 codec ----

    [Fact]
    public void Lz77_RoundTrips_AndShrinks_CompressibleData()
    {
        byte[] data = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("The quick brown fox jumps. ", 400)));
        byte[] compressed = PlainLz77.Compress(data);
        Assert.True(compressed.Length < data.Length, "Repetitive text must compress.");
        Assert.Equal(data, PlainLz77.Decompress(compressed, data.Length));
    }

    [Fact]
    public void Lz77_RoundTrips_LongRun_ExercisesMaxMatchAndOverlap()
    {
        var data = new byte[40_000];
        Array.Fill(data, (byte)0xAB); // one long run > MaxMatch (264) and highly overlapping
        byte[] compressed = PlainLz77.Compress(data);
        Assert.True(compressed.Length < data.Length / 10);
        Assert.Equal(data, PlainLz77.Decompress(compressed, data.Length));
    }

    [Fact]
    public void Lz77_RoundTrips_RandomData_WithoutCorruption()
    {
        byte[] data = RandomNumberGenerator.GetBytes(9000);
        byte[] compressed = PlainLz77.Compress(data);
        Assert.Equal(data, PlainLz77.Decompress(compressed, data.Length));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(9)]   // last length in the 3-bit field
    [InlineData(10)]  // first single-extra-byte length
    [InlineData(265)] // just past the single-byte escape range
    public void Lz77_RoundTrips_EdgeSizes(int size)
    {
        var data = new byte[size];
        for (int i = 0; i < size; i++) data[i] = (byte)(i % 7); // short, repeating → exercises matches
        byte[] compressed = PlainLz77.Compress(data);
        Assert.Equal(data, PlainLz77.Decompress(compressed, size));
    }

    // ---- LZNT1 codec ----

    [Fact]
    public void Lznt1_RoundTrips_AndShrinks_CompressibleData()
    {
        byte[] data = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("The quick brown fox jumps. ", 400)));
        byte[] compressed = Lznt1.Compress(data);
        Assert.True(compressed.Length < data.Length, "Repetitive text must compress.");
        Assert.Equal(data, Lznt1.Decompress(compressed, data.Length));
    }

    [Fact]
    public void Lznt1_RoundTrips_LongRun_ExercisesOverlapAcrossChunks()
    {
        var data = new byte[40_000]; // spans multiple 4096-byte chunks
        Array.Fill(data, (byte)0xAB);
        byte[] compressed = Lznt1.Compress(data);
        Assert.True(compressed.Length < data.Length / 5);
        Assert.Equal(data, Lznt1.Decompress(compressed, data.Length));
    }

    [Fact]
    public void Lznt1_RoundTrips_RandomData_WithoutCorruption()
    {
        byte[] data = RandomNumberGenerator.GetBytes(9000);
        byte[] compressed = Lznt1.Compress(data);
        Assert.Equal(data, Lznt1.Decompress(compressed, data.Length));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(16)]    // last position at the initial 12/4 split
    [InlineData(17)]    // first position after the split shifts
    [InlineData(4096)]  // exactly one chunk
    [InlineData(4097)]  // one chunk + 1 byte
    [InlineData(8500)]  // multiple chunks
    public void Lznt1_RoundTrips_EdgeSizes(int size)
    {
        var data = new byte[size];
        for (int i = 0; i < size; i++) data[i] = (byte)(i % 7); // short, repeating → exercises matches
        byte[] compressed = Lznt1.Compress(data);
        Assert.Equal(data, Lznt1.Decompress(compressed, size));
    }

    [Fact]
    public void Lznt1_CompressedChunkHeader_HasSignatureAndCompressedFlag()
    {
        byte[] data = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("abcabcabc", 200)));
        byte[] compressed = Lznt1.Compress(data);
        ushort header = BinaryPrimitives.ReadUInt16LittleEndian(compressed);
        Assert.Equal(0x3000, header & 0x7000);            // signature bits 14–12 == 0b011
        Assert.NotEqual(0, header & 0x8000);              // compressible payload → compressed flag set
    }

    [Fact]
    public void Lznt1_DecodesHandBuiltUncompressedChunk()
    {
        // Header: signature (0x3000), compressed flag clear, size-1 in low 12 bits.
        byte[] payload = Encoding.ASCII.GetBytes("HELLO");
        var frame = new byte[2 + payload.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(frame, (ushort)(0x3000 | (payload.Length - 1)));
        payload.CopyTo(frame, 2);
        Assert.Equal(payload, Lznt1.Decompress(frame, payload.Length));
    }

    [Fact]
    public void Lznt1_DecodesHandBuiltCompressedChunk_WithBackReference()
    {
        // Spec-derived byte vector, independent of our own encoder: "ABCABC" as one compressed chunk.
        // Flag byte (LSB-first): A,B,C are literals (bits 0–2 clear), the 4th token is a back-reference
        // (bit 3 set) -> 0x08. At chunk output length 3 the split is 12 length / 4 displacement bits, so
        // the 16-bit match token = ((distance-1) << 12) | (length-3) = (2 << 12) | 0 = 0x2000.
        byte[] frame =
        [
            0x05, 0xB0,                   // header: compressed(0x8000) | signature(0x3000) | (size-1=5)
            0x08,                         // flag byte: only the 4th token is a match
            0x41, 0x42, 0x43,             // literals 'A','B','C'
            0x00, 0x20,                   // match token 0x2000 (distance 3, length 3), little-endian
        ];
        Assert.Equal(Encoding.ASCII.GetBytes("ABCABC"), Lznt1.Decompress(frame, originalSize: 6));
    }

    [Fact]
    public void Lznt1_ThroughOrchestrator_RoundTripsAsCompressionFrame()
    {
        byte[] message = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("lznt1 payload row. ", 500)));
        byte[]? frame = SmbCompressor.TryCompressUnchained(SmbCompressionAlgorithm.Lznt1, message, minSize: 256);
        Assert.NotNull(frame);
        Assert.True(SmbProtocolIds.IsCompression(frame));
        Assert.Equal(message, SmbCompressor.Decompress(frame!));
    }

    // ---- LZ77+Huffman codec (decode-only, MS-XCA §2.2) ----

    // A hand-built, spec-derived LZ77+Huffman block for "ABABAB" — independent of any encoder, so it
    // validates the decoder against MS-XCA directly. Four symbols, all Huffman code length 2, so the
    // canonical codes (ordered by symbol value) are: 'A'(65)=00, 'B'(66)=01, EOS(256)=10, match(273)=11.
    // Stream: A, B, match(offset=2,length=4). Match symbol 273 = 256 + offsetBits(1)*16 + lengthCode(1).
    private static byte[] BuildHuffmanAbababPayload()
    {
        var payload = new byte[256 + 4];
        // 256-byte code-length table: symbol 2i in the low nibble of byte i, symbol 2i+1 in the high nibble.
        payload[32] = 0x20;  // symbol 65 ('A') -> high nibble -> bit length 2
        payload[33] = 0x02;  // symbol 66 ('B') -> low nibble  -> bit length 2
        payload[128] = 0x02; // symbol 256 (EOS) -> low nibble -> bit length 2
        payload[136] = 0x20; // symbol 273 (match) -> high nibble -> bit length 2
        // Bitstream, MSB-first: 00 (A) 01 (B) 11 (match) 0 (offset extra bit) -> word0 = 0x1C00; word1 = pad.
        payload[256] = 0x00; payload[257] = 0x1C; // word0 little-endian
        payload[258] = 0x00; payload[259] = 0x00; // word1 (lookahead padding)
        return payload;
    }

    [Fact]
    public void Lz77Huffman_DecodesHandBuiltFrame_LiteralsAndOverlappingMatch()
    {
        byte[] decoded = Lz77Huffman.Decompress(BuildHuffmanAbababPayload(), originalSize: 6);
        Assert.Equal(Encoding.ASCII.GetBytes("ABABAB"), decoded);
    }

    [Fact]
    public void Lz77Huffman_ThroughOrchestrator_DecodesUnchainedFrame()
    {
        byte[] payload = BuildHuffmanAbababPayload();
        var frame = new byte[CompressionTransformHeader.UnchainedSize + payload.Length];
        new CompressionTransformHeader
        {
            OriginalCompressedSegmentSize = 6,
            CompressionAlgorithm = SmbCompressionAlgorithm.Lz77Huffman,
            Flags = SmbCompressionFlags.None,
            Offset = 0,
        }.WriteUnchained(frame);
        payload.CopyTo(frame, CompressionTransformHeader.UnchainedSize);

        Assert.Equal(Encoding.ASCII.GetBytes("ABABAB"), SmbCompressor.Decompress(frame));
    }

    // A spec-derived TWO-block LZ77+Huffman frame that exercises the block boundary (>64 KiB output).
    // Both blocks use a two-symbol, all-length-1 Huffman table (a complete canonical tree): the code's
    // single bit selects between the two symbols MSB-first. Block 1 emits 65536 'A's from an all-zero
    // bitstream; block 2 uses a fresh 'C'/'D' table and the bits 0,1,0,1 to emit "CDCD". If the decoder
    // mislocates block 2's table (the 16-bit read-ahead over-reads past block 1's word-aligned
    // bitstream), block 2's table is garbage and decoding throws or corrupts — so this pins the fix.
    private static byte[] BuildHuffmanTwoBlockPayload()
    {
        const int block1Bitstream = 65536 / 8; // 65536 one-bit symbols = 8192 bytes, all zero -> all 'A'
        var frame = new byte[256 + block1Bitstream + 256 + 4];

        // Block 1 table: 'A'(65) and 'B'(66), both code length 1. Symbol 2i is the low nibble of byte i,
        // 2i+1 the high nibble. 65 = 2*32+1 -> high nibble of byte 32; 66 = 2*33 -> low nibble of byte 33.
        frame[32] = 0x10;
        frame[33] = 0x01;
        // Block 1 bitstream is already all-zero -> every 1-bit symbol decodes to 'A'.

        int b2Table = 256 + block1Bitstream;
        // Block 2 table: 'C'(67) and 'D'(68), both length 1. 67 = 2*33+1 -> high nibble of byte 33;
        // 68 = 2*34 -> low nibble of byte 34 (offsets relative to the block-2 table start).
        frame[b2Table + 33] = 0x10;
        frame[b2Table + 34] = 0x01;
        // Block 2 bitstream: symbols C,D,C,D = bits 0,1,0,1 (MSB-first) = 0x5000 in the first 16-bit word.
        int b2Stream = b2Table + 256;
        frame[b2Stream] = 0x00; frame[b2Stream + 1] = 0x50; // word0 = 0x5000, little-endian
        frame[b2Stream + 2] = 0x00; frame[b2Stream + 3] = 0x00; // word1 (look-ahead padding)
        return frame;
    }

    [Fact]
    public void Lz77Huffman_DecodesMultiBlockFrame_AcrossTheBlockBoundary()
    {
        byte[] decoded = Lz77Huffman.Decompress(BuildHuffmanTwoBlockPayload(), originalSize: 65536 + 4);

        var expected = new byte[65536 + 4];
        Array.Fill(expected, (byte)'A', 0, 65536);
        Encoding.ASCII.GetBytes("CDCD").CopyTo(expected, 65536);
        Assert.Equal(expected, decoded);
    }

    [Fact]
    public void Lz77Huffman_TruncatedTable_Throws()
        => Assert.Throws<SmbWireFormatException>(() => Lz77Huffman.Decompress(new byte[100], originalSize: 4));

    [Fact]
    public void Compressor_DoesNotProduceHuffman_ItIsDecodeOnly()
    {
        Assert.True(SmbCompressor.IsDecodable(SmbCompressionAlgorithm.Lz77Huffman));
        Assert.False(SmbCompressor.IsEncodable(SmbCompressionAlgorithm.Lz77Huffman));
        // TryCompress declines an algorithm it cannot encode rather than emitting a malformed frame.
        byte[] message = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("data ", 500)));
        Assert.Null(SmbCompressor.TryCompressUnchained(SmbCompressionAlgorithm.Lz77Huffman, message, minSize: 64));
    }

    // ---- Transform header wire ----

    [Fact]
    public void UnchainedHeader_RoundTrips()
    {
        var header = new CompressionTransformHeader
        {
            OriginalCompressedSegmentSize = 123456,
            CompressionAlgorithm = SmbCompressionAlgorithm.Lz77,
            Flags = SmbCompressionFlags.None,
            Offset = 64,
        };
        var buffer = new byte[CompressionTransformHeader.UnchainedSize];
        header.WriteUnchained(buffer);

        Assert.True(SmbProtocolIds.IsCompression(buffer));
        CompressionTransformHeader read = CompressionTransformHeader.ReadUnchained(buffer);
        Assert.Equal(123456u, read.OriginalCompressedSegmentSize);
        Assert.Equal(SmbCompressionAlgorithm.Lz77, read.CompressionAlgorithm);
        Assert.Equal(SmbCompressionFlags.None, read.Flags);
        Assert.Equal(64u, read.Offset);
    }

    // ---- Orchestrator ----

    [Fact]
    public void Compressor_Unchained_RoundTripsAndFramesAsCompression()
    {
        byte[] message = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("compress me please. ", 500)));
        byte[]? frame = SmbCompressor.TryCompressUnchained(SmbCompressionAlgorithm.Lz77, message, minSize: 256);

        Assert.NotNull(frame);
        Assert.True(SmbProtocolIds.IsCompression(frame));
        Assert.True(frame!.Length < message.Length);
        Assert.Equal(message, SmbCompressor.Decompress(frame));
    }

    [Fact]
    public void Compressor_ReturnsNull_BelowThreshold()
    {
        byte[] message = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("x", 4096)));
        Assert.Null(SmbCompressor.TryCompressUnchained(SmbCompressionAlgorithm.Lz77, message, minSize: 8192));
    }

    [Fact]
    public void Compressor_ReturnsNull_WhenIncompressible()
    {
        byte[] message = RandomNumberGenerator.GetBytes(4096);
        // Random data does not shrink under LZ77; the frame would not be smaller → no compression.
        Assert.Null(SmbCompressor.TryCompressUnchained(SmbCompressionAlgorithm.Lz77, message, minSize: 512));
    }

    [Fact]
    public void Compressor_DecodesChainedFrame_NonePatternAndLz77()
    {
        // Build a chained frame by hand: [None "AB"] ++ [Pattern_V1 0xCC ×5] ++ [Lz77 of "hello".repeat].
        byte[] none = Encoding.ASCII.GetBytes("AB");
        byte[] lz77Original = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("hello", 50)));
        byte[] lz77Compressed = PlainLz77.Compress(lz77Original);

        byte[] expected = [.. none, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, .. lz77Original];
        byte[] frame = BuildChainedFrame((uint)expected.Length,
        [
            (SmbCompressionAlgorithm.None, none),
            (SmbCompressionAlgorithm.PatternV1, PatternPayload(0xCC, 5)),
            (SmbCompressionAlgorithm.Lz77, Prefix32((uint)lz77Original.Length, lz77Compressed)),
        ]);

        Assert.Equal(expected, SmbCompressor.Decompress(frame));
    }

    // ---- Negotiation ----

    private static SmbServerOptions Options(bool enableCompression) => new()
    {
        ServerGuid = new byte[16],
        SpnegoNegotiator = new DevSpnegoNegotiator(),
        EnableCompression = enableCompression,
    };

    [Fact]
    public void Negotiate_PicksSupportedAlgorithmByServerPreference()
    {
        var conn = new SmbConnection();
        NegotiateRequest request = NegotiateRequest.Parse(
            TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311],
                compressionAlgs: [SmbCompressionAlgorithm.Lznt1, SmbCompressionAlgorithm.Lz77]),
            Smb2Header.Size);

        NegotiateResponse response = NegotiateProcessor.BuildResponse(conn, request, Options(enableCompression: true), []);

        Assert.Equal(SmbCompressionAlgorithm.Lz77, conn.CompressionAlgorithm);
        CompressionContext echoed = response.NegotiateContexts.OfType<CompressionContext>().Single();
        Assert.Equal(SmbCompressionAlgorithm.Lz77, Assert.Single(echoed.Algorithms));
    }

    [Fact]
    public void Negotiate_PicksLznt1_WhenServerPrefersIt()
    {
        var conn = new SmbConnection();
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new DevSpnegoNegotiator(),
            EnableCompression = true,
            CompressionPreference = [SmbCompressionAlgorithm.Lznt1, SmbCompressionAlgorithm.Lz77],
        };
        NegotiateRequest request = NegotiateRequest.Parse(
            TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311],
                compressionAlgs: [SmbCompressionAlgorithm.Lznt1, SmbCompressionAlgorithm.Lz77]),
            Smb2Header.Size);

        NegotiateResponse response = NegotiateProcessor.BuildResponse(conn, request, options, []);

        Assert.Equal(SmbCompressionAlgorithm.Lznt1, conn.CompressionAlgorithm);
        CompressionContext echoed = response.NegotiateContexts.OfType<CompressionContext>().Single();
        Assert.Equal(SmbCompressionAlgorithm.Lznt1, echoed.Algorithms[0]);
    }

    [Fact]
    public void Negotiate_AdvertisesDecodeOnlyHuffman_ButSendsEncodableAlgorithm()
    {
        var conn = new SmbConnection();
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new DevSpnegoNegotiator(),
            EnableCompression = true,
            CompressionPreference = [SmbCompressionAlgorithm.Lz77Huffman, SmbCompressionAlgorithm.Lz77],
        };
        NegotiateRequest request = NegotiateRequest.Parse(
            TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311],
                compressionAlgs: [SmbCompressionAlgorithm.Lz77Huffman, SmbCompressionAlgorithm.Lz77]),
            Smb2Header.Size);

        NegotiateResponse response = NegotiateProcessor.BuildResponse(conn, request, options, []);

        CompressionContext echoed = response.NegotiateContexts.OfType<CompressionContext>().Single();
        // Both are advertised (we can receive Huffman), Huffman first per preference ...
        Assert.Equal(SmbCompressionAlgorithm.Lz77Huffman, echoed.Algorithms[0]);
        Assert.Contains(SmbCompressionAlgorithm.Lz77, echoed.Algorithms);
        // ... but outbound falls back to the first algorithm we can actually produce.
        Assert.Equal(SmbCompressionAlgorithm.Lz77, conn.CompressionAlgorithm);
    }

    [Fact]
    public void Negotiate_Disabled_DoesNotAdvertiseCompression()
    {
        var conn = new SmbConnection();
        NegotiateRequest request = NegotiateRequest.Parse(
            TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311], compressionAlgs: [SmbCompressionAlgorithm.Lz77]),
            Smb2Header.Size);

        NegotiateResponse response = NegotiateProcessor.BuildResponse(conn, request, Options(enableCompression: false), []);

        Assert.Equal(SmbCompressionAlgorithm.None, conn.CompressionAlgorithm);
        Assert.Empty(response.NegotiateContexts.OfType<CompressionContext>());
    }

    [Fact]
    public void Negotiate_AllAlgorithmsUnsupported_NoAgreement()
    {
        var conn = new SmbConnection();
        NegotiateRequest request = NegotiateRequest.Parse(
            TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311],
                compressionAlgs: [SmbCompressionAlgorithm.Lznt1, SmbCompressionAlgorithm.Lz77Huffman]),
            Smb2Header.Size);

        NegotiateResponse response = NegotiateProcessor.BuildResponse(conn, request, Options(enableCompression: true), []);

        Assert.Equal(SmbCompressionAlgorithm.None, conn.CompressionAlgorithm);
        Assert.Empty(response.NegotiateContexts.OfType<CompressionContext>());
    }

    // ---- End-to-end over the host ----

    [Fact]
    public async Task Host_CompressesLargeReadResponse_AndClientCanDecode()
    {
        byte[] fileContent = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("compressible payload row. ", 200)));
        using var share = new TempShare(fileContent);

        await using SmbServer server = share.BuildServer(compression: true);
        await server.StartAsync();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, server.Endpoint.Port);
        await using NetworkStream stream = client.GetStream();

        ulong sid = await LoginAsync(stream, offerCompression: true);
        uint tid = await TreeConnectAsync(stream, sid, @"\\server\Data");
        (ulong p, ulong v) = await CreateAsync(stream, sid, tid, "big.txt");

        // READ the whole file: the response is large + compressible → host returns a compression frame.
        await SendFramed(stream, TestHelpers.BuildReadRequest(10, sid, tid, p, v, (uint)fileContent.Length, 0));
        byte[] readResp = await ReadFramed(stream);

        Assert.True(SmbProtocolIds.IsCompression(readResp), "Large compressible READ response must be compressed.");
        byte[] message = SmbCompressor.Decompress(readResp);
        Assert.True(SmbProtocolIds.IsSmb2(message));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(message).Status);
        Assert.Equal(fileContent, ExtractReadData(message));

        await server.StopAsync();
    }

    [Fact]
    public async Task Host_DoesNotCompress_WhenClientDidNotNegotiate()
    {
        byte[] fileContent = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("compressible payload row. ", 200)));
        using var share = new TempShare(fileContent);

        await using SmbServer server = share.BuildServer(compression: true);
        await server.StartAsync();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, server.Endpoint.Port);
        await using NetworkStream stream = client.GetStream();

        ulong sid = await LoginAsync(stream, offerCompression: false); // client offers no compression context
        uint tid = await TreeConnectAsync(stream, sid, @"\\server\Data");
        (ulong p, ulong v) = await CreateAsync(stream, sid, tid, "big.txt");

        await SendFramed(stream, TestHelpers.BuildReadRequest(10, sid, tid, p, v, (uint)fileContent.Length, 0));
        byte[] readResp = await ReadFramed(stream);

        Assert.False(SmbProtocolIds.IsCompression(readResp), "No compression negotiated → plain SMB2 response.");
        Assert.True(SmbProtocolIds.IsSmb2(readResp));
        Assert.Equal(fileContent, ExtractReadData(readResp));

        await server.StopAsync();
    }

    [Fact]
    public async Task Host_DecodesCompressedInboundRequest()
    {
        using var share = new TempShare([1, 2, 3]);
        await using SmbServer server = share.BuildServer(compression: true);
        await server.StartAsync();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, server.Endpoint.Port);
        await using NetworkStream stream = client.GetStream();

        await LoginAsync(stream, offerCompression: true);

        // Send an ECHO wrapped in a compression transform frame; the host must decompress and process it.
        byte[] echo = TestHelpers.BuildEchoRequest(5);
        byte[] frame = BuildUnchainedFrame(SmbCompressionAlgorithm.Lz77, echo);
        await SendFramed(stream, frame);
        byte[] resp = await ReadFramed(stream);

        byte[] message = SmbProtocolIds.IsCompression(resp) ? SmbCompressor.Decompress(resp) : resp;
        Smb2Header header = Smb2Header.Read(message);
        Assert.Equal(SmbCommand.Echo, header.Command);
        Assert.Equal(NtStatus.Success, header.Status);

        await server.StopAsync();
    }

    // ---- helpers ----

    private static byte[] ExtractReadData(byte[] message)
    {
        int body = Smb2Header.Size;
        int dataOffset = message[body + 2];
        int dataLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(body + 4, 4));
        return message.AsSpan(dataOffset, dataLength).ToArray();
    }

    private static byte[] BuildUnchainedFrame(SmbCompressionAlgorithm algorithm, byte[] message)
    {
        byte[] compressed = PlainLz77.Compress(message);
        var frame = new byte[CompressionTransformHeader.UnchainedSize + compressed.Length];
        new CompressionTransformHeader
        {
            OriginalCompressedSegmentSize = (uint)message.Length,
            CompressionAlgorithm = algorithm,
            Flags = SmbCompressionFlags.None,
            Offset = 0,
        }.WriteUnchained(frame);
        compressed.CopyTo(frame.AsSpan(CompressionTransformHeader.UnchainedSize));
        return frame;
    }

    private static byte[] BuildChainedFrame(uint totalSize, (SmbCompressionAlgorithm Alg, byte[] Data)[] links)
    {
        using var ms = new MemoryStream();
        ms.Write(SmbProtocolIds.Smb2Compression);
        Span<byte> u32 = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(u32, totalSize);
        ms.Write(u32);
        var hdr = new byte[CompressionPayloadHeader.Size];
        foreach ((SmbCompressionAlgorithm alg, byte[] data) in links)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(0, 2), (ushort)alg);
            // First link carries the CHAINED flag so Decompress selects the chained layout.
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(2, 2), (ushort)SmbCompressionFlags.Chained);
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.AsSpan(4, 4), (uint)data.Length);
            ms.Write(hdr);
            ms.Write(data);
        }
        return ms.ToArray();
    }

    private static byte[] PatternPayload(byte pattern, uint repetitions)
    {
        var payload = new byte[8];
        payload[0] = pattern;
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(4, 4), repetitions);
        return payload;
    }

    private static byte[] Prefix32(uint value, byte[] data)
    {
        var result = new byte[4 + data.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(result, value);
        data.CopyTo(result, 4);
        return result;
    }

    private static async Task<ulong> LoginAsync(NetworkStream stream, bool offerCompression)
    {
        await SendFramed(stream, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311],
            compressionAlgs: offerCompression ? [SmbCompressionAlgorithm.Lz77] : null));
        await ReadFramed(stream); // NEGOTIATE response
        await SendFramed(stream, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
        byte[] ss = await ReadFramed(stream);
        return Smb2Header.Read(ss).SessionId;
    }

    private static async Task<uint> TreeConnectAsync(NetworkStream stream, ulong sid, string unc)
    {
        await SendFramed(stream, TestHelpers.BuildTreeConnectRequest(2, sid, unc));
        byte[] tc = await ReadFramed(stream);
        Smb2Header h = Smb2Header.Read(tc);
        Assert.Equal(NtStatus.Success, h.Status);
        return h.TreeId;
    }

    private static async Task<(ulong Persistent, ulong Volatile)> CreateAsync(NetworkStream stream, ulong sid, uint tid, string name)
    {
        await SendFramed(stream, TestHelpers.BuildCreateRequest(3, sid, tid, name,
            desiredAccess: 0x00000001, disposition: (uint)CreateDisposition.Open,
            options: (uint)CreateOptions.NonDirectoryFile));
        byte[] create = await ReadFramed(stream);
        Smb2Header h = Smb2Header.Read(create);
        Assert.Equal(NtStatus.Success, h.Status);
        int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8)));
    }

    private static async Task SendFramed(NetworkStream stream, byte[] message)
    {
        await stream.WriteAsync(NbssFrame.Wrap(message));
        await stream.FlushAsync();
    }

    private static async Task<byte[]> ReadFramed(NetworkStream stream)
    {
        var prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix);
        var payload = new byte[NbssFrame.ReadLength(prefix)];
        await stream.ReadExactlyAsync(payload);
        return payload;
    }

    /// <summary>A temporary on-disk share directory holding a single "big.txt".</summary>
    private sealed class TempShare : IDisposable
    {
        private readonly string _dir;

        public TempShare(byte[] content)
        {
            _dir = Path.Combine(Path.GetTempPath(), "smbcomp_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_dir);
            File.WriteAllBytes(Path.Combine(_dir, "big.txt"), content);
        }

        public SmbServer BuildServer(bool compression)
        {
            SmbServerBuilder builder = SmbServerBuilder.Create()
                .WithEndpoint(IPAddress.Loopback, 0)
                .UseDevAuthentication()
                .AddShare(Share.CreateIpc())
                .AddShare(new Share { Name = "Data", Type = ShareType.Disk, FileStore = new LocalFileStore(_dir, readOnly: true) });
            if (compression) builder.UseCompression(minSize: 512);
            return builder.Build();
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, true); } catch { /* ignore */ }
        }
    }
}
