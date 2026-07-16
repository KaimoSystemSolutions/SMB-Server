using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Smb.Protocol.Compression;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Cross-validates our MS-XCA codecs against the <b>real Windows implementation</b>
/// (<c>ntdll!RtlCompressBuffer</c> / <c>RtlDecompressBufferEx</c>) — the code the SMB client and
/// server drivers use. A symmetric round-trip through our own encoder+decoder proves only internal
/// consistency; the LZ77 wire-format regression (full length byte instead of the shared half-byte,
/// 0-padded instead of 1-padded flag groups) passed every round-trip test and still broke every real
/// Windows client on compressible traffic. These tests make ntdll the referee:
/// <list type="bullet">
///   <item>everything our encoder emits must decompress correctly via ntdll, and</item>
///   <item>everything ntdll emits must decompress correctly via our decoder.</item>
/// </list>
/// Skipped off-Windows (no ntdll); on Windows they always run — no server, no port, no admin needed.
/// </summary>
public class WindowsCodecCrossValidationTests
{
    private const ushort FormatLznt1 = 0x0002;   // COMPRESSION_FORMAT_LZNT1
    private const ushort FormatXpress = 0x0103;  // COMPRESSION_FORMAT_XPRESS = MS-XCA plain LZ77

    public static TheoryData<string> Payloads() => new()
    {
        "tiny",                      // smallest input Windows' XPRESS encoder accepts (8 bytes)
        "single-long-run",           // one long overlapping match (nibble + extra byte escapes)
        "abc-repeat",                // the shared-half-byte case: two+ long matches
        "text",                      // mixed literals and matches
        "random",                    // incompressible → literal-heavy, exact flag-group edges
        "exactly-32-tokens",         // flag group filled exactly → terminator group required
        "binary-listing",            // synthetic QUERY_DIRECTORY-ish payload (the Explorer reproducer)
    };

    private static byte[] Payload(string name) => name switch
    {
        // RtlCompressBuffer(XPRESS) rejects inputs under 8 bytes with STATUS_BUFFER_TOO_SMALL
        // (measured 2026-07-16); SMB never compresses frames that small anyway (CompressionMinSize).
        "tiny" => "abcabcab"u8.ToArray(),
        "single-long-run" => Enumerable.Repeat((byte)'x', 500).ToArray(),
        "abc-repeat" => Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("abc", 200))),
        "text" => Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("The quick brown fox jumps over the lazy dog. ", 150))),
        "random" => RandomBytes(8192),
        "exactly-32-tokens" => Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(),
        "binary-listing" => SyntheticDirectoryListing(),
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private static byte[] RandomBytes(int n)
    {
        var rng = new Random(20260716); // deterministic — failures must reproduce
        var data = new byte[n];
        rng.NextBytes(data);
        return data;
    }

    /// <summary>Mimics the payload shape that broke Explorer: many similar UTF-16 file names.</summary>
    private static byte[] SyntheticDirectoryListing()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 500; i++) sb.Append($"file-{i:D4}.txt");
        return Encoding.Unicode.GetBytes(sb.ToString());
    }

    [SkippableTheory]
    [MemberData(nameof(Payloads))]
    public void Lz77_OurEncoder_DecodesWithWindows(string payloadName)
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "ntdll cross-validation needs Windows");
        byte[] data = Payload(payloadName);

        byte[] ours = PlainLz77.Compress(data);
        byte[] viaWindows = NtdllDecompress(FormatXpress, ours, data.Length);

        Assert.Equal(data, viaWindows);
    }

    [SkippableTheory]
    [MemberData(nameof(Payloads))]
    public void Lz77_WindowsEncoder_DecodesWithOurDecoder(string payloadName)
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "ntdll cross-validation needs Windows");
        byte[] data = Payload(payloadName);

        byte[] windows = NtdllCompress(FormatXpress, data);
        byte[] viaOurs = PlainLz77.Decompress(windows, data.Length);

        Assert.Equal(data, viaOurs);
    }

    [SkippableTheory]
    [MemberData(nameof(Payloads))]
    public void Lznt1_OurEncoder_DecodesWithWindows(string payloadName)
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "ntdll cross-validation needs Windows");
        byte[] data = Payload(payloadName);

        byte[] ours = Lznt1.Compress(data);
        byte[] viaWindows = NtdllDecompress(FormatLznt1, ours, data.Length);

        Assert.Equal(data, viaWindows);
    }

    [SkippableTheory]
    [MemberData(nameof(Payloads))]
    public void Lznt1_WindowsEncoder_DecodesWithOurDecoder(string payloadName)
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "ntdll cross-validation needs Windows");
        byte[] data = Payload(payloadName);

        byte[] windows = NtdllCompress(FormatLznt1, data);
        byte[] viaOurs = Lznt1.Decompress(windows, data.Length);

        Assert.Equal(data, viaOurs);
    }

    // ─── ntdll plumbing ───────────────────────────────────────────────────

    private static byte[] NtdllCompress(ushort format, byte[] data)
    {
        Check(RtlGetCompressionWorkSpaceSize(format, out uint bufWs, out _), "RtlGetCompressionWorkSpaceSize");
        IntPtr ws = Marshal.AllocHGlobal((int)bufWs);
        try
        {
            // RtlCompressBuffer can grow small/incompressible inputs; size generously.
            var dst = new byte[data.Length * 2 + 256];
            Check(RtlCompressBuffer(format, data, (uint)data.Length, dst, (uint)dst.Length, 4096, out uint written, ws),
                "RtlCompressBuffer");
            return dst[..(int)written];
        }
        finally
        {
            Marshal.FreeHGlobal(ws);
        }
    }

    private static byte[] NtdllDecompress(ushort format, byte[] compressed, int originalSize)
    {
        Check(RtlGetCompressionWorkSpaceSize(format, out uint bufWs, out _), "RtlGetCompressionWorkSpaceSize");
        IntPtr ws = Marshal.AllocHGlobal((int)bufWs);
        try
        {
            var dst = new byte[originalSize];
            Check(RtlDecompressBufferEx(format, dst, (uint)dst.Length, compressed, (uint)compressed.Length, out uint written, ws),
                "RtlDecompressBufferEx");
            Assert.Equal(originalSize, (int)written);
            return dst;
        }
        finally
        {
            Marshal.FreeHGlobal(ws);
        }
    }

    private static void Check(int ntStatus, string what)
    {
        // 0xC0000242 = STATUS_BAD_COMPRESSION_BUFFER: Windows rejected the stream — exactly the
        // failure the SMB client turns into a torn connection ("unexpected network error").
        Assert.True(ntStatus == 0, $"{what} failed with NTSTATUS 0x{ntStatus:X8}");
    }

    [DllImport("ntdll.dll")]
    private static extern int RtlGetCompressionWorkSpaceSize(ushort format, out uint bufferWorkSpaceSize, out uint fragmentWorkSpaceSize);

    [DllImport("ntdll.dll")]
    private static extern int RtlCompressBuffer(ushort format, byte[] source, uint sourceLength,
        byte[] destination, uint destinationLength, uint chunkSize, out uint finalSize, IntPtr workSpace);

    [DllImport("ntdll.dll")]
    private static extern int RtlDecompressBufferEx(ushort format, byte[] destination, uint destinationLength,
        byte[] source, uint sourceLength, out uint finalSize, IntPtr workSpace);
}
