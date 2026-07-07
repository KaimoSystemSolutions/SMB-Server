using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// Additional file-system-control codes and their input/output structures (MS-FSCC §2.3,
/// Phase 5 / M5.2): sparse-file control, zeroing ranges, querying allocated extents, reparse
/// points and DFS referrals. The wire layer is pure; the semantics live behind optional
/// <c>IFileStore</c> seams.
/// </summary>
public static class FsctlMessage
{
    public const uint FsctlSetSparse = 0x000900C4;
    public const uint FsctlSetZeroData = 0x000980C8;
    public const uint FsctlQueryAllocatedRanges = 0x000940CF;
    public const uint FsctlGetReparsePoint = 0x000900A8;
    public const uint FsctlSetReparsePoint = 0x000900A4;
    public const uint FsctlDeleteReparsePoint = 0x000900AC;
    public const uint FsctlDfsGetReferrals = 0x00060194;
    public const uint FsctlDfsGetReferralsEx = 0x000601B0;

    /// <summary>A file byte range {offset, length} — FILE_ALLOCATED_RANGE_BUFFER (MS-FSCC §2.3.34/§2.3.35).</summary>
    public readonly record struct FileRange(long Offset, long Length);

    /// <summary>
    /// Parses the FSCTL_SET_SPARSE input (MS-FSCC §2.3.68): an optional single BOOLEAN. An empty
    /// input means "set sparse" (TRUE).
    /// </summary>
    public static bool ParseSetSparse(ReadOnlySpan<byte> input)
        => input.Length == 0 || input[0] != 0;

    /// <summary>Parses FILE_ZERO_DATA_INFORMATION (MS-FSCC §2.3.79): FileOffset + BeyondFinalZero.</summary>
    public static FileRange ParseZeroData(ReadOnlySpan<byte> input)
    {
        var r = new SpanReader(input);
        long start = r.ReadInt64();
        long beyondFinalZero = r.ReadInt64();
        if (beyondFinalZero < start)
            throw new SmbWireFormatException("FILE_ZERO_DATA_INFORMATION: BeyondFinalZero precedes FileOffset.");
        return new FileRange(start, beyondFinalZero - start);
    }

    /// <summary>Parses the FSCTL_QUERY_ALLOCATED_RANGES input (a single FILE_ALLOCATED_RANGE_BUFFER).</summary>
    public static FileRange ParseAllocatedRangeQuery(ReadOnlySpan<byte> input)
    {
        var r = new SpanReader(input);
        long offset = r.ReadInt64();
        long length = r.ReadInt64();
        return new FileRange(offset, length);
    }

    /// <summary>Serializes an array of FILE_ALLOCATED_RANGE_BUFFER (16 bytes each) as the FSCTL output.</summary>
    public static byte[] BuildAllocatedRanges(IReadOnlyList<FileRange> ranges)
    {
        var body = new byte[ranges.Count * 16];
        var w = new SpanWriter(body);
        foreach (FileRange range in ranges)
        {
            w.WriteUInt64((ulong)range.Offset);
            w.WriteUInt64((ulong)range.Length);
        }
        return body;
    }
}
