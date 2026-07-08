using Smb.Protocol.Security;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// One FILE_QUOTA_INFORMATION record (MS-FSCC §2.4.33): the disk-quota state for a single owner SID.
/// <see cref="QuotaThreshold"/> / <see cref="QuotaLimit"/> use <see cref="Unlimited"/> (-1) to mean
/// "no limit". Times/sizes are in the usual SMB units (FILETIME / bytes).
/// </summary>
public readonly record struct FileQuotaInformation(
    Sid Sid, long ChangeTime, long QuotaUsed, long QuotaThreshold, long QuotaLimit)
{
    /// <summary>Sentinel (0xFFFFFFFFFFFFFFFF) for "no threshold / no limit".</summary>
    public const long Unlimited = -1L;
}

/// <summary>
/// SMB2 QUERY_QUOTA_INFO / SET_QUOTA_INFO wire structures (MS-SMB2 §2.2.37.1 request input,
/// MS-FSCC §2.4.33 FILE_QUOTA_INFORMATION list). Pure serialization; the quota semantics live behind
/// the <c>IQuotaProvider</c> seam in <c>Smb.Server.Quota</c>.
/// </summary>
public static class QuotaMessage
{
    /// <summary>Fixed part of a FILE_QUOTA_INFORMATION entry (before the variable SID).</summary>
    public const int EntryFixedSize = 40; // NextEntryOffset(4)+SidLength(4)+ChangeTime(8)+Used(8)+Threshold(8)+Limit(8)

    /// <summary>Parsed SMB2_QUERY_QUOTA_INFO request input (§2.2.37.1).</summary>
    public readonly record struct QueryRequest(bool ReturnSingle, bool RestartScan, IReadOnlyList<Sid> SidFilter);

    /// <summary>
    /// Parses the QUERY_INFO input buffer for an <c>InfoType.Quota</c> request (§2.2.37.1). An empty or
    /// too-short buffer, or one with no SID list, yields an empty filter (= "return all").
    /// </summary>
    public static QueryRequest ParseQueryInfo(ReadOnlySpan<byte> input)
    {
        if (input.Length < 16)
            return new QueryRequest(false, false, []);

        var r = new SpanReader(input);
        bool returnSingle = r.ReadByte() != 0;
        bool restartScan = r.ReadByte() != 0;
        r.Skip(2); // Reserved
        uint sidListLength = r.ReadUInt32();
        uint startSidLength = r.ReadUInt32();
        uint startSidOffset = r.ReadUInt32();

        var sids = new List<Sid>();
        if (sidListLength > 0)
        {
            // A chain of FILE_GET_QUOTA_INFORMATION (NextEntryOffset(4) ‖ SidLength(4) ‖ Sid), starting at
            // the end of the fixed 16-byte header.
            int pos = 16;
            long end = Math.Min(input.Length, 16L + sidListLength);
            while (pos + 8 <= end)
            {
                uint next = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(pos, 4));
                uint sidLen = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(pos + 4, 4));
                if (sidLen > 0 && pos + 8 + sidLen <= input.Length)
                    sids.Add(Sid.Parse(input.Slice(pos + 8, (int)sidLen)));
                if (next == 0) break;
                pos += (int)next;
            }
        }
        else if (startSidLength > 0 && startSidOffset + startSidLength <= (uint)input.Length)
        {
            sids.Add(Sid.Parse(input.Slice((int)startSidOffset, (int)startSidLength)));
        }

        return new QueryRequest(returnSingle, restartScan, sids);
    }

    /// <summary>
    /// Serializes a FILE_QUOTA_INFORMATION list (MS-FSCC §2.4.33), 8-byte aligned between entries and
    /// capped to <paramref name="maxBytes"/> (entries that do not fit are dropped). Returns the buffer.
    /// </summary>
    public static byte[] BuildQuotaInformation(IReadOnlyList<FileQuotaInformation> entries, int maxBytes)
    {
        var w = new GrowableWriter(Math.Min(256, Math.Max(16, maxBytes)));
        int lastEntryStart = -1;

        foreach (FileQuotaInformation e in entries)
        {
            byte[] sid = e.Sid.ToBytes();
            int entryLen = EntryFixedSize + sid.Length;
            int padded = Align8(entryLen);
            if (w.Position + padded > maxBytes)
                break;

            int start = w.Position;
            w.WriteUInt32(0);                 // NextEntryOffset (patched once the next entry is known)
            w.WriteUInt32((uint)sid.Length);  // SidLength
            w.WriteUInt64((ulong)e.ChangeTime);
            w.WriteUInt64((ulong)e.QuotaUsed);
            w.WriteUInt64((ulong)e.QuotaThreshold);
            w.WriteUInt64((ulong)e.QuotaLimit);
            w.WriteBytes(sid);
            while (w.Position < start + padded) w.WriteByte(0); // 8-byte alignment padding

            if (lastEntryStart >= 0)
                w.PatchUInt32(lastEntryStart, (uint)(start - lastEntryStart));
            lastEntryStart = start;
        }

        return w.ToArray(); // last NextEntryOffset stays 0 (end of list)
    }

    /// <summary>Parses a FILE_QUOTA_INFORMATION list (the SET_QUOTA_INFO input buffer).</summary>
    public static IReadOnlyList<FileQuotaInformation> ParseQuotaInformation(ReadOnlySpan<byte> buffer)
    {
        var result = new List<FileQuotaInformation>();
        int pos = 0;
        while (pos + EntryFixedSize <= buffer.Length)
        {
            var r = new SpanReader(buffer[pos..]);
            uint next = r.ReadUInt32();
            uint sidLen = r.ReadUInt32();
            long changeTime = r.ReadInt64();
            long used = r.ReadInt64();
            long threshold = r.ReadInt64();
            long limit = r.ReadInt64();
            if (sidLen == 0 || pos + EntryFixedSize + sidLen > buffer.Length)
                break;
            Sid sid = Sid.Parse(buffer.Slice(pos + EntryFixedSize, (int)sidLen));
            result.Add(new FileQuotaInformation(sid, changeTime, used, threshold, limit));

            if (next == 0) break;
            pos += (int)next;
        }
        return result;
    }

    private static int Align8(int value) => (value + 7) & ~7;
}
