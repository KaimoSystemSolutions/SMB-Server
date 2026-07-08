using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// DFS referral request/response wire structures (MS-DFSC §2.2, Phase 7 / M7.1): the payload of
/// FSCTL_DFS_GET_REFERRALS / _EX. The wire layer is pure; the namespace resolution (path → targets)
/// lives behind the <c>IDfsNamespace</c> seam in <c>Smb.Server</c>.
/// </summary>
/// <remarks>
/// This builder emits <b>DFS_REFERRAL_V4</b> entries in the non-name-list format (§2.2.5.4) — the
/// form Windows uses for a link (or root) referral to storage targets. Per the spec the string
/// offsets in each entry are relative to the <b>start of that entry</b>, so the fixed entry headers
/// come first and a shared, de-duplicated string pool follows.
/// </remarks>
public static class DfsReferralMessage
{
    /// <summary>ReferralHeaderFlags (§2.2.4): the returned targets are referral (namespace) servers.</summary>
    public const uint HeaderFlagReferralServers = 0x00000001;

    /// <summary>ReferralHeaderFlags (§2.2.4): the returned targets are storage servers (the common case).</summary>
    public const uint HeaderFlagStorageServers = 0x00000002;

    /// <summary>ReferralHeaderFlags (§2.2.4): the client should fail back to a higher-priority target.</summary>
    public const uint HeaderFlagTargetFailback = 0x00000004;

    /// <summary>ServerType (§2.2.5.4): the referral is for a DFS link; the targets are not root targets.</summary>
    public const ushort ServerTypeLink = 0x0000;

    /// <summary>ServerType (§2.2.5.4): the targets are DFS root targets.</summary>
    public const ushort ServerTypeRoot = 0x0001;

    private const ushort ReferralVersion = 4;
    private const int ResponseHeaderSize = 8;   // PathConsumed(2) + NumberOfReferrals(2) + HeaderFlags(4)
    private const int EntrySize = 34;           // fixed V3/V4 non-name-list entry (offsets relative to entry start)

    /// <summary>A parsed DFS referral request (§2.2.2 / §2.2.3).</summary>
    public readonly record struct Request(ushort MaxReferralLevel, string RequestFileName);

    /// <summary>One target of a DFS referral response entry.</summary>
    public sealed class ReferralEntry
    {
        /// <summary>The namespace path being referred (the DFS link/root path, e.g. <c>\SERVER\Dfs\Link</c>).</summary>
        public required string DfsPath { get; init; }

        /// <summary>The UNC target the client should use instead (e.g. <c>\Server2\Share</c>).</summary>
        public required string TargetPath { get; init; }

        /// <summary>Referral lifetime in seconds — the client may cache the mapping for this long.</summary>
        public uint TimeToLive { get; init; } = 300;

        /// <summary><see cref="ServerTypeLink"/> (storage target, default) or <see cref="ServerTypeRoot"/>.</summary>
        public ushort ServerType { get; init; } = ServerTypeLink;
    }

    /// <summary>
    /// Parses REQ_GET_DFS_REFERRAL (§2.2.2): <c>MaxReferralLevel</c> (2 bytes) followed by a
    /// null-terminated UTF-16LE <c>RequestFileName</c>.
    /// </summary>
    public static Request ParseRequest(ReadOnlySpan<byte> input)
    {
        if (input.Length < 2)
            throw new SmbWireFormatException("REQ_GET_DFS_REFERRAL is shorter than 2 bytes.");
        var r = new SpanReader(input);
        ushort maxLevel = r.ReadUInt16();
        return new Request(maxLevel, ReadUnicodeZ(input[2..]));
    }

    /// <summary>
    /// Parses REQ_GET_DFS_REFERRAL_EX (§2.2.3): <c>MaxReferralLevel</c> (2), <c>RequestFlags</c> (2),
    /// <c>RequestDataLength</c> (4), then RequestData = <c>RequestFileNameLength</c> (2) +
    /// <c>RequestFileName</c> (UTF-16LE, that many bytes). A trailing SiteName block, if present, is ignored.
    /// </summary>
    public static Request ParseRequestEx(ReadOnlySpan<byte> input)
    {
        if (input.Length < 10)
            throw new SmbWireFormatException("REQ_GET_DFS_REFERRAL_EX is shorter than 10 bytes.");
        var r = new SpanReader(input);
        ushort maxLevel = r.ReadUInt16();
        r.ReadUInt16();             // RequestFlags
        r.ReadUInt32();             // RequestDataLength
        ushort nameLen = r.ReadUInt16();  // RequestFileNameLength (start of RequestData)
        if (10 + nameLen > input.Length)
            throw new SmbWireFormatException("REQ_GET_DFS_REFERRAL_EX RequestFileName extends past the buffer.");
        string name = nameLen == 0
            ? string.Empty
            : System.Text.Encoding.Unicode.GetString(input.Slice(10, nameLen)).TrimEnd('\0');
        return new Request(maxLevel, name);
    }

    /// <summary>
    /// Serializes RESP_GET_DFS_REFERRAL (§2.2.4) with V4 referral entries.
    /// </summary>
    /// <param name="pathConsumedBytes">Number of bytes of the request <c>RequestFileName</c> the
    /// referral covers (the client appends the unconsumed remainder to the chosen target).</param>
    /// <param name="headerFlags">ReferralHeaderFlags (<see cref="HeaderFlagStorageServers"/> etc.).</param>
    /// <param name="entries">One entry per target; each carries its DFS path and its target UNC path.</param>
    public static byte[] BuildResponse(ushort pathConsumedBytes, uint headerFlags, IReadOnlyList<ReferralEntry> entries)
    {
        int n = entries.Count;
        int poolStart = ResponseHeaderSize + n * EntrySize;

        // De-duplicated string pool (UTF-16LE, null-terminated). Offsets are local to the pool.
        var pool = new List<byte>();
        var interned = new Dictionary<string, int>(StringComparer.Ordinal);
        int Intern(string s)
        {
            if (interned.TryGetValue(s, out int existing))
                return existing;
            int local = pool.Count;
            interned[s] = local;
            pool.AddRange(System.Text.Encoding.Unicode.GetBytes(s));
            pool.Add(0);
            pool.Add(0);
            return local;
        }

        var dfsPool = new int[n];
        var netPool = new int[n];
        for (int i = 0; i < n; i++)
        {
            dfsPool[i] = Intern(entries[i].DfsPath);
            netPool[i] = Intern(entries[i].TargetPath);
        }

        byte[] buf = new byte[poolStart + pool.Count];
        var w = new SpanWriter(buf);
        w.WriteUInt16(pathConsumedBytes);
        w.WriteUInt16((ushort)n);
        w.WriteUInt32(headerFlags);

        for (int i = 0; i < n; i++)
        {
            int entryStart = ResponseHeaderSize + i * EntrySize;
            // The DFS alternate path is the same as the DFS path (no legacy 8.3 name).
            int dfsRel = poolStart + dfsPool[i] - entryStart;
            int netRel = poolStart + netPool[i] - entryStart;

            var e = new SpanWriter(buf.AsSpan(entryStart, EntrySize));
            e.WriteUInt16(ReferralVersion);         // VersionNumber
            e.WriteUInt16(EntrySize);               // Size
            e.WriteUInt16(entries[i].ServerType);   // ServerType
            e.WriteUInt16(0);                       // ReferralEntryFlags
            e.WriteUInt32(entries[i].TimeToLive);   // TimeToLive
            e.WriteUInt16((ushort)dfsRel);          // DFSPathOffset
            e.WriteUInt16((ushort)dfsRel);          // DFSAlternatePathOffset (== DFS path)
            e.WriteUInt16((ushort)netRel);          // NetworkAddressOffset
            // ServiceSiteGuid (16 bytes) left zero.
        }

        pool.CopyTo(buf, poolStart);
        return buf;
    }

    /// <summary>Reads a null-terminated UTF-16LE string from the start of <paramref name="s"/>.</summary>
    private static string ReadUnicodeZ(ReadOnlySpan<byte> s)
    {
        int len = 0;
        while (len + 1 < s.Length && !(s[len] == 0 && s[len + 1] == 0))
            len += 2;
        return len == 0 ? string.Empty : System.Text.Encoding.Unicode.GetString(s[..len]);
    }
}
