using System.Buffers.Binary;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Dfs;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 7 / M7.1 — DFS referrals. The pure wire layer (<see cref="DfsReferralMessage"/>), the
/// <see cref="StandaloneDfsNamespace"/> resolver, FSCTL_DFS_GET_REFERRALS over the dispatcher, and the
/// DFS flags/capability advertised at TREE_CONNECT / NEGOTIATE when a namespace is configured.
/// </summary>
public class DfsReferralTests : IDisposable
{
    private const uint ReadWrite = 0x00000003;

    private readonly string _dir;
    private ulong _mid = 10;

    private ulong NextMid() => _mid++;

    public DfsReferralTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "smbdfs_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { /* ignore */ }
    }

    // --- pure wire round-trips ---

    [Fact]
    public void ParseRequest_RoundTrip()
    {
        byte[] input = BuildReferralRequestInput(@"\SERVER\Dfs\Docs", maxLevel: 4);
        DfsReferralMessage.Request req = DfsReferralMessage.ParseRequest(input);
        Assert.Equal(4, req.MaxReferralLevel);
        Assert.Equal(@"\SERVER\Dfs\Docs", req.RequestFileName);
    }

    [Fact]
    public void ParseRequestEx_RoundTrip()
    {
        const string path = @"\SERVER\Dfs\Docs\sub";
        byte[] name = System.Text.Encoding.Unicode.GetBytes(path);
        byte[] input = new byte[10 + name.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(0, 2), 4);   // MaxReferralLevel
        BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(2, 2), 0);   // RequestFlags
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(4, 4), (uint)(2 + name.Length)); // RequestDataLength
        BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(8, 2), (ushort)name.Length);     // RequestFileNameLength
        name.CopyTo(input.AsSpan(10));

        DfsReferralMessage.Request req = DfsReferralMessage.ParseRequestEx(input);
        Assert.Equal(4, req.MaxReferralLevel);
        Assert.Equal(path, req.RequestFileName);
    }

    [Fact]
    public void BuildResponse_SingleTarget_ParsesBack()
    {
        var entries = new List<DfsReferralMessage.ReferralEntry>
        {
            new() { DfsPath = @"\SERVER\Dfs\Docs", TargetPath = @"\FileBox\Docs", TimeToLive = 600 },
        };
        ushort pathConsumed = (ushort)(@"\SERVER\Dfs\Docs".Length * 2);
        byte[] resp = DfsReferralMessage.BuildResponse(pathConsumed, DfsReferralMessage.HeaderFlagStorageServers, entries);

        var (consumed, flags, parsed) = ParseReferralResponse(resp);
        Assert.Equal(pathConsumed, consumed);
        Assert.Equal(DfsReferralMessage.HeaderFlagStorageServers, flags);
        (string dfsPath, string target, ushort serverType, uint ttl) = Assert.Single(parsed);
        Assert.Equal(@"\SERVER\Dfs\Docs", dfsPath);
        Assert.Equal(@"\FileBox\Docs", target);
        Assert.Equal(DfsReferralMessage.ServerTypeLink, serverType);
        Assert.Equal(600u, ttl);
    }

    [Fact]
    public void BuildResponse_MultipleTargets_ShareDfsPath()
    {
        var entries = new List<DfsReferralMessage.ReferralEntry>
        {
            new() { DfsPath = @"\SERVER\Dfs\Docs", TargetPath = @"\NodeA\Docs" },
            new() { DfsPath = @"\SERVER\Dfs\Docs", TargetPath = @"\NodeB\Docs" },
        };
        byte[] resp = DfsReferralMessage.BuildResponse(30, DfsReferralMessage.HeaderFlagStorageServers, entries);

        var (_, _, parsed) = ParseReferralResponse(resp);
        Assert.Equal(2, parsed.Count);
        Assert.Equal(@"\NodeA\Docs", parsed[0].target);
        Assert.Equal(@"\NodeB\Docs", parsed[1].target);
        Assert.All(parsed, e => Assert.Equal(@"\SERVER\Dfs\Docs", e.dfsPath));
    }

    // --- StandaloneDfsNamespace ---

    [Fact]
    public void Standalone_ResolvesLongestPrefix_AndSubPath()
    {
        var ns = new StandaloneDfsNamespace()
            .AddLink(@"\SERVER\Dfs\Docs", @"\FileBox\Docs")
            .AddLink(@"\SERVER\Dfs\Docs\Archive", @"\ColdStore\Archive");

        DfsReferralResult? sub = ns.Resolve(@"\SERVER\Dfs\Docs\report.txt");
        Assert.NotNull(sub);
        Assert.Equal(@"\SERVER\Dfs\Docs", sub!.ConsumedPath);
        Assert.Equal(@"\FileBox\Docs", Assert.Single(sub.Targets).TargetPath);

        // The longer link wins for a path under it.
        DfsReferralResult? archive = ns.Resolve(@"\SERVER\Dfs\Docs\Archive\old.txt");
        Assert.Equal(@"\SERVER\Dfs\Docs\Archive", archive!.ConsumedPath);
        Assert.Equal(@"\ColdStore\Archive", Assert.Single(archive.Targets).TargetPath);
    }

    [Fact]
    public void Standalone_UnknownPath_ReturnsNull()
    {
        var ns = new StandaloneDfsNamespace().AddLink(@"\SERVER\Dfs\Docs", @"\FileBox\Docs");
        Assert.Null(ns.Resolve(@"\SERVER\Other\Thing"));
        // A prefix that is not on a component boundary must not match.
        Assert.Null(ns.Resolve(@"\SERVER\Dfs\DocsExtra"));
    }

    // --- dispatcher: FSCTL_DFS_GET_REFERRALS ---

    [Fact]
    public void DfsGetReferrals_WithNamespace_ReturnsTargets()
    {
        var ns = new StandaloneDfsNamespace().AddLink(@"\SERVER\Dfs\Docs", @"\FileBox\Docs", @"\FileBox2\Docs");
        var (d, conn, sid, tid) = Setup(ns, dfsShare: true);

        byte[] input = BuildReferralRequestInput(@"\SERVER\Dfs\Docs\report.txt");
        byte[] resp = Ioctl(d, conn, sid, tid, 0, 0, FsctlMessage.FsctlDfsGetReferrals, input);

        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        var (consumed, flags, parsed) = ParseReferralResponse(IoctlOutput(resp));
        Assert.Equal((ushort)(@"\SERVER\Dfs\Docs".Length * 2), consumed);
        Assert.Equal(DfsReferralMessage.HeaderFlagStorageServers, flags);
        Assert.Equal(2, parsed.Count);
        Assert.Equal(@"\FileBox\Docs", parsed[0].target);
        Assert.Equal(@"\FileBox2\Docs", parsed[1].target);
    }

    [Fact]
    public void DfsGetReferrals_PathOutsideNamespace_NotFound()
    {
        var ns = new StandaloneDfsNamespace().AddLink(@"\SERVER\Dfs\Docs", @"\FileBox\Docs");
        var (d, conn, sid, tid) = Setup(ns, dfsShare: true);

        byte[] input = BuildReferralRequestInput(@"\SERVER\Nope\x");
        byte[] resp = Ioctl(d, conn, sid, tid, 0, 0, FsctlMessage.FsctlDfsGetReferrals, input);

        Assert.Equal(NtStatus.NotFound, Smb2Header.Read(resp).Status);
    }

    // --- M7.2: DFS link resolution on CREATE ---

    [Fact]
    public void Create_UnderDfsLink_ReturnsPathNotCovered()
    {
        var ns = new StandaloneDfsNamespace().AddLink(@"\SRV\Files\Docs", @"\FileBox\Docs");
        var (d, conn, sid, tid) = Setup(ns, dfsShare: true);

        Assert.Equal(NtStatus.PathNotCovered, Create(d, conn, sid, tid, @"Docs\report.txt"));
    }

    [Fact]
    public void Create_AtDfsRoot_NotCovered_ServedLocally()
    {
        var ns = new StandaloneDfsNamespace().AddLink(@"\SRV\Files\Docs", @"\FileBox\Docs");
        var (d, conn, sid, tid) = Setup(ns, dfsShare: true);
        File.WriteAllBytes(Path.Combine(_dir, "readme.txt"), new byte[4]);

        // A file that sits directly in the DFS root (not under any link) is opened locally.
        Assert.Equal(NtStatus.Success, Create(d, conn, sid, tid, "readme.txt"));
    }

    [Fact]
    public void Create_OnNonDfsShare_LinkPathServedLocally()
    {
        var ns = new StandaloneDfsNamespace().AddLink(@"\SRV\Files\Docs", @"\FileBox\Docs");
        var (d, conn, sid, tid) = Setup(ns, dfsShare: false);

        // A plain (non-DFS) share ignores the namespace entirely: the path is resolved locally and only
        // fails because the file is absent — never with PATH_NOT_COVERED.
        Assert.NotEqual(NtStatus.PathNotCovered, Create(d, conn, sid, tid, @"Docs\report.txt"));
    }

    // --- TREE_CONNECT / NEGOTIATE advertise DFS ---

    [Fact]
    public void TreeConnect_DfsShare_AdvertisesDfsFlagsAndCapability()
    {
        var ns = new StandaloneDfsNamespace().AddLink(@"\SERVER\Dfs\Docs", @"\FileBox\Docs");
        var (_, _, _, _, treeResp) = SetupWithTreeResponse(ns, dfsShare: true);

        const int body = Smb2Header.Size;
        var shareFlags = (ShareFlags)BinaryPrimitives.ReadUInt32LittleEndian(treeResp.AsSpan(body + 4, 4));
        var caps = (ShareCapabilities)BinaryPrimitives.ReadUInt32LittleEndian(treeResp.AsSpan(body + 8, 4));

        Assert.True(shareFlags.HasFlag(ShareFlags.Dfs));
        Assert.True(shareFlags.HasFlag(ShareFlags.DfsRoot));
        Assert.True(caps.HasFlag(ShareCapabilities.Dfs));
    }

    [Fact]
    public void TreeConnect_PlainShare_NoDfsFlags()
    {
        var ns = new StandaloneDfsNamespace().AddLink(@"\SERVER\Dfs\Docs", @"\FileBox\Docs");
        var (_, _, _, _, treeResp) = SetupWithTreeResponse(ns, dfsShare: false);

        const int body = Smb2Header.Size;
        var shareFlags = (ShareFlags)BinaryPrimitives.ReadUInt32LittleEndian(treeResp.AsSpan(body + 4, 4));
        var caps = (ShareCapabilities)BinaryPrimitives.ReadUInt32LittleEndian(treeResp.AsSpan(body + 8, 4));

        Assert.False(shareFlags.HasFlag(ShareFlags.Dfs));
        Assert.False(caps.HasFlag(ShareCapabilities.Dfs));
    }

    [Fact]
    public void Negotiate_AdvertisesDfsCapability_OnlyWhenNamespaceConfigured()
    {
        Assert.True(NegotiateCapabilities(withNamespace: true).HasFlag(Smb2Capabilities.Dfs));
        Assert.False(NegotiateCapabilities(withNamespace: false).HasFlag(Smb2Capabilities.Dfs));
    }

    // --- helpers ---

    private static Smb2Capabilities NegotiateCapabilities(bool withNamespace)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
            DfsNamespace = withNamespace ? new StandaloneDfsNamespace().AddLink(@"\S\Dfs\L", @"\T\S") : null,
        };
        options.Shares.Add(Share.CreateIpc());
        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        byte[] resp = dispatcher.ProcessMessage(new SmbConnection(), TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        return (Smb2Capabilities)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 24, 4));
    }

    private byte[] Ioctl(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong p, ulong v, uint ctlCode, byte[] input)
        => d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(NextMid(), sid, tid, p, v, ctlCode, input));

    private NtStatus Create(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, string name)
    {
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            NextMid(), sid, tid, name, ReadWrite, (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile));
        return Smb2Header.Read(resp).Status;
    }

    private static byte[] IoctlOutput(byte[] resp)
    {
        int outputOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 32, 4));
        int outputCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 36, 4));
        return outputCount == 0 ? [] : resp.AsSpan(outputOffset, outputCount).ToArray();
    }

    private static byte[] BuildReferralRequestInput(string path, ushort maxLevel = 4)
    {
        byte[] name = System.Text.Encoding.Unicode.GetBytes(path);
        byte[] input = new byte[2 + name.Length + 2];
        BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(0, 2), maxLevel);
        name.CopyTo(input.AsSpan(2));
        // trailing UTF-16 null terminator (last two bytes stay zero)
        return input;
    }

    /// <summary>Parses RESP_GET_DFS_REFERRAL (V4 entries) back into targets for assertions.</summary>
    private static (ushort pathConsumed, uint headerFlags, List<(string dfsPath, string target, ushort serverType, uint ttl)> entries)
        ParseReferralResponse(byte[] output)
    {
        ushort pathConsumed = BinaryPrimitives.ReadUInt16LittleEndian(output.AsSpan(0, 2));
        ushort count = BinaryPrimitives.ReadUInt16LittleEndian(output.AsSpan(2, 2));
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(4, 4));

        var list = new List<(string, string, ushort, uint)>();
        const int entrySize = 34;
        for (int i = 0; i < count; i++)
        {
            int entryStart = 8 + i * entrySize;
            ushort serverType = BinaryPrimitives.ReadUInt16LittleEndian(output.AsSpan(entryStart + 4, 2));
            uint ttl = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(entryStart + 8, 4));
            ushort dfsOff = BinaryPrimitives.ReadUInt16LittleEndian(output.AsSpan(entryStart + 12, 2));
            ushort netOff = BinaryPrimitives.ReadUInt16LittleEndian(output.AsSpan(entryStart + 16, 2));
            string dfsPath = ReadUnicodeZ(output, entryStart + dfsOff);
            string target = ReadUnicodeZ(output, entryStart + netOff);
            list.Add((dfsPath, target, serverType, ttl));
        }
        return (pathConsumed, flags, list);
    }

    private static string ReadUnicodeZ(byte[] buf, int start)
    {
        int len = 0;
        while (start + len + 1 < buf.Length && !(buf[start + len] == 0 && buf[start + len + 1] == 0))
            len += 2;
        return System.Text.Encoding.Unicode.GetString(buf, start, len);
    }

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(IDfsNamespace ns, bool dfsShare)
    {
        var (d, conn, sid, tid, _) = SetupWithTreeResponse(ns, dfsShare);
        return (d, conn, sid, tid);
    }

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, byte[] treeResp) SetupWithTreeResponse(IDfsNamespace ns, bool dfsShare)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            ServerName = "SRV",
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
            DfsNamespace = ns,
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share
        {
            Name = "Files",
            Type = ShareType.Disk,
            FileStore = new LocalFileStore(_dir, readOnly: false),
            IsDfs = dfsShare,
        });

        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();

        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        byte[] treeResp = dispatcher.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\s\Files"));
        uint treeId = Smb2Header.Read(treeResp).TreeId;
        return (dispatcher, conn, sessionId, treeId, treeResp);
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }
}
