using System.Buffers.Binary;
using Smb.Auth;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Security;
using Smb.Server;
using Smb.Server.Quota;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 11 / M11.1 — disk quota. Covers the QUERY_QUOTA_INFO / FILE_QUOTA_INFORMATION wire, the
/// in-memory provider, the QUERY/SET_QUOTA dispatch, and per-owner write enforcement (over-limit →
/// STATUS_DISK_FULL).
/// </summary>
public class Phase11QuotaTests : IDisposable
{
    private readonly string _dir;

    public Phase11QuotaTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "smbquota_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllBytes(Path.Combine(_dir, "f.txt"), []);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { /* ignore */ }
    }

    private static readonly Sid Owner = Sid.Create(5, 21, 111, 222, 333, 1001);

    // ---- wire ----

    [Fact]
    public void QueryQuotaInfo_EmptyInput_MeansReturnAll()
    {
        QuotaMessage.QueryRequest req = QuotaMessage.ParseQueryInfo([]);
        Assert.Empty(req.SidFilter);
        Assert.False(req.ReturnSingle);
    }

    [Fact]
    public void QueryQuotaInfo_ParsesSidFilter()
    {
        Sid a = Sid.Create(5, 21, 1, 2, 3, 500);
        byte[] sidA = a.ToBytes();
        // Fixed 16-byte header (returnSingle=1) + one FILE_GET_QUOTA_INFORMATION (next=0, sidLen, sid).
        var input = new byte[16 + 8 + sidA.Length];
        input[0] = 1; // ReturnSingle
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(4, 4), (uint)(8 + sidA.Length)); // SidListLength
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(16, 4), 0); // NextEntryOffset
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(20, 4), (uint)sidA.Length); // SidLength
        sidA.CopyTo(input.AsSpan(24));

        QuotaMessage.QueryRequest req = QuotaMessage.ParseQueryInfo(input);
        Assert.True(req.ReturnSingle);
        Assert.Equal(a, Assert.Single(req.SidFilter));
    }

    [Fact]
    public void QuotaInformation_RoundTrips()
    {
        FileQuotaInformation[] entries =
        [
            new(Sid.Create(5, 21, 1, 2, 3, 500), ChangeTime: 12345, QuotaUsed: 4096, QuotaThreshold: 8192, QuotaLimit: 16384),
            new(Sid.Create(5, 21, 1, 2, 3, 501), ChangeTime: 0, QuotaUsed: 0, QuotaThreshold: FileQuotaInformation.Unlimited, QuotaLimit: FileQuotaInformation.Unlimited),
        ];

        byte[] buffer = QuotaMessage.BuildQuotaInformation(entries, maxBytes: 4096);
        IReadOnlyList<FileQuotaInformation> parsed = QuotaMessage.ParseQuotaInformation(buffer);

        Assert.Equal(2, parsed.Count);
        Assert.Equal(entries[0], parsed[0]);
        Assert.Equal(entries[1], parsed[1]);
    }

    // ---- provider ----

    [Fact]
    public void InMemoryProvider_ReservesUntilLimit_ThenReleases()
    {
        var q = new InMemoryQuotaProvider();
        var share = new Share { Name = "Data", Type = ShareType.Disk };
        q.SetLimit("Data", Owner, limit: 100);

        Assert.True(q.TryReserve(share, Owner, 60));   // used 60
        Assert.False(q.TryReserve(share, Owner, 60));  // would be 120 > 100
        q.Release(share, Owner, 60);                    // back to 0
        Assert.True(q.TryReserve(share, Owner, 100));   // exactly the limit
    }

    [Fact]
    public void NullProvider_ReportsUnsupported_AndNeverLimits()
    {
        IQuotaProvider q = NullQuotaProvider.Instance;
        var share = new Share { Name = "Data", Type = ShareType.Disk };
        Assert.False(q.IsSupported);
        Assert.Equal(NtStatus.NotSupported, q.Set(share, []));
        Assert.True(q.TryReserve(share, Owner, long.MaxValue));
    }

    // ---- dispatcher ----

    [Fact]
    public void QueryQuota_UnsupportedProvider_ReturnsNotSupported()
    {
        var (d, _, conn) = NewServer(NullQuotaProvider.Instance);
        (ulong sid, uint tid, ulong p, ulong v) = OpenRoot(d, conn);
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryInfoRequest(
            10, sid, tid, p, v, (byte)InfoType.Quota, 0, 4096));
        Assert.Equal(NtStatus.NotSupported, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void QueryQuota_ReturnsSeededEntry()
    {
        var quota = new InMemoryQuotaProvider();
        quota.SetLimit("Data", Owner, limit: 16384, threshold: 8192);
        var (d, _, conn) = NewServer(quota);
        (ulong sid, uint tid, ulong p, ulong v) = OpenRoot(d, conn);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryInfoRequest(
            10, sid, tid, p, v, (byte)InfoType.Quota, 0, 4096));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);

        FileQuotaInformation entry = Assert.Single(ParseQuotaResponse(resp));
        Assert.Equal(Owner, entry.Sid);
        Assert.Equal(16384, entry.QuotaLimit);
        Assert.Equal(8192, entry.QuotaThreshold);
    }

    [Fact]
    public void SetQuota_UpdatesProvider()
    {
        var quota = new InMemoryQuotaProvider();
        var (d, _, conn) = NewServer(quota);
        (ulong sid, uint tid, ulong p, ulong v) = OpenRoot(d, conn);

        byte[] input = QuotaMessage.BuildQuotaInformation(
            [new FileQuotaInformation(Owner, ChangeTime: 0, QuotaUsed: 0, QuotaThreshold: 512, QuotaLimit: 1024)], 4096);
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            11, sid, tid, p, v, (byte)InfoType.Quota, 0, input));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);

        FileQuotaInformation entry = Assert.Single(quota.Query(new Share { Name = "Data" }, [Owner]));
        Assert.Equal(1024, entry.QuotaLimit);
        Assert.Equal(512, entry.QuotaThreshold);
    }

    [Fact]
    public void Write_ExceedingOwnerQuota_ReturnsDiskFull()
    {
        var quota = new InMemoryQuotaProvider();
        quota.SetLimit("Data", Owner, limit: 100);
        var (d, state, conn) = NewServer(quota);
        ulong sid = Handshake(d, conn);
        // Give the session a resolvable owner SID (dev auth is anonymous).
        state.SessionGlobalList[sid].Identity = new SecurityIdentity { UserName = "quotauser", DomainName = "WORKGROUP", UserSid = Owner.ToString() };
        uint tid = TreeConnect(d, conn, sid, @"\\server\Data");
        (ulong p, ulong v) = Create(d, conn, sid, tid, "f.txt", write: true);

        // First 50 bytes fit (used 50 ≤ 100).
        byte[] ok = d.ProcessMessage(conn, TestHelpers.BuildWriteRequest(20, sid, tid, p, v, 0, new byte[50]));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(ok).Status);

        // Next 60 bytes would push usage to 110 > 100 → DISK_FULL.
        byte[] full = d.ProcessMessage(conn, TestHelpers.BuildWriteRequest(21, sid, tid, p, v, 50, new byte[60]));
        Assert.Equal(NtStatus.DiskFull, Smb2Header.Read(full).Status);
    }

    // ---- harness ----

    private (Smb2Dispatcher d, SmbServerState state, SmbConnection conn) NewServer(IQuotaProvider quota)
    {
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new DevSpnegoNegotiator(),
            RequireMessageSigning = false,
            AllowAnonymousAccess = true,
            MaxDialect = SmbDialect.Smb311,
            QuotaProvider = quota,
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Data", Type = ShareType.Disk, FileStore = new LocalFileStore(_dir, readOnly: false) });
        var state = new SmbServerState(options);
        return (new Smb2Dispatcher(state), state, new SmbConnection());
    }

    private static ulong Handshake(Smb2Dispatcher d, SmbConnection conn)
    {
        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        byte[] ss = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
        return Smb2Header.Read(ss).SessionId;
    }

    private static uint TreeConnect(Smb2Dispatcher d, SmbConnection conn, ulong sid, string unc)
        => Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(2, sid, unc))).TreeId;

    private static (ulong Persistent, ulong Volatile) Create(
        Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, string name, bool write)
    {
        uint access = write ? 0x00000003u : 0x00000001u; // FILE_READ_DATA (+ FILE_WRITE_DATA)
        uint options = name.Length == 0 ? (uint)CreateOptions.DirectoryFile : (uint)CreateOptions.NonDirectoryFile;
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            3, sid, tid, name, access, (uint)CreateDisposition.Open, options));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8)));
    }

    private (ulong sid, uint tid, ulong p, ulong v) OpenRoot(Smb2Dispatcher d, SmbConnection conn)
    {
        ulong sid = Handshake(d, conn);
        uint tid = TreeConnect(d, conn, sid, @"\\server\Data");
        (ulong p, ulong v) = Create(d, conn, sid, tid, "", write: false);
        return (sid, tid, p, v);
    }

    private static IReadOnlyList<FileQuotaInformation> ParseQuotaResponse(byte[] resp)
    {
        int body = Smb2Header.Size;
        int outputOffset = BinaryPrimitives.ReadUInt16LittleEndian(resp.AsSpan(body + 2, 2));
        int outputLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(body + 4, 4));
        return QuotaMessage.ParseQuotaInformation(resp.AsSpan(outputOffset, outputLength));
    }
}
