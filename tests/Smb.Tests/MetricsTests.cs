using System.Buffers.Binary;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Diagnostics;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 8 / M8.5 — health &amp; performance metrics. Verifies the counters/gauges increment on real
/// operations over the dispatcher and that the latency histogram produces sane percentiles.
/// </summary>
public class MetricsTests : IDisposable
{
    private const uint ReadWrite = 0x00000003;

    private readonly string _dir;
    private ulong _mid = 10;

    private ulong NextMid() => _mid++;

    public MetricsTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "smbmetrics_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void Histogram_Percentiles_AreMonotonicAndBucketed()
    {
        var m = new SmbServerMetrics();
        for (int i = 0; i < 95; i++) m.OnRequestCompleted(1);    // fast
        for (int i = 0; i < 5; i++) m.OnRequestCompleted(400);   // slow tail

        MetricsSnapshot s = m.Snapshot();
        Assert.Equal(100, s.RequestCount);
        Assert.True(s.RequestLatencyP50Ms <= s.RequestLatencyP95Ms);
        Assert.True(s.RequestLatencyP95Ms <= s.RequestLatencyP99Ms);
        Assert.Equal(1, s.RequestLatencyP50Ms);       // median in the ≤1ms bucket
        Assert.Equal(500, s.RequestLatencyP99Ms);     // tail lands in the ≤500ms bucket
    }

    [Fact]
    public void AuthCounters_Increment()
    {
        var (d, m) = Server();
        var conn = new SmbConnection();

        // Bad login → failure counter.
        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var bad = new NtlmClient("DOM", "alice", "WRONG");
        byte[] b1 = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, bad.BuildNegotiate()));
        d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, Smb2Header.Read(b1).SessionId,
            bad.BuildAuthenticate(ExtractSecurityBuffer(b1))));

        Assert.Equal(1, m.AuthenticationFailures);
        Assert.Equal(0, m.AuthenticationSuccesses);

        // Good login → success counter + active session.
        Login(d);
        Assert.Equal(1, m.AuthenticationSuccesses);
        Assert.Equal(1, m.ActiveSessions);
    }

    [Fact]
    public void HandleAndByteCounters_Track_Read_And_Write()
    {
        var (d, m) = Server();
        var (conn, sid, tid) = Login(d);
        File.WriteAllBytes(Path.Combine(_dir, "f.bin"), new byte[64]);

        Assert.Equal(0, m.OpenHandles);
        Assert.Equal(1, m.ActiveTreeConnects);

        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            NextMid(), sid, tid, "f.bin", ReadWrite, (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        const int body = Smb2Header.Size;
        ulong p = BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8));
        ulong v = BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8));
        Assert.Equal(1, m.OpenHandles);

        d.ProcessMessage(conn, TestHelpers.BuildWriteRequest(NextMid(), sid, tid, p, v, 0, new byte[16]));
        d.ProcessMessage(conn, TestHelpers.BuildReadRequest(NextMid(), sid, tid, p, v, 16, 0)); // length, offset

        Assert.Equal(16, m.BytesWritten);
        Assert.Equal(16, m.BytesRead);
        Assert.Equal((16L, 16L), m.BytesForShare("Files"));

        d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(NextMid(), sid, tid, p, v));
        Assert.Equal(0, m.OpenHandles);
        Assert.True(m.RequestCount > 0);
    }

    // --- helpers ---

    private (Smb2Dispatcher d, SmbServerMetrics m) Server()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var metrics = new SmbServerMetrics();
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
            Metrics = metrics,
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_dir, readOnly: false) });
        return (new Smb2Dispatcher(new SmbServerState(options)), metrics);
    }

    private (SmbConnection conn, ulong sid, uint tid) Login(Smb2Dispatcher d)
    {
        var conn = new SmbConnection();
        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sid = Smb2Header.Read(r1).SessionId;
        d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sid, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        uint tid = Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(3, sid, @"\\s\Files"))).TreeId;
        _mid = 10;
        return (conn, sid, tid);
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }
}
