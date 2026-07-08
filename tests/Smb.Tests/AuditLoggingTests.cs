using System.Buffers.Binary;
using System.Collections.Concurrent;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Authorization;
using Smb.Server.Diagnostics;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 8 / M8.1 — structured audit logging. A capturing <see cref="ISmbAuditLogger"/> asserts that
/// the security-relevant events (authentication, share access, file open/close/delete, permission
/// change) are emitted with the expected type, user, share and path fields.
/// </summary>
public class AuditLoggingTests : IDisposable
{
    private const uint ReadWrite = 0x00000003;

    private readonly string _dir;
    private ulong _mid = 10;

    private ulong NextMid() => _mid++;

    public AuditLoggingTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "smbaudit_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void AuditEvent_ToString_RendersStructuredFields()
    {
        var evt = new SmbAuditEvent
        {
            EventType = SmbAuditEventType.ShareAccessDenied,
            Level = SmbLogLevel.Warning,
            Timestamp = DateTimeOffset.UnixEpoch,
            User = @"DOM\alice",
            ClientAddress = "10.0.0.5:5000",
            Share = "Secret",
            Status = NtStatus.AccessDenied,
        };
        string line = evt.ToString();
        Assert.Contains("5143 ShareAccessDenied", line);
        Assert.Contains(@"user=DOM\alice", line);
        Assert.Contains("share=Secret", line);
        Assert.Contains("status=AccessDenied", line);
    }

    [Fact]
    public void DelegatingLogger_RespectsMinLevel()
    {
        var seen = new List<SmbAuditEvent>();
        var logger = new DelegatingSmbAuditLogger(seen.Add, SmbLogLevel.Warning);
        Assert.False(logger.IsEnabled(SmbLogLevel.Information));
        Assert.True(logger.IsEnabled(SmbLogLevel.Warning));

        logger.Log(new SmbAuditEvent { EventType = SmbAuditEventType.FileOpened, Level = SmbLogLevel.Information });
        logger.Log(new SmbAuditEvent { EventType = SmbAuditEventType.AuthenticationFailed, Level = SmbLogLevel.Warning });
        SmbAuditEvent only = Assert.Single(seen);
        Assert.Equal(SmbAuditEventType.AuthenticationFailed, only.EventType);
    }

    [Fact]
    public void SuccessfulLogin_EmitsAuthenticationSucceeded()
    {
        var (log, _, _, _, _) = Login(out _);
        SmbAuditEvent evt = Assert.Single(log.Events, e => e.EventType == SmbAuditEventType.AuthenticationSucceeded);
        Assert.Equal(SmbLogLevel.Information, evt.Level);
        Assert.Contains("alice", evt.User);
    }

    [Fact]
    public void BadPassword_EmitsAuthenticationFailed()
    {
        var log = new CapturingAuditLogger();
        var (d, conn) = Server(log, null);

        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "WRONG");
        byte[] r1 = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));

        Assert.Contains(log.Events, e => e.EventType == SmbAuditEventType.AuthenticationFailed);
        Assert.DoesNotContain(log.Events, e => e.EventType == SmbAuditEventType.AuthenticationSucceeded);
    }

    [Fact]
    public void TreeConnect_Granted_EmitsShareAccessGranted()
    {
        // Login already performs the TREE_CONNECT to \\s\Files.
        var (log, _, _, _, _) = Login(out _);

        SmbAuditEvent evt = Assert.Single(log.Events, e => e.EventType == SmbAuditEventType.ShareAccessGranted);
        Assert.Equal("Files", evt.Share);
    }

    [Fact]
    public void TreeConnect_Denied_EmitsShareAccessDenied()
    {
        var deny = new DelegateSharePolicy(ctx =>
            ctx.ShareName == "Files" ? ShareAccessResult.Deny() : ShareAccessResult.Grant());
        // Login's TREE_CONNECT to \\s\Files is rejected by the policy.
        var (log, _, _, _, _) = Login(out _, deny);

        SmbAuditEvent evt = Assert.Single(log.Events, e => e.EventType == SmbAuditEventType.ShareAccessDenied);
        Assert.Equal("Files", evt.Share);
        Assert.Equal(NtStatus.AccessDenied, evt.Status);
    }

    [Fact]
    public void OpenAndClose_EmitFileOpenedAndClosed()
    {
        var (log, d, conn, sid, tid) = Login(out _);
        File.WriteAllBytes(Path.Combine(_dir, "f.txt"), new byte[8]);

        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            NextMid(), sid, tid, "f.txt", ReadWrite, (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile));
        Smb2Header h = Smb2Header.Read(create);
        Assert.Equal(NtStatus.Success, h.Status);
        const int body = Smb2Header.Size;
        ulong p = BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8));
        ulong v = BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8));
        d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(NextMid(), sid, tid, p, v));

        SmbAuditEvent opened = Assert.Single(log.Events, e => e.EventType == SmbAuditEventType.FileOpened);
        Assert.Equal("f.txt", opened.Path);
        Assert.Equal("Files", opened.Share);
        Assert.Contains(log.Events, e => e.EventType == SmbAuditEventType.FileClosed && e.Path == "f.txt");
        Assert.DoesNotContain(log.Events, e => e.EventType == SmbAuditEventType.FileDeleted);
    }

    [Fact]
    public void DeleteOnClose_EmitsFileDeleted()
    {
        var (log, d, conn, sid, tid) = Login(out _);
        File.WriteAllBytes(Path.Combine(_dir, "gone.txt"), new byte[8]);

        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            NextMid(), sid, tid, "gone.txt", ReadWrite, (uint)CreateDisposition.Open,
            (uint)(CreateOptions.NonDirectoryFile | CreateOptions.DeleteOnClose)));
        Smb2Header h = Smb2Header.Read(create);
        Assert.Equal(NtStatus.Success, h.Status);
        const int body = Smb2Header.Size;
        ulong p = BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8));
        ulong v = BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8));
        d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(NextMid(), sid, tid, p, v));

        Assert.Contains(log.Events, e => e.EventType == SmbAuditEventType.FileDeleted && e.Path == "gone.txt");
    }

    // --- helpers ---

    private (CapturingAuditLogger log, Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Login(
        out ulong sessionId, IShareAccessPolicy? policy = null)
    {
        var log = new CapturingAuditLogger();
        var (d, conn) = Server(log, policy);

        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        sessionId = Smb2Header.Read(r1).SessionId;
        d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        uint treeId = Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\s\Files"))).TreeId;
        _mid = 10;
        return (log, d, conn, sessionId, treeId);
    }

    private (Smb2Dispatcher d, SmbConnection conn) Server(ISmbAuditLogger logger, IShareAccessPolicy? policy)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
            AuditLogger = logger,
        };
        if (policy is not null) options.ShareAccessPolicy = policy;
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share
        {
            Name = "Files",
            Type = ShareType.Disk,
            FileStore = new LocalFileStore(_dir, readOnly: false),
        });

        var conn = new SmbConnection { ClientAddress = "10.0.0.9:4444" };
        return (new Smb2Dispatcher(new SmbServerState(options)), conn);
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    private sealed class CapturingAuditLogger : ISmbAuditLogger
    {
        private readonly ConcurrentQueue<SmbAuditEvent> _events = new();
        public IReadOnlyList<SmbAuditEvent> Events => _events.ToArray();
        public bool IsEnabled(SmbLogLevel level) => true;
        public void Log(in SmbAuditEvent auditEvent) => _events.Enqueue(auditEvent);
    }
}
