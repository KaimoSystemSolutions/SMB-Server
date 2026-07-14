using System.Buffers.Binary;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 4 / M4.1 — durable handles (v1) over the dispatcher: a batch-oplocked open that requests
/// durability survives a transport drop and can be reconnected by FileId; it expires after the timeout
/// and rejects a reconnect from a different principal.
/// </summary>
public class DurableHandleTests : IDisposable
{
    private const byte OplockBatch = 0x09;
    private const uint ReadWrite = 0x00000003;

    private readonly string _shareDir;
    private readonly ManualTimeProvider _time = new(DateTimeOffset.UnixEpoch);
    private readonly Smb2Dispatcher _dispatcher;

    public DurableHandleTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbdur_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "durable.txt"), "persist me");

        var backend = new InMemoryIdentityBackend()
            .AddUser("DOM", "alice", "pw")
            .AddUser("DOM", "bob", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
            TimeProvider = _time,
            DurableHandleTimeout = TimeSpan.FromSeconds(60),
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_shareDir, readOnly: false) });
        // A continuously-available share (grants persistent handles).
        options.Shares.Add(new Share
        {
            Name = "CA", Type = ShareType.Disk, ContinuousAvailability = true,
            FileStore = new LocalFileStore(_shareDir, readOnly: false),
        });
        _dispatcher = new Smb2Dispatcher(new SmbServerState(options));
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void DurableRequest_WithBatchOplock_IsGranted()
    {
        Client c = Connect("alice");
        byte[] create = OpenDurable(c, OplockBatch);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);

        Assert.True(HasResponseContext(create, CreateContextNames.DurableHandleRequest));
        (ulong persistent, _) = FileId(create);
        Assert.NotEqual(0UL, persistent); // durable opens get a stable, server-unique persistent id
    }

    [Fact]
    public void TreeConnect_ContinuousAvailabilityShare_AdvertisesCaCapability()
    {
        // [C1.0] A CA share advertises SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY on an SMB3 connection;
        // a plain share (and the mandatory IPC$) does not.
        Assert.True((TreeConnectCapabilities("CA") & (uint)ShareCapabilities.ContinuousAvailability) != 0);
        Assert.True((TreeConnectCapabilities("Files") & (uint)ShareCapabilities.ContinuousAvailability) == 0);
    }

    /// <summary>Connects a fresh SMB3.1.1 client and returns the TREE_CONNECT response Capabilities field.</summary>
    private uint TreeConnectCapabilities(string share)
    {
        var conn = new SmbConnection();
        var c = new Client(conn);
        _dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = _dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(c.NextMid(), 0, client.BuildNegotiate()));
        c.Sid = Smb2Header.Read(r1).SessionId;
        _dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(c.NextMid(), c.Sid, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        byte[] tc = _dispatcher.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(c.NextMid(), c.Sid, $@"\\s\{share}"));
        // TREE_CONNECT response body: StructureSize(2) ShareType(1) Reserved(1) ShareFlags(4) Capabilities(4).
        return BinaryPrimitives.ReadUInt32LittleEndian(tc.AsSpan(Smb2Header.Size + 8, 4));
    }

    [Fact]
    public void DurableRequest_WithoutOplock_IsNotGranted()
    {
        Client c = Connect("alice");
        byte[] create = OpenDurable(c, requestedOplock: 0 /* none */);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);

        Assert.False(HasResponseContext(create, CreateContextNames.DurableHandleRequest)); // no caching guarantee → no durability
    }

    [Fact]
    public void Reconnect_AfterTransportDrop_RestoresHandle_AndReads()
    {
        Client a = Connect("alice");
        byte[] create = OpenDurable(a, OplockBatch);
        (ulong persistent, ulong vol) = FileId(create);

        // Transport drop: the durable open is preserved, not released.
        _dispatcher.OnConnectionClosed(a.Conn);

        // New connection, same user, reconnect by FileId.
        Client b = Connect("alice");
        byte[] reconnect = Reconnect(b, persistent, vol);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(reconnect).Status);

        // The restored handle is usable.
        byte[] read = _dispatcher.ProcessMessage(b.Conn, TestHelpers.BuildReadRequest(b.NextMid(), b.Sid, b.Tid, persistent, vol, length: 9, offset: 0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(read).Status);
    }

    [Fact]
    public void Reconnect_AfterTimeout_IsScavenged_AndFails()
    {
        Client a = Connect("alice");
        (ulong persistent, ulong vol) = FileId(OpenDurable(a, OplockBatch));
        _dispatcher.OnConnectionClosed(a.Conn);

        _time.Advance(TimeSpan.FromSeconds(61));
        _dispatcher.ScavengeDurableHandles();

        Client b = Connect("alice");
        byte[] reconnect = Reconnect(b, persistent, vol);
        Assert.Equal(NtStatus.ObjectNameNotFound, Smb2Header.Read(reconnect).Status);
    }

    [Fact]
    public void Reconnect_FromDifferentPrincipal_IsDenied_ButOwnerCanStillReconnect()
    {
        Client a = Connect("alice");
        (ulong persistent, ulong vol) = FileId(OpenDurable(a, OplockBatch));
        _dispatcher.OnConnectionClosed(a.Conn);

        // Bob must not steal Alice's durable handle.
        Client bob = Connect("bob");
        Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(Reconnect(bob, persistent, vol)).Status);

        // The handle is kept, so Alice can still reconnect.
        Client alice2 = Connect("alice");
        Assert.Equal(NtStatus.Success, Smb2Header.Read(Reconnect(alice2, persistent, vol)).Status);
    }

    [Fact]
    public void DurableV2Request_IsGranted_WithTimeoutAndGuid()
    {
        Client c = Connect("alice");
        var guid = Guid.NewGuid();
        byte[] create = OpenDurableV2(c, OplockBatch, guid, timeoutMs: 30_000, persistent: false);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        Assert.True(HasResponseContext(create, CreateContextNames.DurableHandleRequestV2));
    }

    [Fact]
    public void DurableV2_Reconnect_RequiresMatchingCreateGuid()
    {
        Client a = Connect("alice");
        var guid = Guid.NewGuid();
        (ulong persistent, ulong vol) = FileId(OpenDurableV2(a, OplockBatch, guid, timeoutMs: 0, persistent: false));
        _dispatcher.OnConnectionClosed(a.Conn);

        // Wrong GUID is rejected (handle kept)...
        Client b = Connect("alice");
        Assert.Equal(NtStatus.ObjectNameNotFound, Smb2Header.Read(ReconnectV2(b, persistent, vol, Guid.NewGuid())).Status);

        // ...the correct GUID reconnects.
        Client d = Connect("alice");
        Assert.Equal(NtStatus.Success, Smb2Header.Read(ReconnectV2(d, persistent, vol, guid)).Status);
    }

    [Fact]
    public void PersistentHandle_OnCaShare_SurvivesTimeout()
    {
        Client a = Connect("alice", share: "CA");
        var guid = Guid.NewGuid();
        byte[] create = OpenDurableV2(a, OplockBatch, guid, timeoutMs: 10_000, persistent: true);
        Assert.True(HasResponseContext(create, CreateContextNames.DurableHandleRequestV2));
        (ulong persistent, ulong vol) = FileId(create);
        _dispatcher.OnConnectionClosed(a.Conn);

        // Long past any timeout, and after a scavenge sweep, a persistent handle is still reconnectable.
        _time.Advance(TimeSpan.FromHours(2));
        _dispatcher.ScavengeDurableHandles();

        Client b = Connect("alice", share: "CA");
        Assert.Equal(NtStatus.Success, Smb2Header.Read(ReconnectV2(b, persistent, vol, guid)).Status);
    }

    [Fact]
    public void PersistentFlag_OnNonCaShare_IsDowngradedToDurable()
    {
        // Requesting persistent on a non-CA share yields a (non-persistent) durable handle that DOES expire.
        Client a = Connect("alice"); // "Files" is not continuously available
        var guid = Guid.NewGuid();
        (ulong persistent, ulong vol) = FileId(OpenDurableV2(a, OplockBatch, guid, timeoutMs: 10_000, persistent: true));
        _dispatcher.OnConnectionClosed(a.Conn);

        _time.Advance(TimeSpan.FromSeconds(11));
        _dispatcher.ScavengeDurableHandles();

        Client b = Connect("alice");
        Assert.Equal(NtStatus.ObjectNameNotFound, Smb2Header.Read(ReconnectV2(b, persistent, vol, guid)).Status);
    }

    // --- helpers ---

    private byte[] OpenDurableV2(Client c, byte requestedOplock, Guid createGuid, uint timeoutMs, bool persistent)
    {
        byte[] ctx = CreateContextList.Serialize(new[]
        {
            new CreateContext
            {
                Name = DurableHandleMessages.NameBytes(CreateContextNames.DurableHandleRequestV2),
                Data = DurableHandleMessages.BuildV2RequestData(timeoutMs, createGuid, persistent),
            },
        });
        return _dispatcher.ProcessMessage(c.Conn, TestHelpers.BuildCreateRequest(
            c.NextMid(), c.Sid, c.Tid, "durable.txt", desiredAccess: ReadWrite,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile,
            requestedOplockLevel: requestedOplock, createContexts: ctx));
    }

    private byte[] ReconnectV2(Client c, ulong persistent, ulong vol, Guid createGuid)
    {
        byte[] ctx = CreateContextList.Serialize(new[]
        {
            new CreateContext
            {
                Name = DurableHandleMessages.NameBytes(CreateContextNames.DurableHandleReconnectV2),
                Data = DurableHandleMessages.BuildV2ReconnectData(persistent, vol, createGuid, persistent: false),
            },
        });
        return _dispatcher.ProcessMessage(c.Conn, TestHelpers.BuildCreateRequest(
            c.NextMid(), c.Sid, c.Tid, "durable.txt", desiredAccess: ReadWrite,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile,
            createContexts: ctx));
    }

    private byte[] OpenDurable(Client c, byte requestedOplock)
    {
        byte[] durableCtx = CreateContextList.Serialize(new[]
        {
            new CreateContext
            {
                Name = DurableHandleMessages.NameBytes(CreateContextNames.DurableHandleRequest),
                Data = new byte[16],
            },
        });
        return _dispatcher.ProcessMessage(c.Conn, TestHelpers.BuildCreateRequest(
            c.NextMid(), c.Sid, c.Tid, "durable.txt", desiredAccess: ReadWrite,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile,
            requestedOplockLevel: requestedOplock, createContexts: durableCtx));
    }

    private byte[] Reconnect(Client c, ulong persistent, ulong vol)
    {
        byte[] reconnectCtx = CreateContextList.Serialize(new[]
        {
            new CreateContext
            {
                Name = DurableHandleMessages.NameBytes(CreateContextNames.DurableHandleReconnect),
                Data = DurableHandleMessages.BuildReconnectData(persistent, vol),
            },
        });
        return _dispatcher.ProcessMessage(c.Conn, TestHelpers.BuildCreateRequest(
            c.NextMid(), c.Sid, c.Tid, "durable.txt", desiredAccess: ReadWrite,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile,
            createContexts: reconnectCtx));
    }

    private static (ulong persistent, ulong vol) FileId(byte[] createResponse)
    {
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(createResponse.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(createResponse.AsSpan(body + 72, 8)));
    }

    private static bool HasResponseContext(byte[] createResponse, uint tag)
    {
        int off = (int)BinaryPrimitives.ReadUInt32LittleEndian(createResponse.AsSpan(Smb2Header.Size + 80, 4));
        int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(createResponse.AsSpan(Smb2Header.Size + 84, 4));
        if (len == 0) return false;
        IReadOnlyList<CreateContext> contexts = CreateContextList.Parse(createResponse, off, len);
        return CreateContextList.Find(contexts, tag) is not null;
    }

    private Client Connect(string user, string share = "Files")
    {
        var conn = new SmbConnection();
        var c = new Client(conn);
        _dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", user, "pw");
        byte[] r1 = _dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(c.NextMid(), 0, client.BuildNegotiate()));
        c.Sid = Smb2Header.Read(r1).SessionId;
        _dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(c.NextMid(), c.Sid, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        c.Tid = Smb2Header.Read(_dispatcher.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(c.NextMid(), c.Sid, $@"\\s\{share}"))).TreeId;
        return c;
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    private sealed class Client(SmbConnection conn)
    {
        public SmbConnection Conn { get; } = conn;
        public ulong Sid { get; set; }
        public uint Tid { get; set; }
        private ulong _mid = 1;
        public ulong NextMid() => _mid++;
    }

    /// <summary>Deterministic, manually advanced <see cref="TimeProvider"/> for durable-timeout tests.</summary>
    private sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }
}
