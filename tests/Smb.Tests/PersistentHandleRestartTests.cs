using System.Buffers.Binary;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Durable;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// C2 — a persistent (continuously-available) handle survives a full server restart via
/// <see cref="FileDurableHandleStore"/>: its metadata is persisted at CREATE, reloaded by a fresh store
/// after a "restart", and rehydrated into a live open on reconnect (backend re-opened) so the client keeps
/// reading. Plus store-level persistence unit tests.
/// </summary>
public class PersistentHandleRestartTests : IDisposable
{
    private const byte OplockBatch = 0x09;
    private const uint ReadWrite = 0x00000003;
    private const string FileContent = "persist me";

    private readonly string _shareDir;
    private readonly string _persistDir;

    public PersistentHandleRestartTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbca_" + Guid.NewGuid().ToString("N"));
        _persistDir = Path.Combine(Path.GetTempPath(), "smbph_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "durable.txt"), FileContent);
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
        try { Directory.Delete(_persistDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void PersistentHandle_SurvivesRestart_AndReconnectReads()
    {
        var guid = Guid.NewGuid();

        // Server instance #1: open a persistent handle on the CA share (record written at CREATE).
        Smb2Dispatcher d1 = NewServer();
        Client a = Connect(d1);
        byte[] create = OpenPersistent(d1, a, guid);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        Assert.True(HasResponseContext(create, CreateContextNames.DurableHandleRequestV2));
        (ulong persistent, ulong vol) = FileId(create);
        Assert.NotEqual(0UL, persistent);

        // A record now exists on disk, independent of any live server state.
        Assert.NotEmpty(Directory.GetFiles(_persistDir, "*.json"));

        // "Restart": a brand-new server + fresh store over the SAME persistence dir and share backend.
        // (d1's in-process warm table is gone — only the on-disk record remains.)
        Smb2Dispatcher d2 = NewServer();
        Client b = Connect(d2);
        byte[] reconnect = ReconnectV2(d2, b, persistent, vol, guid);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(reconnect).Status);

        // The rehydrated handle is live: reading returns the file's content.
        byte[] read = d2.ProcessMessage(b.Conn,
            TestHelpers.BuildReadRequest(b.NextMid(), b.Sid, b.Tid, persistent, vol, length: (uint)FileContent.Length, offset: 0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(read).Status);
    }

    [Fact]
    public void Reconnect_AfterRestart_WrongCreateGuid_IsRejected_AndRecordKept()
    {
        var guid = Guid.NewGuid();
        Smb2Dispatcher d1 = NewServer();
        Client a = Connect(d1);
        (ulong persistent, ulong vol) = FileId(OpenPersistent(d1, a, guid));

        Smb2Dispatcher d2 = NewServer();
        Client b = Connect(d2);
        // Wrong GUID → rejected, record retained.
        Assert.Equal(NtStatus.ObjectNameNotFound,
            Smb2Header.Read(ReconnectV2(d2, b, persistent, vol, Guid.NewGuid())).Status);

        // The correct GUID still reconnects on a fresh server (record was returned, not consumed).
        Smb2Dispatcher d3 = NewServer();
        Client c = Connect(d3);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(ReconnectV2(d3, c, persistent, vol, guid)).Status);
    }

    [Fact]
    public void FileStore_PersistsAndReloadsRecords_AndRemoveDeletes()
    {
        var rec = new PersistentHandleRecord(
            PersistentId: 0x8000_0000_0000_0007, VolatileId: 3, OwnerKey: "S-1-5-21-1",
            CreateGuid: Guid.NewGuid(), ShareName: "CA", Path: "durable.txt",
            GrantedAccess: ReadWrite, ShareAccess: 0x7);

        new FileDurableHandleStore(_persistDir).Persist(rec);

        // A fresh store over the same directory loads it as a claimable cold record.
        var reloaded = new FileDurableHandleStore(_persistDir);
        Assert.Equal(rec.PersistentId, reloaded.HighestPersistentId);
        Assert.True(reloaded.TryClaimColdRecord(rec.PersistentId, rec.VolatileId, out PersistentHandleRecord got));
        Assert.Equal(rec, got);
        // Claiming does not delete the on-disk copy (survives a subsequent restart).
        Assert.False(reloaded.TryClaimColdRecord(rec.PersistentId, rec.VolatileId, out _)); // in-memory consumed
        Assert.True(new FileDurableHandleStore(_persistDir).TryClaimColdRecord(rec.PersistentId, rec.VolatileId, out _));

        // RemovePersisted deletes it for good.
        reloaded.RemovePersisted(rec.PersistentId, rec.VolatileId);
        Assert.False(new FileDurableHandleStore(_persistDir).TryClaimColdRecord(rec.PersistentId, rec.VolatileId, out _));
    }

    [Fact]
    public void FileStore_SkipsCorruptRecord_OnLoad()
    {
        Directory.CreateDirectory(_persistDir);
        File.WriteAllText(Path.Combine(_persistDir, "garbage.json"), "{ not valid json");
        // Must not throw; the corrupt record is simply skipped.
        var store = new FileDurableHandleStore(_persistDir);
        Assert.Equal(0UL, store.HighestPersistentId);
    }

    // --- helpers ---

    private Smb2Dispatcher NewServer()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
            DurableHandleStore = new FileDurableHandleStore(_persistDir),
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share
        {
            Name = "CA", Type = ShareType.Disk, ContinuousAvailability = true,
            FileStore = new LocalFileStore(_shareDir, readOnly: false),
        });
        return new Smb2Dispatcher(new SmbServerState(options));
    }

    private byte[] OpenPersistent(Smb2Dispatcher d, Client c, Guid guid)
    {
        byte[] ctx = CreateContextList.Serialize(new[]
        {
            new CreateContext
            {
                Name = DurableHandleMessages.NameBytes(CreateContextNames.DurableHandleRequestV2),
                Data = DurableHandleMessages.BuildV2RequestData(30_000, guid, persistent: true),
            },
        });
        return d.ProcessMessage(c.Conn, TestHelpers.BuildCreateRequest(
            c.NextMid(), c.Sid, c.Tid, "durable.txt", desiredAccess: ReadWrite,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile,
            requestedOplockLevel: OplockBatch, createContexts: ctx));
    }

    private byte[] ReconnectV2(Smb2Dispatcher d, Client c, ulong persistent, ulong vol, Guid guid)
    {
        byte[] ctx = CreateContextList.Serialize(new[]
        {
            new CreateContext
            {
                Name = DurableHandleMessages.NameBytes(CreateContextNames.DurableHandleReconnectV2),
                Data = DurableHandleMessages.BuildV2ReconnectData(persistent, vol, guid, persistent: true),
            },
        });
        return d.ProcessMessage(c.Conn, TestHelpers.BuildCreateRequest(
            c.NextMid(), c.Sid, c.Tid, "durable.txt", desiredAccess: ReadWrite,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile,
            createContexts: ctx));
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

    private Client Connect(Smb2Dispatcher d)
    {
        var conn = new SmbConnection();
        var c = new Client(conn);
        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(c.NextMid(), 0, client.BuildNegotiate()));
        c.Sid = Smb2Header.Read(r1).SessionId;
        d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(c.NextMid(), c.Sid, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        c.Tid = Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(c.NextMid(), c.Sid, @"\\s\CA"))).TreeId;
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
}
