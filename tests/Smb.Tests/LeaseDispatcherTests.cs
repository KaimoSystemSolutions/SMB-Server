using System.Buffers.Binary;
using System.Collections.Concurrent;
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
/// Phase 1 / M1.2 — lease break pipeline end-to-end via the dispatcher: a lease is granted at
/// CREATE (with the granted state echoed in a response context, §2.2.13.2.8); a second open with a
/// distinct lease key breaks the holder down to Read and sends a LEASE_BREAK notification
/// (§2.2.23.2); the holder's LEASE_BREAK acknowledgment (§2.2.24.2) is answered with a LEASE_BREAK
/// response (§2.2.25.2); and CLOSE releases the lease.
/// </summary>
public class LeaseDispatcherTests : IDisposable
{
    private readonly string _shareDir;
    private const byte LeaseOplock = 0xFF;   // SMB2_OPLOCK_LEVEL_LEASE

    public LeaseDispatcherTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smblease_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "doc.txt"), new string('x', 100));
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void Create_RequestingLease_OnSoloOpen_GrantsRequestedStateAndEchoesContext()
    {
        var (d, conn, sid, tid) = Setup();
        byte[] key = Key(0x11);

        byte[] create = OpenWithLease(d, conn, sid, tid, 10, key, LeaseState.ReadWriteHandle);

        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        Assert.Equal(LeaseOplock, GrantedOplock(create));               // response signals a lease
        Assert.Equal(LeaseState.ReadWriteHandle, GrantedLeaseState(create));
    }

    [Fact]
    public async Task SecondDistinctLeaseKey_BreaksHolderToRead_AndNotifiesTheHolder()
    {
        var (d, conn, sid, tid) = Setup();
        var sent = new ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        byte[] k1 = Key(0x01), k2 = Key(0x02);

        // First open holds a full RWH lease (solo).
        byte[] first = OpenWithLease(d, conn, sid, tid, 10, k1, LeaseState.ReadWriteHandle);
        Assert.Equal(LeaseState.ReadWriteHandle, GrantedLeaseState(first));

        // Second open, distinct key, same file → the holder breaks to Read. [W1] Losing W/H means the
        // holder must flush and acknowledge first, so this CREATE parks and its Read grant arrives
        // out-of-band (covered by BreakBeforeGrantTests). This test is about the holder's notification.
        Assert.Empty(OpenWithLeaseRaw(d, conn, sid, tid, 11, k2, LeaseState.ReadWriteHandle));

        Assert.Equal(NtStatus.Pending, Smb2Header.Read(await WaitForSend(sent)).Status);   // the parked CREATE's interim

        // The first holder receives an out-of-band LEASE_BREAK notification (MessageId 0xFFFF…F).
        byte[] notify = await WaitForSend(sent);
        Smb2Header nh = Smb2Header.Read(notify);
        Assert.Equal(SmbCommand.OplockBreak, nh.Command);
        Assert.Equal(0xFFFFFFFFFFFFFFFFul, nh.MessageId);
        Assert.Equal(LeaseBreakMessage.NotificationStructureSize, NotifyStructureSize(notify));
        Assert.Equal(k1, NotifyLeaseKey(notify));                         // addresses the first lease
        Assert.Equal(LeaseState.ReadWriteHandle, NotifyCurrentState(notify));
        Assert.Equal(LeaseState.Read, NotifyNewState(notify));
        Assert.Equal(LeaseBreakMessage.FlagAckRequired, NotifyFlags(notify)); // W/H lost → ack required
    }

    [Fact]
    public void LeaseBreakAcknowledgment_IsAnsweredWithResponse()
    {
        var (d, conn, sid, tid) = Setup();
        conn.SendRawAsync = (_, _) => Task.CompletedTask;

        byte[] k1 = Key(0x01), k2 = Key(0x02);
        OpenWithLease(d, conn, sid, tid, 10, k1, LeaseState.ReadWriteHandle);
        OpenWithLeaseRaw(d, conn, sid, tid, 11, k2, LeaseState.ReadWriteHandle); // triggers the break (and parks, W1)

        // Holder confirms downgrade to Read → server responds with a LEASE_BREAK response (§2.2.25.2).
        byte[] ack = d.ProcessMessage(conn, TestHelpers.BuildLeaseBreakAck(12, sid, tid, k1, LeaseState.Read));
        Smb2Header ah = Smb2Header.Read(ack);
        Assert.Equal(NtStatus.Success, ah.Status);
        Assert.Equal(SmbCommand.OplockBreak, ah.Command);
        Assert.Equal(LeaseBreakMessage.ResponseStructureSize, RespStructureSize(ack));
        Assert.Equal(k1, RespLeaseKey(ack));
        Assert.Equal(LeaseState.Read, RespLeaseState(ack));
    }

    [Fact]
    public void ClosingHolder_ReleasesLease_SoNextSoloOpenGetsFullLeaseAgain()
    {
        var (d, conn, sid, tid) = Setup();
        conn.SendRawAsync = (_, _) => Task.CompletedTask;

        byte[] k1 = Key(0x01), k2 = Key(0x02);
        byte[] first = OpenWithLease(d, conn, sid, tid, 10, k1, LeaseState.ReadWriteHandle);
        (ulong fp, ulong fv) = ExtractCreateFileId(first);
        d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(11, sid, tid, fp, fv)); // releases the lease

        // File has no leases anymore → a fresh distinct key is solo again → full grant.
        byte[] reopen = OpenWithLease(d, conn, sid, tid, 12, k2, LeaseState.ReadWriteHandle);
        Assert.Equal(LeaseState.ReadWriteHandle, GrantedLeaseState(reopen));
    }

    [Fact]
    public void Create_WithoutLeaseContext_GrantsNoLeaseAndCarriesNoResponseContext()
    {
        var (d, conn, sid, tid) = Setup();
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            10, sid, tid, "doc.txt", desiredAccess: 0x00000003,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile,
            requestedOplockLevel: 0));

        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        Assert.Equal((byte)OplockLevel.None, GrantedOplock(create));
        Assert.Equal(0u, ResponseContextsLength(create));   // no create contexts echoed
    }

    // --- setup & helpers ---

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_shareDir, readOnly: false) });

        var state = new SmbServerState(options);
        var dispatcher = new Smb2Dispatcher(state);
        var conn = new SmbConnection();

        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        uint treeId = Smb2Header.Read(dispatcher.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\s\Files"))).TreeId;
        return (dispatcher, conn, sessionId, treeId);
    }

    /// <summary>A lease CREATE that is expected to answer in-band (no break to wait for).</summary>
    private static byte[] OpenWithLease(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid,
        ulong mid, byte[] leaseKey, LeaseState requested)
    {
        byte[] create = OpenWithLeaseRaw(d, conn, sid, tid, mid, leaseKey, requested);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        return create;
    }

    /// <summary>
    /// A lease CREATE whose response is returned as-is. [W1] An open that costs another lease its
    /// write/handle caching parks behind the acknowledgment and answers out-of-band → empty in-band response.
    /// </summary>
    private static byte[] OpenWithLeaseRaw(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid,
        ulong mid, byte[] leaseKey, LeaseState requested)
        => d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            mid, sid, tid, "doc.txt", desiredAccess: 0x00000003 /* read+write */,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile,
            requestedOplockLevel: LeaseOplock,
            createContexts: TestHelpers.BuildLeaseV1Context(leaseKey, requested)));

    private static byte[] Key(byte value)
    {
        var k = new byte[16];
        Array.Fill(k, value);
        return k;
    }

    private static byte GrantedOplock(byte[] message) => message[Smb2Header.Size + 2];

    // --- CREATE response create-context extraction ---

    private static uint ResponseContextsLength(byte[] message)
        => BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(Smb2Header.Size + 84, 4));

    private static LeaseState GrantedLeaseState(byte[] message)
    {
        int off = (int)BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(Smb2Header.Size + 80, 4));
        int len = (int)ResponseContextsLength(message);
        IReadOnlyList<CreateContext> contexts = CreateContextList.Parse(message, off, len);
        CreateContext? lease = CreateContextList.Find(contexts, CreateContextNames.Lease);
        Assert.NotNull(lease);
        return LeaseRequest.FromContext(lease!).RequestedState;   // response context carries the granted state
    }

    private static (ulong persistent, ulong vol) ExtractCreateFileId(byte[] response)
    {
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 72, 8)));
    }

    // --- LEASE_BREAK notification field access (§2.2.23.2) ---

    private static ushort NotifyStructureSize(byte[] m) => BinaryPrimitives.ReadUInt16LittleEndian(m.AsSpan(Smb2Header.Size, 2));
    private static uint NotifyFlags(byte[] m) => BinaryPrimitives.ReadUInt32LittleEndian(m.AsSpan(Smb2Header.Size + 4, 4));
    private static byte[] NotifyLeaseKey(byte[] m) => m.AsSpan(Smb2Header.Size + 8, 16).ToArray();
    private static LeaseState NotifyCurrentState(byte[] m) => (LeaseState)BinaryPrimitives.ReadUInt32LittleEndian(m.AsSpan(Smb2Header.Size + 24, 4));
    private static LeaseState NotifyNewState(byte[] m) => (LeaseState)BinaryPrimitives.ReadUInt32LittleEndian(m.AsSpan(Smb2Header.Size + 28, 4));

    // --- LEASE_BREAK response field access (§2.2.25.2) ---

    private static ushort RespStructureSize(byte[] m) => BinaryPrimitives.ReadUInt16LittleEndian(m.AsSpan(Smb2Header.Size, 2));
    private static byte[] RespLeaseKey(byte[] m) => m.AsSpan(Smb2Header.Size + 8, 16).ToArray();
    private static LeaseState RespLeaseState(byte[] m) => (LeaseState)BinaryPrimitives.ReadUInt32LittleEndian(m.AsSpan(Smb2Header.Size + 24, 4));

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    private static async Task<byte[]> WaitForSend(ConcurrentQueue<byte[]> queue)
    {
        for (int i = 0; i < 150; i++)
        {
            if (queue.TryDequeue(out byte[]? msg)) return msg;
            await Task.Delay(20);
        }
        throw new Xunit.Sdk.XunitException("No out-of-band LEASE_BREAK notification received within the time limit.");
    }
}
