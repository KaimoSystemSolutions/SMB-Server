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
/// Oplocks end-to-end via the dispatcher (Context §15): grant at CREATE, downgrade +
/// OPLOCK_BREAK notification on a second open of the same file, acknowledgment response,
/// release at CLOSE and distinction from (not yet supported) lease breaks.
/// </summary>
public class OplockTests : IDisposable
{
    private readonly string _shareDir;

    public OplockTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smboplock_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "doc.txt"), new string('x', 100));
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void Create_RequestingBatch_OnSoloOpen_GrantsBatch()
    {
        var (d, conn, sid, tid) = Setup();
        byte[] create = OpenFile(d, conn, sid, tid, 10, oplock: (byte)OplockLevel.Batch);

        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        Assert.Equal((byte)OplockLevel.Batch, GrantedOplock(create));
    }

    [Fact]
    public void Create_RequestingExclusive_OnSoloOpen_GrantsExclusive()
    {
        var (d, conn, sid, tid) = Setup();
        byte[] create = OpenFile(d, conn, sid, tid, 10, oplock: (byte)OplockLevel.Exclusive);

        Assert.Equal((byte)OplockLevel.Exclusive, GrantedOplock(create));
    }

    [Fact]
    public void Create_WithoutRequestingOplock_GrantsNone()
    {
        var (d, conn, sid, tid) = Setup();
        byte[] create = OpenFile(d, conn, sid, tid, 10, oplock: (byte)OplockLevel.None);

        Assert.Equal((byte)OplockLevel.None, GrantedOplock(create));
    }

    [Fact]
    public async Task SecondOpen_BreaksHolderToLevelII_AndNotifiesTheHolder()
    {
        var (d, conn, sid, tid) = Setup();
        var sent = new ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        // First open holds a Batch oplock (solo open).
        byte[] first = OpenFile(d, conn, sid, tid, 10, oplock: (byte)OplockLevel.Batch);
        (ulong fp, ulong fv) = ExtractCreateFileId(first);
        Assert.Equal((byte)OplockLevel.Batch, GrantedOplock(first));

        // Second open on the same file → the holder breaks to Level II. [W1] Since break-before-grant, a
        // Batch holder must flush and acknowledge first, so this CREATE parks and its Level II grant
        // arrives out-of-band once the holder answers (covered by BreakBeforeGrantTests). What this test
        // is about is the notification the holder receives, so it only walks that far.
        Assert.Empty(OpenFileRaw(d, conn, sid, tid, 11, oplock: (byte)OplockLevel.Batch));

        Assert.Equal(NtStatus.Pending, Smb2Header.Read(await WaitForSend(sent)).Status);   // the parked CREATE's interim

        // The first holder receives an out-of-band OPLOCK_BREAK notification (MessageId 0xFFFF…F).
        byte[] notify = await WaitForSend(sent);
        Smb2Header nh = Smb2Header.Read(notify);
        Assert.Equal(SmbCommand.OplockBreak, nh.Command);
        Assert.Equal(0xFFFFFFFFFFFFFFFFul, nh.MessageId);
        Assert.Equal((byte)OplockLevel.LevelII, GrantedOplock(notify));   // broken target level
        (ulong np, ulong nv) = BreakFileId(notify);
        Assert.Equal(fp, np);
        Assert.Equal(fv, nv);                                            // notification addresses the first open
    }

    [Fact]
    public void OplockBreakAcknowledgment_IsQuittancedWithResponse()
    {
        var (d, conn, sid, tid) = Setup();
        conn.SendRawAsync = (_, _) => Task.CompletedTask;

        byte[] first = OpenFile(d, conn, sid, tid, 10, oplock: (byte)OplockLevel.Batch);
        (ulong fp, ulong fv) = ExtractCreateFileId(first);
        OpenFileRaw(d, conn, sid, tid, 11, oplock: (byte)OplockLevel.Batch); // triggers the break (and parks, W1)

        // Holder confirms downgrade to Level II → server responds with OPLOCK_BREAK response.
        byte[] ack = d.ProcessMessage(conn,
            TestHelpers.BuildOplockBreakAck(12, sid, tid, fp, fv, (byte)OplockLevel.LevelII));
        Smb2Header ah = Smb2Header.Read(ack);
        Assert.Equal(NtStatus.Success, ah.Status);
        Assert.Equal(SmbCommand.OplockBreak, ah.Command);
        Assert.Equal((byte)OplockLevel.LevelII, GrantedOplock(ack));
        (ulong ap, ulong av) = BreakFileId(ack);
        Assert.Equal(fp, ap);
        Assert.Equal(fv, av);
    }

    [Fact]
    public void ClosingHolder_ReleasesOplock_SoNextSoloOpenGetsExclusiveAgain()
    {
        var (d, conn, sid, tid) = Setup();
        conn.SendRawAsync = (_, _) => Task.CompletedTask;

        byte[] first = OpenFile(d, conn, sid, tid, 10, oplock: (byte)OplockLevel.Batch);
        (ulong fp, ulong fv) = ExtractCreateFileId(first);
        d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(11, sid, tid, fp, fv)); // releases the oplock

        // Again the only open → exclusive oplock possible again.
        byte[] reopen = OpenFile(d, conn, sid, tid, 12, oplock: (byte)OplockLevel.Batch);
        Assert.Equal((byte)OplockLevel.Batch, GrantedOplock(reopen));
    }

    [Fact]
    public void OplockBreakAck_WithUnknownStructureSize_ReturnsNotSupported()
    {
        // A break acknowledgment whose StructureSize is neither 24 (oplock) nor 36 (lease) is an
        // unknown variant → STATUS_NOT_SUPPORTED. (StructureSize 36 is now routed to the lease path,
        // see LeaseDispatcherTests.)
        var (d, conn, sid, tid) = Setup();

        var body = new byte[40];
        BinaryPrimitives.WriteUInt16LittleEndian(body, 40); // neither 24 nor 36
        byte[] unknownAck = TestHelpers.Concat(TestHelpers.BuildHeader(SmbCommand.OplockBreak, 20, sid, tid), body);

        Assert.Equal(NtStatus.NotSupported, Smb2Header.Read(d.ProcessMessage(conn, unknownAck)).Status);
    }

    // --- Setup & helpers (analogous to LockDispatcherTests) ---

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

    /// <summary>A CREATE that is expected to answer in-band (no break to wait for).</summary>
    private static byte[] OpenFile(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong mid, byte oplock)
    {
        byte[] create = OpenFileRaw(d, conn, sid, tid, mid, oplock);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        return create;
    }

    /// <summary>
    /// A CREATE whose response is returned as-is. [W1] An open that breaks another holder's Batch/Exclusive
    /// oplock parks behind the acknowledgment and answers out-of-band, so its in-band response is empty.
    /// </summary>
    private static byte[] OpenFileRaw(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong mid, byte oplock)
        => d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            mid, sid, tid, "doc.txt", desiredAccess: 0x00000003 /* read+write */,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile,
            requestedOplockLevel: oplock));

    /// <summary>Reads the OplockLevel byte (offset +2 in body) — valid for both CREATE response and OPLOCK_BREAK.</summary>
    private static byte GrantedOplock(byte[] message) => message[Smb2Header.Size + 2];

    /// <summary>FileId from an OPLOCK_BREAK body (Persistent @+8, Volatile @+16).</summary>
    private static (ulong persistent, ulong vol) BreakFileId(byte[] message)
    {
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(message.AsSpan(body + 8, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(message.AsSpan(body + 16, 8)));
    }

    private static (ulong persistent, ulong vol) ExtractCreateFileId(byte[] response)
    {
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 72, 8)));
    }

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
        throw new Xunit.Sdk.XunitException("No out-of-band OPLOCK_BREAK notification received within the time limit.");
    }
}
