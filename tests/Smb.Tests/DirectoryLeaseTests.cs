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
/// Phase 1 / M1.3 — directory leases end-to-end via the dispatcher. A directory opened with a
/// lease-V2 "RqLs" context is granted a Read+Handle lease (§2.2.13.2.10); when a child entry is
/// added (CREATE), removed (DELETE_ON_CLOSE) or renamed (SET_INFO) inside the directory, the holder
/// is sent a LEASE_BREAK notification downgrading it to Read (§2.2.23.2), and its acknowledgment is
/// answered with a LEASE_BREAK response (§2.2.25.2).
/// </summary>
public class DirectoryLeaseTests : IDisposable
{
    private readonly string _shareDir;
    private readonly string _watchedDir;
    private const byte LeaseOplock = 0xFF;   // SMB2_OPLOCK_LEVEL_LEASE

    public DirectoryLeaseTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbdirlease_" + Guid.NewGuid().ToString("N"));
        _watchedDir = Path.Combine(_shareDir, "watched");
        Directory.CreateDirectory(_watchedDir);
        // Pre-existing children used by the remove/rename tests (opening them is an "Opened", not a
        // "Created", so it does not itself break the directory lease).
        File.WriteAllText(Path.Combine(_watchedDir, "victim.txt"), "bye");
        File.WriteAllText(Path.Combine(_watchedDir, "old.txt"), "data");
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void DirectoryOpen_RequestingReadHandleLease_GrantsItAndEchoesContext()
    {
        var (d, conn, sid, tid) = Setup();

        byte[] open = OpenDirWithLease(d, conn, sid, tid, 10, Key(0x21), LeaseState.ReadHandle);

        Assert.Equal(NtStatus.Success, Smb2Header.Read(open).Status);
        Assert.Equal(LeaseOplock, GrantedOplock(open));
        Assert.Equal(LeaseState.ReadHandle, GrantedLeaseState(open));   // solo directory → full RH
    }

    [Fact]
    public async Task ChildCreate_BreaksParentDirectoryLease_ToRead()
    {
        var (d, conn, sid, tid) = Setup();
        var sent = new ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        byte[] dirKey = Key(0x21);
        OpenDirWithLease(d, conn, sid, tid, 10, dirKey, LeaseState.ReadHandle);

        // Create a brand-new file inside the leased directory → the directory listing changes.
        byte[] child = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            11, sid, tid, @"watched\fresh.txt", desiredAccess: 0x00000003,
            disposition: (uint)CreateDisposition.Create, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(child).Status);

        byte[] notify = await WaitForSend(sent);
        Smb2Header nh = Smb2Header.Read(notify);
        Assert.Equal(SmbCommand.OplockBreak, nh.Command);
        Assert.Equal(0xFFFFFFFFFFFFFFFFul, nh.MessageId);
        Assert.Equal(LeaseBreakMessage.NotificationStructureSize, NotifyStructureSize(notify));
        Assert.Equal(dirKey, NotifyLeaseKey(notify));                      // addresses the directory lease
        Assert.Equal(LeaseState.ReadHandle, NotifyCurrentState(notify));
        Assert.Equal(LeaseState.Read, NotifyNewState(notify));            // Handle caching dropped
        Assert.Equal(LeaseBreakMessage.FlagAckRequired, NotifyFlags(notify)); // H lost → ack required
    }

    [Fact]
    public async Task ChildDelete_BreaksParentDirectoryLease()
    {
        var (d, conn, sid, tid) = Setup();
        var sent = new ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        byte[] dirKey = Key(0x22);
        OpenDirWithLease(d, conn, sid, tid, 10, dirKey, LeaseState.ReadHandle);

        // Open the pre-existing child with DELETE_ON_CLOSE and close it → the entry is removed.
        byte[] victim = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            11, sid, tid, @"watched\victim.txt", desiredAccess: 0x00010000 /* DELETE */,
            disposition: (uint)CreateDisposition.Open,
            options: (uint)(CreateOptions.NonDirectoryFile | CreateOptions.DeleteOnClose)));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(victim).Status);
        Assert.Empty(sent);   // opening a pre-existing file does not change the listing → no break yet
        (ulong p, ulong v) = ExtractCreateFileId(victim);

        d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(12, sid, tid, p, v));
        Assert.False(File.Exists(Path.Combine(_watchedDir, "victim.txt")));

        byte[] notify = await WaitForSend(sent);
        Assert.Equal(dirKey, NotifyLeaseKey(notify));
        Assert.Equal(LeaseState.Read, NotifyNewState(notify));
    }

    [Fact]
    public async Task ChildRename_BreaksParentDirectoryLease()
    {
        var (d, conn, sid, tid) = Setup();
        var sent = new ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        byte[] dirKey = Key(0x23);
        OpenDirWithLease(d, conn, sid, tid, 10, dirKey, LeaseState.ReadHandle);

        byte[] file = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            11, sid, tid, @"watched\old.txt", desiredAccess: 0x00010000 | 0x00000003,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(file).Status);
        Assert.Empty(sent);
        (ulong p, ulong v) = ExtractCreateFileId(file);

        byte[] rename = d.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            12, sid, tid, p, v, infoType: 0x01,
            fileInfoClass: (byte)FileInformationClass.FileRenameInformation,
            buffer: BuildRenameBuffer(@"watched\renamed.txt")));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(rename).Status);
        Assert.True(File.Exists(Path.Combine(_watchedDir, "renamed.txt")));

        byte[] notify = await WaitForSend(sent);
        Assert.Equal(dirKey, NotifyLeaseKey(notify));
        Assert.Equal(LeaseState.Read, NotifyNewState(notify));
    }

    [Fact]
    public void DirectoryLeaseBreak_Acknowledgment_IsAnsweredWithResponse()
    {
        var (d, conn, sid, tid) = Setup();
        conn.SendRawAsync = (_, _) => Task.CompletedTask;

        byte[] dirKey = Key(0x24);
        OpenDirWithLease(d, conn, sid, tid, 10, dirKey, LeaseState.ReadHandle);
        d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(          // child add → triggers the break
            11, sid, tid, @"watched\trigger.txt", desiredAccess: 0x00000003,
            disposition: (uint)CreateDisposition.Create, options: (uint)CreateOptions.NonDirectoryFile));

        // Holder confirms the downgrade to Read → server answers with a LEASE_BREAK response (§2.2.25.2).
        byte[] ack = d.ProcessMessage(conn, TestHelpers.BuildLeaseBreakAck(12, sid, tid, dirKey, LeaseState.Read));
        Smb2Header ah = Smb2Header.Read(ack);
        Assert.Equal(NtStatus.Success, ah.Status);
        Assert.Equal(SmbCommand.OplockBreak, ah.Command);
        Assert.Equal(LeaseBreakMessage.ResponseStructureSize, RespStructureSize(ack));
        Assert.Equal(dirKey, RespLeaseKey(ack));
        Assert.Equal(LeaseState.Read, RespLeaseState(ack));
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

    private static byte[] OpenDirWithLease(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid,
        ulong mid, byte[] leaseKey, LeaseState requested)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            mid, sid, tid, "watched", desiredAccess: 0x00000001 /* read */,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.DirectoryFile,
            requestedOplockLevel: LeaseOplock,
            createContexts: TestHelpers.BuildLeaseV2Context(leaseKey, requested)));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        return create;
    }

    /// <summary>FILE_RENAME_INFORMATION buffer (§2.4.34): ReplaceIfExists + Reserved + RootDir + name.</summary>
    private static byte[] BuildRenameBuffer(string newPath)
    {
        byte[] name = System.Text.Encoding.Unicode.GetBytes(newPath);
        var buf = new byte[20 + name.Length];
        buf[0] = 1;   // ReplaceIfExists
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(16, 4), (uint)name.Length);
        name.CopyTo(buf.AsSpan(20));
        return buf;
    }

    private static byte[] Key(byte value)
    {
        var k = new byte[16];
        Array.Fill(k, value);
        return k;
    }

    private static byte GrantedOplock(byte[] message) => message[Smb2Header.Size + 2];

    private static LeaseState GrantedLeaseState(byte[] message)
    {
        int off = (int)BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(Smb2Header.Size + 80, 4));
        int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(Smb2Header.Size + 84, 4));
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
