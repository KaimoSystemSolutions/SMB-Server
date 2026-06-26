using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Text;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Locking;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// LOCK/CANCEL end-to-end über den Dispatcher: synchroner Grant, READ/WRITE-Konfliktprüfung,
/// sowie der asynchrone Pfad (Interim STATUS_PENDING + finale out-of-band-Antwort, CANCEL).
/// </summary>
public class LockDispatcherTests : IDisposable
{
    private readonly string _shareDir;

    public LockDispatcherTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smblock_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "lock.txt"), new string('x', 100));
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void Lock_OnRealFile_ReturnsSuccess()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = OpenFile(d, conn, sid, tid, 4);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildLockRequest(5, sid, tid, p, v,
            [(0, 10, (uint)(LockFlags.ExclusiveLock | LockFlags.FailImmediately))]));

        Smb2Header h = Smb2Header.Read(resp);
        Assert.Equal(NtStatus.Success, h.Status);
        Assert.Equal(SmbCommand.Lock, h.Command);
        Assert.Equal(4, BinaryPrimitives.ReadUInt16LittleEndian(resp.AsSpan(64, 2))); // LOCK-Response StructureSize
    }

    [Fact]
    public void Write_IntoLockedRange_ReturnsFileLockConflict()
    {
        var (d, conn, sid, tid) = Setup(new DenyAllLockManager());
        (ulong p, ulong v) = OpenFile(d, conn, sid, tid, 4);

        byte[] resp = d.ProcessMessage(conn,
            TestHelpers.BuildWriteRequest(5, sid, tid, p, v, 0, Encoding.UTF8.GetBytes("data")));
        Assert.Equal(NtStatus.FileLockConflict, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public async Task BlockingLock_SendsInterimPending_ThenFinalGrantedOutOfBand()
    {
        var gated = new GatedLockManager();
        var (d, conn, sid, tid) = Setup(gated);
        (ulong p, ulong v) = OpenFile(d, conn, sid, tid, 4);

        var sent = new ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        // LOCK ohne FAIL_IMMEDIATELY → der Manager blockiert → Interim-Antwort STATUS_PENDING.
        byte[] interim = d.ProcessMessage(conn, TestHelpers.BuildLockRequest(6, sid, tid, p, v,
            [(0, 10, (uint)LockFlags.ExclusiveLock)]));
        Smb2Header ih = Smb2Header.Read(interim);
        Assert.Equal(NtStatus.Pending, ih.Status);
        Assert.True(ih.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand));
        Assert.NotEqual(0ul, ih.AsyncId);

        // Gate öffnen → finale Granted-Antwort geht out-of-band an die Senke (gleiche AsyncId).
        gated.Complete(LockOutcome.Granted);
        Smb2Header fh = Smb2Header.Read(await WaitForSend(sent));
        Assert.Equal(NtStatus.Success, fh.Status);
        Assert.True(fh.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand));
        Assert.Equal(ih.AsyncId, fh.AsyncId);
    }

    [Fact]
    public async Task BlockingLock_OnEncryptedTree_ForcesEncryptedFinalResponse()
    {
        // ASYNC-Antworten tragen keine TreeId — die Per-Share-Verschlüsselungspflicht muss daher
        // explizit über den Sendekanal erzwungen werden (sonst ginge die finale Antwort im Klartext).
        // Erzwingung der Eingangsverschlüsselung hier aus, um den Fluss im Test unverschlüsselt
        // treiben zu können; geprüft wird allein, dass die ASYNC-Antwort verschlüsselt rausgeht.
        var gated = new GatedLockManager();
        var (d, conn, sid, tid) = Setup(gated, rejectUnencrypted: false);
        conn.Sessions[sid].TreeConnects[tid].EncryptData = true; // Tree verlangt Verschlüsselung
        (ulong p, ulong v) = OpenFile(d, conn, sid, tid, 4);

        var sent = new ConcurrentQueue<byte[]>();
        bool? forcedEncrypt = null;
        conn.SendRawAsync = (b, enc) => { forcedEncrypt = enc; sent.Enqueue(b); return Task.CompletedTask; };

        d.ProcessMessage(conn, TestHelpers.BuildLockRequest(6, sid, tid, p, v,
            [(0, 10, (uint)LockFlags.ExclusiveLock)]));
        gated.Complete(LockOutcome.Granted);
        await WaitForSend(sent);

        Assert.True(forcedEncrypt, "Die finale LOCK-Antwort auf einem verschlüsselten Tree muss verschlüsselt gesendet werden.");
    }

    [Fact]
    public async Task Cancel_AbortsPendingLock_WithStatusCancelled()
    {
        var gated = new GatedLockManager();
        var (d, conn, sid, tid) = Setup(gated);
        (ulong p, ulong v) = OpenFile(d, conn, sid, tid, 4);

        var sent = new ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        byte[] interim = d.ProcessMessage(conn, TestHelpers.BuildLockRequest(6, sid, tid, p, v,
            [(0, 10, (uint)LockFlags.ExclusiveLock)]));
        Assert.Equal(NtStatus.Pending, Smb2Header.Read(interim).Status);

        // CANCEL mit derselben MessageId → bricht den wartenden Lock ab (selbst ohne Antwort).
        byte[] cancel = TestHelpers.Concat(TestHelpers.BuildHeader(SmbCommand.Cancel, 6, sid, tid), CancelBody());
        Assert.Empty(d.ProcessMessage(conn, cancel));

        Smb2Header fh = Smb2Header.Read(await WaitForSend(sent));
        Assert.Equal(NtStatus.Cancelled, fh.Status);
    }

    // --- Setup ---

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(
        ILockManager? lockManager = null, bool rejectUnencrypted = true)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
            RejectUnencryptedAccess = rejectUnencrypted,
        };
        if (lockManager is not null) options.LockManager = lockManager;
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

    private static (ulong p, ulong v) OpenFile(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong mid)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            mid, sid, tid, "lock.txt", desiredAccess: 0x00000003 /* read+write */,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        return ExtractCreateFileId(create);
    }

    private static byte[] CancelBody()
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(b, 4); // StructureSize
        return b;
    }

    private static async Task<byte[]> WaitForSend(ConcurrentQueue<byte[]> queue)
    {
        for (int i = 0; i < 150; i++)
        {
            if (queue.TryDequeue(out byte[]? msg)) return msg;
            await Task.Delay(20);
        }
        throw new Xunit.Sdk.XunitException("Keine out-of-band-Antwort innerhalb des Zeitlimits erhalten.");
    }

    // --- Test-LockManager ---

    private sealed class DenyAllLockManager : ILockManager
    {
        public Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> e, bool fail, CancellationToken ct)
            => Task.FromResult(LockOutcome.Granted);
        public bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool forWrite) => false;
        public void ReleaseOwner(SmbOpen owner) { }
    }

    private sealed class GatedLockManager : ILockManager
    {
        private readonly TaskCompletionSource<LockOutcome> _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> e, bool fail, CancellationToken ct)
        {
            ct.Register(() => _tcs.TrySetResult(LockOutcome.Cancelled));
            return _tcs.Task;
        }
        public void Complete(LockOutcome outcome) => _tcs.TrySetResult(outcome);
        public bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool forWrite) => true;
        public void ReleaseOwner(SmbOpen owner) { }
    }

    // --- Parse-Hilfen ---

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    private static (ulong persistent, ulong vol) ExtractCreateFileId(byte[] response)
    {
        const int body = Smb2Header.Size;
        ulong persistent = BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 64, 8));
        ulong vol = BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 72, 8));
        return (persistent, vol);
    }
}
