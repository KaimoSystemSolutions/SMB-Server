using System.Buffers.Binary;
using System.Text;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Notification;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// CHANGE_NOTIFY end-to-end über den Dispatcher: Validierung, NOT_SUPPORTED ohne Watcher,
/// Interim STATUS_PENDING + Abbruch via CANCEL, sowie ein echter Dateisystem-Watcher-Lauf.
/// </summary>
public class ChangeNotifyTests : IDisposable
{
    private const uint FilterFileName = 0x00000001;
    private readonly string _shareDir;

    public ChangeNotifyTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbnotify_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(_shareDir, "watched"));
        File.WriteAllText(Path.Combine(_shareDir, "file.txt"), "x");
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void ChangeNotifyMessage_ParseRequest_Roundtrip()
    {
        byte[] msg = TestHelpers.BuildChangeNotifyRequest(9, sessionId: 2, treeId: 1,
            persistentId: 0xAA, volatileId: 0xBB, completionFilter: 0x17, flags: ChangeNotifyMessage.FlagWatchTree);
        ChangeNotifyMessage.Request req = ChangeNotifyMessage.ParseRequest(msg, Smb2Header.Size);
        Assert.Equal(0xAAul, req.PersistentId);
        Assert.Equal(0xBBul, req.VolatileId);
        Assert.Equal(0x17u, req.CompletionFilter);
        Assert.True(req.WatchTree);
    }

    [Fact]
    public void ChangeNotify_OnFileHandle_ReturnsInvalidParameter()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = OpenPath(d, conn, sid, tid, "file.txt", directory: false);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildChangeNotifyRequest(6, sid, tid, p, v, FilterFileName));
        Assert.Equal(NtStatus.InvalidParameter, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void ChangeNotify_WithNullWatcher_ReturnsNotSupported()
    {
        var (d, conn, sid, tid) = Setup(new NullDirectoryWatcher());
        (ulong p, ulong v) = OpenPath(d, conn, sid, tid, "watched", directory: true);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildChangeNotifyRequest(6, sid, tid, p, v, FilterFileName));
        Assert.Equal(NtStatus.NotSupported, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public async Task ChangeNotify_PendingThenCancelled()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = OpenPath(d, conn, sid, tid, "watched", directory: true);

        var sent = new System.Collections.Concurrent.ConcurrentQueue<byte[]>();
        conn.SendRawAsync = b => { sent.Enqueue(b); return Task.CompletedTask; };

        byte[] interim = d.ProcessMessage(conn, TestHelpers.BuildChangeNotifyRequest(6, sid, tid, p, v, FilterFileName));
        Assert.Equal(NtStatus.Pending, Smb2Header.Read(interim).Status);

        byte[] cancel = TestHelpers.Concat(TestHelpers.BuildHeader(SmbCommand.Cancel, 6, sid, tid), CancelBody());
        Assert.Empty(d.ProcessMessage(conn, cancel));

        Smb2Header fh = Smb2Header.Read(await WaitForSend(sent));
        Assert.Equal(NtStatus.Cancelled, fh.Status);
    }

    [Fact]
    public async Task ChangeNotify_FileCreated_DeliversAddedEvent()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = OpenPath(d, conn, sid, tid, "watched", directory: true);

        var sent = new System.Collections.Concurrent.ConcurrentQueue<byte[]>();
        conn.SendRawAsync = b => { sent.Enqueue(b); return Task.CompletedTask; };

        byte[] interim = d.ProcessMessage(conn, TestHelpers.BuildChangeNotifyRequest(6, sid, tid, p, v, FilterFileName));
        Assert.Equal(NtStatus.Pending, Smb2Header.Read(interim).Status);

        await Task.Delay(150); // dem Watcher Zeit geben, scharf zu werden
        File.WriteAllText(Path.Combine(_shareDir, "watched", "neu.txt"), "hallo");

        byte[] final = await WaitForSend(sent);
        Smb2Header fh = Smb2Header.Read(final);
        Assert.Equal(NtStatus.Success, fh.Status);
        Assert.True(fh.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand));
        Assert.Contains("neu.txt", ParseNotifyNames(final));
    }

    // --- Setup / Hilfen ---

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(IDirectoryWatcher? watcher = null)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        if (watcher is not null) options.DirectoryWatcher = watcher;
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

    private static (ulong p, ulong v) OpenPath(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, string name, bool directory)
    {
        uint options = directory ? (uint)CreateOptions.DirectoryFile : (uint)CreateOptions.NonDirectoryFile;
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            4, sid, tid, name, desiredAccess: 0x00000001, disposition: (uint)CreateDisposition.Open, options: options));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        const int body = Smb2Header.Size;
        ulong p = BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8));
        ulong v = BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8));
        return (p, v);
    }

    private static byte[] CancelBody()
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(b, 4);
        return b;
    }

    private static async Task<byte[]> WaitForSend(System.Collections.Concurrent.ConcurrentQueue<byte[]> queue)
    {
        for (int i = 0; i < 200; i++)
        {
            if (queue.TryDequeue(out byte[]? msg)) return msg;
            await Task.Delay(20);
        }
        throw new Xunit.Sdk.XunitException("Keine out-of-band-Antwort innerhalb des Zeitlimits erhalten.");
    }

    private static List<string> ParseNotifyNames(byte[] response)
    {
        const int bodyOff = Smb2Header.Size;
        int bufOff = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(bodyOff + 2, 2));
        uint bufLen = BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(bodyOff + 4, 4));
        var names = new List<string>();
        if (bufLen == 0 || bufOff == 0) return names;

        int off = bufOff;
        int end = bufOff + (int)bufLen;
        while (off + 12 <= end)
        {
            uint next = BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(off, 4));
            uint nameLen = BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(off + 8, 4));
            names.Add(Encoding.Unicode.GetString(response.AsSpan(off + 12, (int)nameLen)));
            if (next == 0) break;
            off += (int)next;
        }
        return names;
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }
}
