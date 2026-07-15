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
/// CHANGE_NOTIFY end-to-end via the dispatcher: validation, NOT_SUPPORTED without a watcher,
/// interim STATUS_PENDING + cancellation via CANCEL, and a real filesystem watcher run.
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
    public void ChangeNotify_OnFile_ReturnsInvalidParameter()
    {
        var (d, conn, sid, tid) = Setup(withWatcher: false);
        (ulong p, ulong v) = OpenEntry(d, conn, sid, tid, 4, "file.txt", isDir: false);

        byte[] resp = d.ProcessMessage(conn,
            TestHelpers.BuildChangeNotifyRequest(5, sid, tid, p, v, FilterFileName));
        Assert.Equal(NtStatus.InvalidParameter, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void ChangeNotify_WithoutWatcher_ReturnsNotSupported()
    {
        var (d, conn, sid, tid) = Setup(withWatcher: false);
        (ulong p, ulong v) = OpenEntry(d, conn, sid, tid, 4, "watched", isDir: true);

        byte[] resp = d.ProcessMessage(conn,
            TestHelpers.BuildChangeNotifyRequest(5, sid, tid, p, v, FilterFileName));
        Assert.Equal(NtStatus.NotSupported, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public async Task ChangeNotify_WithWatcher_SendsInterimPending_ThenNotification()
    {
        var (d, conn, sid, tid) = Setup(withWatcher: true);
        (ulong p, ulong v) = OpenEntry(d, conn, sid, tid, 4, "watched", isDir: true);

        var sent = new System.Collections.Concurrent.ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        byte[] interim = d.ProcessMessage(conn,
            TestHelpers.BuildChangeNotifyRequest(5, sid, tid, p, v, FilterFileName));
        Smb2Header ih = Smb2Header.Read(interim);
        Assert.Equal(NtStatus.Pending, ih.Status);
        Assert.True(ih.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand));

        // Trigger a filesystem change. Re-trigger on every poll (with a fresh name) so a slow or
        // loaded CI runner — where the FileSystemWatcher may not be armed yet, or drops the first
        // event — still produces a notification instead of a spurious timeout.
        int n = 0;
        byte[] final = await WaitForSend(sent,
            () => File.WriteAllText(Path.Combine(_shareDir, "watched", $"new{n++}.txt"), "y"));
        Smb2Header fh = Smb2Header.Read(final);
        Assert.Equal(NtStatus.Success, fh.Status);
        Assert.True(fh.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand));
        Assert.Equal(ih.AsyncId, fh.AsyncId);
    }

    [Fact]
    public async Task Cancel_AbortsPendingChangeNotify_WithStatusCancelled()
    {
        var (d, conn, sid, tid) = Setup(withWatcher: true);
        (ulong p, ulong v) = OpenEntry(d, conn, sid, tid, 4, "watched", isDir: true);

        var sent = new System.Collections.Concurrent.ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        byte[] interim = d.ProcessMessage(conn,
            TestHelpers.BuildChangeNotifyRequest(5, sid, tid, p, v, FilterFileName));
        Assert.Equal(NtStatus.Pending, Smb2Header.Read(interim).Status);

        // Send CANCEL with the same MessageId.
        byte[] cancelBody = new byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(cancelBody, 4);
        byte[] cancel = TestHelpers.Concat(TestHelpers.BuildHeader(SmbCommand.Cancel, 5, sid, tid), cancelBody);
        Assert.Empty(d.ProcessMessage(conn, cancel));

        Smb2Header fh = Smb2Header.Read(await WaitForSend(sent));
        Assert.Equal(NtStatus.Cancelled, fh.Status);
    }

    /// <summary>
    /// The shape a real Windows client actually sends to cancel a parked CHANGE_NOTIFY: SMB2_FLAGS_ASYNC_COMMAND
    /// with the AsyncId from the interim response, and a MessageId field that is <b>not</b> the notify's
    /// MessageId. §3.3.5.16 says to match on AsyncId whenever that flag is set; matching on MessageId instead
    /// missed it entirely, the notify was never completed, and the client blocked for its own ~65 s timeout —
    /// observed as Explorer freezing when a folder window on the share was closed. The sync-CANCEL case above
    /// passed throughout, because it cancels by the MessageId the old lookup happened to use.
    /// </summary>
    [Fact]
    public async Task AsyncCancel_ByAsyncId_AbortsPendingChangeNotify_WithStatusCancelled()
    {
        var (d, conn, sid, tid) = Setup(withWatcher: true);
        (ulong p, ulong v) = OpenEntry(d, conn, sid, tid, 4, "watched", isDir: true);

        var sent = new System.Collections.Concurrent.ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        byte[] interim = d.ProcessMessage(conn,
            TestHelpers.BuildChangeNotifyRequest(5, sid, tid, p, v, FilterFileName));
        Smb2Header ih = Smb2Header.Read(interim);
        Assert.Equal(NtStatus.Pending, ih.Status);

        var cancelHeader = new Smb2Header
        {
            Command = SmbCommand.Cancel,
            MessageId = 99,                          // deliberately NOT the CHANGE_NOTIFY's MessageId
            SessionId = sid,
            Flags = Smb2HeaderFlags.AsyncCommand,
            AsyncId = ih.AsyncId,                    // the only thing that identifies the target
        };
        byte[] cancelBody = new byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(cancelBody, 4);
        Assert.Empty(d.ProcessMessage(conn, TestHelpers.Concat(cancelHeader.ToArray(), cancelBody)));

        Smb2Header fh = Smb2Header.Read(await WaitForSend(sent));
        Assert.Equal(NtStatus.Cancelled, fh.Status);
    }

    // --- Setup ---

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(bool withWatcher)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.DirectoryWatcher = withWatcher ? new FileSystemDirectoryWatcher() : new NullDirectoryWatcher();
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

    private static (ulong p, ulong v) OpenEntry(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong mid,
        string name, bool isDir)
    {
        uint options = isDir ? (uint)CreateOptions.DirectoryFile : (uint)CreateOptions.NonDirectoryFile;
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            mid, sid, tid, name, desiredAccess: 0x00100080 /* GENERIC_READ */,
            disposition: (uint)CreateDisposition.Open, options: options));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8)));
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    private static async Task<byte[]> WaitForSend(
        System.Collections.Concurrent.ConcurrentQueue<byte[]> queue, Action? retrigger = null)
    {
        for (int i = 0; i < 250; i++)
        {
            if (queue.TryDequeue(out byte[]? msg)) return msg;
            retrigger?.Invoke();
            await Task.Delay(20);
        }
        throw new Xunit.Sdk.XunitException("No out-of-band CHANGE_NOTIFY response received within the time limit.");
    }
}
