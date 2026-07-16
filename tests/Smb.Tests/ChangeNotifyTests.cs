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

    // --- W3.1 buffering between two requests / W3.2 STATUS_NOTIFY_CLEANUP at CLOSE ---

    [Fact]
    public async Task ChangeInWindowBetweenRequests_IsDeliveredImmediately_OnReRegister()
    {
        var watcher = new ManualDirectoryWatcher();
        var (d, conn, sid, tid) = Setup(watcher);
        (ulong p, ulong v) = OpenEntry(d, conn, sid, tid, 4, "watched", isDir: true);

        var sent = new System.Collections.Concurrent.ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        // First request parks and establishes the per-open watch; complete it with a change.
        Assert.Equal(NtStatus.Pending, Smb2Header.Read(Notify(d, conn, sid, tid, 5, p, v)).Status);
        watcher.Fire(new FileNotifyEvent(FileNotifyAction.Added, "a.txt"));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(await WaitForSend(sent)).Status);

        // A change now arrives while the client has NO request registered — the pre-W3 gap. It must be
        // buffered on the open, then delivered in-band the moment the client re-registers (no interim).
        watcher.Fire(new FileNotifyEvent(FileNotifyAction.Removed, "b.txt"));
        byte[] resp = Notify(d, conn, sid, tid, 6, p, v);
        Smb2Header h = Smb2Header.Read(resp);
        Assert.Equal(NtStatus.Success, h.Status);
        Assert.False(h.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand)); // answered directly, not parked
        uint outLen = BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 4, 4));
        Assert.True(outLen > 0); // the buffered change was actually carried
    }

    [Fact]
    public void BufferOverflow_AnswersNotifyEnumDir()
    {
        var watcher = new ManualDirectoryWatcher();
        var (d, conn, sid, tid) = Setup(watcher, changeNotifyBufferLimit: 2);
        (ulong p, ulong v) = OpenEntry(d, conn, sid, tid, 4, "watched", isDir: true);
        conn.SendRawAsync = (_, _) => Task.CompletedTask;

        // Establish the watch, complete the first request, then flood past the buffer cap with no request parked.
        Assert.Equal(NtStatus.Pending, Smb2Header.Read(Notify(d, conn, sid, tid, 5, p, v)).Status);
        watcher.Fire(new FileNotifyEvent(FileNotifyAction.Added, "first.txt")); // completes request 5
        watcher.Fire(new FileNotifyEvent(FileNotifyAction.Added, "1.txt"));
        watcher.Fire(new FileNotifyEvent(FileNotifyAction.Added, "2.txt"));
        watcher.Fire(new FileNotifyEvent(FileNotifyAction.Added, "3.txt")); // exceeds cap 2 → overflow latched

        byte[] resp = Notify(d, conn, sid, tid, 6, p, v);
        Assert.Equal(NtStatus.NotifyEnumDir, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void ChangeBeforeFirstRegister_IsNotDelivered()
    {
        var watcher = new ManualDirectoryWatcher();
        var (d, conn, sid, tid) = Setup(watcher);
        (ulong p, ulong v) = OpenEntry(d, conn, sid, tid, 4, "watched", isDir: true);
        conn.SendRawAsync = (_, _) => Task.CompletedTask;

        // Nothing was watching before the first CHANGE_NOTIFY, so there is nothing to deliver: the first
        // request must park (STATUS_PENDING), not return an immediate answer. Guards against over-buffering.
        Assert.Equal(0, watcher.WatchCount);
        Assert.Equal(NtStatus.Pending, Smb2Header.Read(Notify(d, conn, sid, tid, 5, p, v)).Status);
        Assert.Equal(1, watcher.WatchCount);
    }

    [Fact]
    public void DifferentFilter_RestartsWatch_SameFilterReuses()
    {
        var watcher = new ManualDirectoryWatcher();
        var (d, conn, sid, tid) = Setup(watcher);
        (ulong p, ulong v) = OpenEntry(d, conn, sid, tid, 4, "watched", isDir: true);
        conn.SendRawAsync = (_, _) => Task.CompletedTask;

        // filter FileName → watch #1
        Notify(d, conn, sid, tid, 5, p, v, filter: 0x00000001);
        Assert.Equal(1, watcher.WatchCount);
        ManualDirectoryWatcher.Registration first = watcher.Active!;
        watcher.Fire(new FileNotifyEvent(FileNotifyAction.Added, "a.txt")); // complete request 5

        // Same (filter, tree) → the watch is reused, not restarted.
        Notify(d, conn, sid, tid, 6, p, v, filter: 0x00000001);
        Assert.Equal(1, watcher.WatchCount);
        watcher.Fire(new FileNotifyEvent(FileNotifyAction.Added, "b.txt")); // complete request 6

        // Different filter (DirName) → the old watch is disposed and a new one established.
        Notify(d, conn, sid, tid, 7, p, v, filter: 0x00000002);
        Assert.Equal(2, watcher.WatchCount);
        Assert.True(first.Disposed);
    }

    [Fact]
    public async Task Close_CompletesParkedChangeNotify_WithNotifyCleanup_AndClearsPending()
    {
        var watcher = new ManualDirectoryWatcher();
        var (d, conn, sid, tid) = Setup(watcher);
        (ulong p, ulong v) = OpenEntry(d, conn, sid, tid, 4, "watched", isDir: true);

        var sent = new System.Collections.Concurrent.ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        Assert.Equal(NtStatus.Pending, Smb2Header.Read(Notify(d, conn, sid, tid, 5, p, v)).Status);
        Assert.Single(conn.PendingRequests);

        // CLOSE the directory handle with the CHANGE_NOTIFY still parked (a client that just closes, without a
        // CANCEL first). §3.3.5.10: the outstanding notify is completed with STATUS_NOTIFY_CLEANUP — not the
        // generic STATUS_CANCELLED — and its watcher subscription is torn down (no leak).
        byte[] closeResp = d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(6, sid, tid, p, v));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(closeResp).Status);

        Smb2Header fh = Smb2Header.Read(await WaitForSend(sent));
        Assert.Equal(NtStatus.NotifyCleanup, fh.Status);
        Assert.True(fh.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand));
        Assert.Empty(conn.PendingRequests);
        Assert.True(watcher.Active!.Disposed);
    }

    // --- Setup ---

    private static byte[] Notify(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong mid,
        ulong p, ulong v, uint filter = FilterFileName)
        => d.ProcessMessage(conn, TestHelpers.BuildChangeNotifyRequest(mid, sid, tid, p, v, filter));

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(bool withWatcher)
        => Setup(withWatcher ? new FileSystemDirectoryWatcher() : new NullDirectoryWatcher());

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(
        IDirectoryWatcher watcher, int changeNotifyBufferLimit = 1024)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
            ChangeNotifyBufferLimit = changeNotifyBufferLimit,
        };
        options.DirectoryWatcher = watcher;
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

    /// <summary>
    /// A deterministic <see cref="IDirectoryWatcher"/>: it captures the callback of the most recently
    /// established watch and lets the test drive changes synchronously via <see cref="Fire"/> — no reliance
    /// on real filesystem-watcher timing. Tracks how many watches were established (to prove reuse vs restart)
    /// and whether each was disposed.
    /// </summary>
    private sealed class ManualDirectoryWatcher : IDirectoryWatcher
    {
        private readonly object _gate = new();
        private Registration? _active;

        public int WatchCount { get; private set; }
        public Registration? Active { get { lock (_gate) return _active; } }

        public IDisposable? Watch(string directoryFullPath, bool watchSubtree, ChangeNotifyFilter filter,
            Action<IReadOnlyList<FileNotifyEvent>> onChanges)
        {
            lock (_gate)
            {
                var reg = new Registration(watchSubtree, filter, onChanges);
                _active = reg;
                WatchCount++;
                return reg;
            }
        }

        public void Fire(params FileNotifyEvent[] events)
        {
            Registration? reg;
            lock (_gate) reg = _active;
            if (reg is { Disposed: false }) reg.OnChanges(events);
        }

        internal sealed class Registration(bool watchTree, ChangeNotifyFilter filter,
            Action<IReadOnlyList<FileNotifyEvent>> onChanges) : IDisposable
        {
            public bool WatchTree { get; } = watchTree;
            public ChangeNotifyFilter Filter { get; } = filter;
            public Action<IReadOnlyList<FileNotifyEvent>> OnChanges { get; } = onChanges;
            public bool Disposed { get; private set; }
            public void Dispose() => Disposed = true;
        }
    }
}
