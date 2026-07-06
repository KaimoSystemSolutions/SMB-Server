using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.Host;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Concurrent READ/WRITE dispatches (docs/ASYNC_IO_ROADMAP.md, A4): frame classification
/// (<c>TryBeginConcurrentFrame</c>), deterministic overlap proof at the dispatcher level,
/// and out-of-order responses over a real TCP connection (host read loop).
/// </summary>
public class ConcurrentIoTests
{
    // ─── Classification ───────────────────────────────────────────────────

    [Fact]
    public void Classifier_AcceptsSingleReadWrite_RejectsRest()
    {
        var store = new GatedReadStore();
        (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) = Setup(store);
        (ulong p, ulong v) = OpenFile(d, conn, sid, tid, 4, "fast.txt");

        // Single READ → allowed concurrently (consumes the sequence window).
        byte[] read = TestHelpers.BuildReadRequest(5, sid, tid, p, v, length: 16, offset: 0);
        Assert.True(d.TryBeginConcurrentFrame(conn, read, false, out _));

        // Same MessageId again → window already consumed → sequential path.
        Assert.False(d.TryBeginConcurrentFrame(conn, read, false, out _));

        // WRITE → allowed.
        byte[] write = TestHelpers.BuildWriteRequest(6, sid, tid, p, v, 0, Encoding.UTF8.GetBytes("x"));
        Assert.True(d.TryBeginConcurrentFrame(conn, write, false, out _));

        // CREATE → never concurrent.
        byte[] create = TestHelpers.BuildCreateRequest(7, sid, tid, "fast.txt", 0x1,
            (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile);
        Assert.False(d.TryBeginConcurrentFrame(conn, create, false, out _));

        // Compound (NextCommand != 0) → never concurrent.
        byte[] compound = TestHelpers.BuildReadRequest(7, sid, tid, p, v, length: 16, offset: 0);
        BinaryPrimitives.WriteUInt32LittleEndian(compound.AsSpan(20, 4), 96); // patch NextCommand
        Assert.False(d.TryBeginConcurrentFrame(conn, compound, false, out _));
    }

    [Fact]
    public void Classifier_RejectsBeforeNegotiate()
    {
        var store = new GatedReadStore();
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(
                new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw"),
                new NtlmServerOptions { NetbiosDomainName = "DOM" }),
        };
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = store });
        var d = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection(); // no NEGOTIATE performed

        byte[] read = TestHelpers.BuildReadRequest(0, 1, 1, 1, 1, 16, 0);
        Assert.False(d.TryBeginConcurrentFrame(conn, read, false, out _));
    }

    // ─── Overlap (dispatcher level, deterministic) ────────────────────────

    [Fact]
    public async Task PreparedFrames_ExecuteConcurrently_SlowReadDoesNotBlockFast()
    {
        var store = new GatedReadStore();
        (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) = Setup(store);
        (ulong sp, ulong sv) = OpenFile(d, conn, sid, tid, 4, "slow.txt");
        (ulong fp, ulong fv) = OpenFile(d, conn, sid, tid, 5, "fast.txt");

        try
        {
            byte[] readSlow = TestHelpers.BuildReadRequest(6, sid, tid, sp, sv, 64, 0);
            byte[] readFast = TestHelpers.BuildReadRequest(7, sid, tid, fp, fv, 64, 0);
            Assert.True(d.TryBeginConcurrentFrame(conn, readSlow, false, out Smb2Dispatcher.PreparedFrame f1));
            Assert.True(d.TryBeginConcurrentFrame(conn, readFast, false, out Smb2Dispatcher.PreparedFrame f2));

            Task<byte[]> slowTask = d.ExecutePreparedFrameAsync(conn, f1).AsTask();
            Task<byte[]> fastTask = d.ExecutePreparedFrameAsync(conn, f2).AsTask();

            // The fast READ completes WHILE the slow one is still blocked in the backend.
            byte[] fastResp = await fastTask.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(NtStatus.Success, Smb2Header.Read(fastResp).Status);
            Assert.Equal(7UL, Smb2Header.Read(fastResp).MessageId);
            Assert.False(slowTask.IsCompleted, "The slow READ should not have completed yet.");

            store.ReleaseSlowReads();
            byte[] slowResp = await slowTask.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(NtStatus.Success, Smb2Header.Read(slowResp).Status);
            Assert.Equal(6UL, Smb2Header.Read(slowResp).MessageId);
        }
        finally
        {
            store.ReleaseSlowReads(); // never clean up with a blocked backend
        }
    }

    // ─── Out-of-order over real TCP (host read loop) ──────────────────────

    [Fact]
    public async Task Host_PipelinedReads_AnswerOutOfOrder()
    {
        var store = new GatedReadStore();
        await using SmbServer server = SmbServerBuilder.Create()
            .WithEndpoint(IPAddress.Loopback, 0)
            .UseDevAuthentication()
            .AddShare(new Share { Name = "Files", Type = ShareType.Disk, FileStore = store })
            .Build();
        await server.StartAsync();

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, server.Endpoint.Port);
            await using NetworkStream stream = client.GetStream();

            await SendAsync(stream, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
            await ReceiveAsync(stream);

            await SendAsync(stream, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
            byte[] ss = await ReceiveAsync(stream);
            Assert.Equal(NtStatus.Success, Smb2Header.Read(ss).Status);
            ulong sid = Smb2Header.Read(ss).SessionId;

            await SendAsync(stream, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\s\Files"));
            byte[] tc = await ReceiveAsync(stream);
            uint tid = Smb2Header.Read(tc).TreeId;

            await SendAsync(stream, TestHelpers.BuildCreateRequest(3, sid, tid, "slow.txt", 0x1,
                (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile));
            (ulong sp, ulong sv) = ExtractCreateFileId(await ReceiveAsync(stream));

            await SendAsync(stream, TestHelpers.BuildCreateRequest(4, sid, tid, "fast.txt", 0x1,
                (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile));
            (ulong fp, ulong fv) = ExtractCreateFileId(await ReceiveAsync(stream));

            // Pipeline two READs WITHOUT reading the response in between: first the blocking
            // one (slow.txt), then the immediate one (fast.txt).
            await SendAsync(stream, TestHelpers.BuildReadRequest(5, sid, tid, sp, sv, 64, 0));
            await SendAsync(stream, TestHelpers.BuildReadRequest(6, sid, tid, fp, fv, 64, 0));

            // The response to the SECOND request arrives first (out-of-order) — proof that
            // the host overlaps both backend accesses instead of serializing them.
            byte[] first = await ReceiveAsync(stream);
            Assert.Equal(6UL, Smb2Header.Read(first).MessageId);
            Assert.Equal(NtStatus.Success, Smb2Header.Read(first).Status);

            store.ReleaseSlowReads();
            byte[] second = await ReceiveAsync(stream);
            Assert.Equal(5UL, Smb2Header.Read(second).MessageId);
            Assert.Equal(NtStatus.Success, Smb2Header.Read(second).Status);
        }
        finally
        {
            store.ReleaseSlowReads(); // never shut down with a blocked backend (drain would wait)
            await server.StopAsync();
        }
    }

    // ─── Setup / helpers ──────────────────────────────────────────────────

    private static (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(IFileStore store)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = store });

        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();

        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        uint treeId = Smb2Header.Read(dispatcher.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\s\Files"))).TreeId;
        return (dispatcher, conn, sessionId, treeId);
    }

    private static (ulong p, ulong v) OpenFile(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong mid, string name)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            mid, sid, tid, name, 0x1, (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        return ExtractCreateFileId(create);
    }

    private static async Task SendAsync(NetworkStream stream, byte[] message)
    {
        await stream.WriteAsync(NbssFrame.Wrap(message));
        await stream.FlushAsync();
    }

    private static async Task<byte[]> ReceiveAsync(NetworkStream stream)
    {
        var prefix = new byte[NbssFrame.HeaderLength];
        await stream.ReadExactlyAsync(prefix).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        int length = NbssFrame.ReadLength(prefix);
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        return payload;
    }

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

    // ─── Backend with controllably slow READ ──────────────────────────────

    /// <summary>
    /// In-memory store with two files: READs on <c>slow.txt</c> block until
    /// <see cref="ReleaseSlowReads"/> is called; <c>fast.txt</c> responds immediately.
    /// Deterministic proof of overlapping backend I/O.
    /// </summary>
    private sealed class GatedReadStore : IFileStore
    {
        private readonly TaskCompletionSource _slowGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private static readonly byte[] Content = Encoding.UTF8.GetBytes("content");

        public void ReleaseSlowReads() => _slowGate.TrySetResult();

        public ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(
            string path, FileAccessIntent access, CreateDispositionIntent disposition,
            bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
            => path is "slow.txt" or "fast.txt"
                ? new(FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(new Handle(path), CreateOutcome.Opened)))
                : new(FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectNameNotFound));

        public async ValueTask<FileStoreResult<int>> ReadAsync(
            IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (handle.Path == "slow.txt")
                await _slowGate.Task.ConfigureAwait(false);
            if (offset >= Content.Length)
                return FileStoreResult<int>.Ok(0);
            int n = Math.Min(buffer.Length, Content.Length - (int)offset);
            Content.AsSpan((int)offset, n).CopyTo(buffer.Span);
            return FileStoreResult<int>.Ok(n);
        }

        public ValueTask<FileStoreResult<int>> WriteAsync(
            IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
            => new(FileStoreResult<int>.Ok(data.Length));

        public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(
            IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
            => new(FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(NtStatus.InvalidParameter));

        public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default)
            => new(NtStatus.Success);

        public ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default)
            => new(NtStatus.Success);

        public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default)
            => new(NtStatus.Success);

        public ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default)
            => new(NtStatus.Success);

        private sealed class Handle(string path) : IFileHandle
        {
            public string Path { get; } = path;
            public bool IsDirectory => false;
            public FileEntryInfo GetInfo() => new()
            {
                Name = Path,
                Attributes = SmbFileAttributes.Normal,
                EndOfFile = Content.Length,
                AllocationSize = 4096,
            };
            public void Dispose() { }
        }
    }
}
