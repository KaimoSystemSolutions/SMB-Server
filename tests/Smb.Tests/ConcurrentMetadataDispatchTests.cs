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
/// Concurrent metadata dispatch (docs/ENTERPRISE_HARDENING_ROADMAP.md, A2b): with
/// <see cref="SmbServerOptions.ConcurrentMetadataOps"/> on, CREATE/CLOSE/SET_INFO/QUERY_* leave the
/// per-connection barrier and are ordered/excluded per Open by the reader/writer queue. Verifies the
/// classifier, the key safety property (an exclusive CLOSE waits for inflight I/O of the same Open),
/// cross-Open parallelism, that lifecycle commands stay a barrier, and end-to-end functional correctness.
/// </summary>
public class ConcurrentMetadataDispatchTests
{
    // ─── Classification (feature on) ──────────────────────────────────────

    [Fact]
    public void Classifier_WithMetadataConcurrency_AcceptsMetadataOps_StillRejectsLifecycle()
    {
        var store = new MetadataGatedStore();
        (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) = Setup(store, concurrentMetadata: true);
        (ulong p, ulong v) = OpenFile(d, conn, sid, tid, 4, "a.txt");

        ulong mid = 10;
        Assert.True(d.TryBeginConcurrentFrame(conn, TestHelpers.BuildCloseRequest(mid++, sid, tid, p, v), false, out _));
        Assert.True(d.TryBeginConcurrentFrame(conn, TestHelpers.BuildQueryInfoRequest(mid++, sid, tid, p, v, 1, 5, 1024), false, out _));
        Assert.True(d.TryBeginConcurrentFrame(conn, TestHelpers.BuildQueryDirectoryRequest(mid++, sid, tid, p, v, 1, "*", 4096), false, out _));
        Assert.True(d.TryBeginConcurrentFrame(conn, TestHelpers.BuildSetInfoRequest(mid++, sid, tid, p, v, 1, 20, new byte[8]), false, out _));
        Assert.True(d.TryBeginConcurrentFrame(conn, TestHelpers.BuildCreateRequest(mid++, sid, tid, "b.txt", 0x1,
            (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile), false, out _));

        // Lifecycle commands remain a barrier even with the feature on.
        Assert.False(d.TryBeginConcurrentFrame(conn, TestHelpers.BuildLogoffRequest(mid++, sid), false, out _));
    }

    [Fact]
    public void Classifier_WithoutMetadataConcurrency_RejectsMetadataOps()
    {
        var store = new MetadataGatedStore();
        (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) = Setup(store, concurrentMetadata: false);
        (ulong p, ulong v) = OpenFile(d, conn, sid, tid, 4, "a.txt");

        // Default behavior: only READ/WRITE are concurrent; a CLOSE is a barrier op.
        Assert.False(d.TryBeginConcurrentFrame(conn, TestHelpers.BuildCloseRequest(10, sid, tid, p, v), false, out _));
    }

    // ─── Safety: exclusive CLOSE waits for inflight (shared) WRITE of the same Open ──

    [Fact]
    public async Task Close_WaitsForInflightWrite_OnSameOpen()
    {
        var store = new MetadataGatedStore();
        (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) = Setup(store, concurrentMetadata: true);
        (ulong p, ulong v) = OpenFile(d, conn, sid, tid, 4, "a.txt");

        try
        {
            // WRITE (shared) begins first and blocks in the backend; CLOSE (exclusive) is reserved after.
            Prepare(d, conn, TestHelpers.BuildWriteRequest(5, sid, tid, p, v, 0, Encoding.UTF8.GetBytes("x")), out var writeFrame);
            Prepare(d, conn, TestHelpers.BuildCloseRequest(6, sid, tid, p, v), out var closeFrame);

            Task<byte[]> writeTask = d.ExecutePreparedFrameAsync(conn, writeFrame).AsTask();
            Task<byte[]> closeTask = d.ExecutePreparedFrameAsync(conn, closeFrame).AsTask();

            await Task.Delay(150);
            Assert.False(closeTask.IsCompleted, "CLOSE must not run while a WRITE on the same Open is inflight.");
            Assert.False(writeTask.IsCompleted, "sanity: the WRITE is still gated in the backend.");

            store.ReleaseWrites();

            byte[] writeResp = await writeTask.WaitAsync(TimeSpan.FromSeconds(10));
            byte[] closeResp = await closeTask.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(NtStatus.Success, Smb2Header.Read(writeResp).Status);
            Assert.Equal(NtStatus.Success, Smb2Header.Read(closeResp).Status);
        }
        finally
        {
            store.ReleaseWrites();
        }
    }

    // ─── Cross-Open parallelism: a metadata op on a different Open is not blocked ──

    [Fact]
    public async Task MetadataOp_OnDifferentOpen_IsNotBlockedByInflightWrite()
    {
        var store = new MetadataGatedStore();
        (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) = Setup(store, concurrentMetadata: true);
        (ulong ap, ulong av) = OpenFile(d, conn, sid, tid, 4, "a.txt");
        (ulong bp, ulong bv) = OpenFile(d, conn, sid, tid, 5, "b.txt");

        try
        {
            // WRITE on A blocks; CLOSE on B (different Open → different scope) must complete meanwhile.
            Prepare(d, conn, TestHelpers.BuildWriteRequest(6, sid, tid, ap, av, 0, Encoding.UTF8.GetBytes("x")), out var writeA);
            Prepare(d, conn, TestHelpers.BuildCloseRequest(7, sid, tid, bp, bv), out var closeB);

            Task<byte[]> writeTask = d.ExecutePreparedFrameAsync(conn, writeA).AsTask();
            Task<byte[]> closeTask = d.ExecutePreparedFrameAsync(conn, closeB).AsTask();

            byte[] closeResp = await closeTask.WaitAsync(TimeSpan.FromSeconds(10)); // completes despite blocked WRITE on A
            Assert.Equal(NtStatus.Success, Smb2Header.Read(closeResp).Status);
            Assert.False(writeTask.IsCompleted, "the WRITE on A should still be gated.");

            store.ReleaseWrites();
            await writeTask.WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally
        {
            store.ReleaseWrites();
        }
    }

    // ─── Functional: a CLOSE via the concurrent path really tears the Open down ──

    [Fact]
    public async Task ConcurrentPath_Close_RemovesOpenFromSession()
    {
        var store = new MetadataGatedStore();
        (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) = Setup(store, concurrentMetadata: true);
        store.ReleaseWrites(); // no gating needed here
        (ulong p, ulong v) = OpenFile(d, conn, sid, tid, 4, "gone.txt");

        // CLOSE through the concurrent path.
        Prepare(d, conn, TestHelpers.BuildCloseRequest(5, sid, tid, p, v), out var closeFrame);
        byte[] closeResp = await d.ExecutePreparedFrameAsync(conn, closeFrame);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(closeResp).Status);

        // The Open is gone: a follow-up CLOSE on the same FileId is rejected (FILE_CLOSED).
        byte[] secondClose = d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(6, sid, tid, p, v));
        Assert.Equal(NtStatus.FileClosed, Smb2Header.Read(secondClose).Status);
    }

    // ─── End-to-end over the real host loop (TCP), feature on ─────────────

    [Fact]
    public async Task Host_ConcurrentMetadata_CreateQueryClose_Succeeds()
    {
        string dir = Path.Combine(Path.GetTempPath(), "smb-a2b-host-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        await File.WriteAllTextAsync(Path.Combine(dir, "doc.txt"), "hello");
        try
        {
            await using SmbServer server = SmbServerBuilder.Create()
                .WithEndpoint(IPAddress.Loopback, 0)
                .UseDevAuthentication()
                .Configure(o => o.ConcurrentMetadataOps = true) // A2b feature on
                .AddShare(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new Smb.FileSystem.Local.LocalFileStore(dir) })
                .Build();
            await server.StartAsync();

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, server.Endpoint.Port);
            await using NetworkStream stream = client.GetStream();

            await SendAsync(stream, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
            await ReceiveAsync(stream);
            await SendAsync(stream, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
            ulong sid = Smb2Header.Read(await ReceiveAsync(stream)).SessionId;
            await SendAsync(stream, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\s\Files"));
            uint tid = Smb2Header.Read(await ReceiveAsync(stream)).TreeId;

            await SendAsync(stream, TestHelpers.BuildCreateRequest(3, sid, tid, "doc.txt", 0x1,
                (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile));
            byte[] createResp = await ReceiveAsync(stream);
            Assert.Equal(NtStatus.Success, Smb2Header.Read(createResp).Status);
            (ulong p, ulong v) = ExtractCreateFileId(createResp);

            // QUERY_INFO then CLOSE go through the concurrent metadata path in the host.
            await SendAsync(stream, TestHelpers.BuildQueryInfoRequest(4, sid, tid, p, v, 1, 5, 1024));
            Assert.Equal(NtStatus.Success, Smb2Header.Read(await ReceiveAsync(stream)).Status);

            await SendAsync(stream, TestHelpers.BuildCloseRequest(5, sid, tid, p, v));
            Assert.Equal(NtStatus.Success, Smb2Header.Read(await ReceiveAsync(stream)).Status);

            await server.StopAsync();
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best-effort */ }
        }
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
        var payload = new byte[NbssFrame.ReadLength(prefix)];
        await stream.ReadExactlyAsync(payload).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        return payload;
    }

    // ─── Helpers ──────────────────────────────────────────────────────────

    /// <summary>Runs the host's read-loop steps for one eligible frame: classify → reserve scope.</summary>
    private static void Prepare(Smb2Dispatcher d, SmbConnection conn, byte[] message, out Smb2Dispatcher.PreparedFrame frame)
    {
        Assert.True(d.TryBeginConcurrentFrame(conn, message, false, out frame));
        frame = d.ReserveScope(frame);
    }

    private static (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(IFileStore store, bool concurrentMetadata)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
            ConcurrentMetadataOps = concurrentMetadata,
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
            mid, sid, tid, name, 0x3 /* READ|WRITE */, (uint)CreateDisposition.OpenIf, (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        return ExtractCreateFileId(create);
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    private static (ulong persistent, ulong vol) ExtractCreateFileId(byte[] response)
    {
        const int body = Smb2Header.Size;
        ulong persistent = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 64, 8));
        ulong vol = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 72, 8));
        return (persistent, vol);
    }

    /// <summary>In-memory store whose WRITEs block until <see cref="ReleaseWrites"/>; opens any path.</summary>
    private sealed class MetadataGatedStore : IFileStore
    {
        private readonly TaskCompletionSource _writeGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private static readonly byte[] Content = Encoding.UTF8.GetBytes("content");

        public void ReleaseWrites() => _writeGate.TrySetResult();

        public ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(
            string path, FileAccessIntent access, CreateDispositionIntent disposition,
            bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
            => new(FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(new Handle(path), CreateOutcome.Opened)));

        public ValueTask<FileStoreResult<int>> ReadAsync(
            IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (offset >= Content.Length) return new(FileStoreResult<int>.Ok(0));
            int n = Math.Min(buffer.Length, Content.Length - (int)offset);
            Content.AsSpan((int)offset, n).CopyTo(buffer.Span);
            return new(FileStoreResult<int>.Ok(n));
        }

        public async ValueTask<FileStoreResult<int>> WriteAsync(
            IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        {
            await _writeGate.Task.ConfigureAwait(false);
            return FileStoreResult<int>.Ok(data.Length);
        }

        public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(
            IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
            => new(FileStoreResult<IReadOnlyList<FileEntryInfo>>.Ok(Array.Empty<FileEntryInfo>()));

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
