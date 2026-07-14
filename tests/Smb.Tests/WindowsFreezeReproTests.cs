using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Smb.FileSystem;
using Smb.Host;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Smb.Server;
using Smb.Server.Authorization;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// docs/WINDOWS_COMPATIBILITY_ROADMAP.md, Phase W0 — <b>the freeze, proven</b>.
/// <para>
/// Root cause (verified against the code): with <see cref="SmbServerOptions.ConcurrentMetadataOps"/>
/// <b>off</b> (the default), a metadata op (here CREATE) is a per-connection <i>barrier</i>. The host read
/// loop runs it with <c>await ProcessMessageAsync(...)</c> <b>inline in the loop</b>
/// (<c>SmbConnectionHandler</c> step 5), so it reads <b>no further frame</b> until that op finishes. A slow
/// backend CREATE therefore freezes the <i>entire connection</i> — including an unrelated READ on a file
/// that is already open and instantly served. This is exactly what Explorer experiences when a background
/// CREATE/metadata storm stalls the foreground.
/// </para>
/// <para>
/// The two tests share one backend (CREATE on <c>slow.txt</c> blocks until released; READ is instant) and
/// differ only in the flag, isolating the barrier as the cause:
/// <list type="bullet">
/// <item><b>Default (barrier):</b> the unrelated READ gets no response while the CREATE is stuck → freeze.</item>
/// <item><b>ConcurrentMetadataOps on:</b> the READ completes immediately while the CREATE is still stuck → fixed.</item>
/// </list>
/// The block is path-gated (not timing-based) so the proof is deterministic, not flaky.
/// </para>
/// </summary>
public class WindowsFreezeReproTests
{
    // Message IDs used on the wire (must strictly increase per the sequence window).
    private const ulong MidOpenFast = 4;
    private const ulong MidSlowCreate = 5;
    private const ulong MidRead = 6;

    [Fact]
    public async Task DefaultBarrier_SlowMetadataOp_FreezesUnrelatedRead()
    {
        var store = new SlowCreateGatedStore();
        await using SmbServer server = await StartServerAsync(store, concurrentMetadata: false);
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, server.Endpoint.Port);
            await using NetworkStream stream = client.GetStream();
            (ulong sid, uint tid) = await HandshakeAsync(stream);
            (ulong fp, ulong fv) = await OpenFastFileAsync(stream, sid, tid);

            // Pipeline a slow CREATE (stuck in the backend) followed by a READ on the already-open fast
            // file. The read loop reads the CREATE first, enters the barrier, and blocks — so it never even
            // reads the READ frame off the socket.
            await SendAsync(stream, TestHelpers.BuildCreateRequest(MidSlowCreate, sid, tid, "slow.txt", 0x1,
                (uint)CreateDisposition.OpenIf, (uint)CreateOptions.NonDirectoryFile));
            await SendAsync(stream, TestHelpers.BuildReadRequest(MidRead, sid, tid, fp, fv, length: 4, offset: 0));

            // FREEZE: nothing comes back while the CREATE is stuck, even though the READ is independent and
            // would take microseconds. A generous window makes a false "freeze" impossible — as long as the
            // gate is shut there is no code path that can answer.
            byte[]? early = await TryReceiveAsync(stream, TimeSpan.FromSeconds(2));
            Assert.Null(early);

            // Release the backend → both responses now flow. Proves the connection was merely frozen, not dead.
            store.ReleaseCreates();
            byte[] a = await ReceiveAsync(stream);
            byte[] b = await ReceiveAsync(stream);
            var mids = new[] { Smb2Header.Read(a).MessageId, Smb2Header.Read(b).MessageId };
            Assert.Contains(MidSlowCreate, mids);
            Assert.Contains(MidRead, mids);

            await server.StopAsync();
        }
        finally
        {
            store.ReleaseCreates(); // never leave the drain/shutdown blocked
        }
    }

    [Fact]
    public async Task ConcurrentMetadataOps_SlowMetadataOp_UnrelatedReadCompletes()
    {
        var store = new SlowCreateGatedStore();
        await using SmbServer server = await StartServerAsync(store, concurrentMetadata: true);
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, server.Endpoint.Port);
            await using NetworkStream stream = client.GetStream();
            (ulong sid, uint tid) = await HandshakeAsync(stream);
            (ulong fp, ulong fv) = await OpenFastFileAsync(stream, sid, tid);

            // Same pipeline, feature on: CREATE runs free (its FileId does not exist yet) as a background
            // task, so the read loop keeps going and dispatches the READ concurrently.
            await SendAsync(stream, TestHelpers.BuildCreateRequest(MidSlowCreate, sid, tid, "slow.txt", 0x1,
                (uint)CreateDisposition.OpenIf, (uint)CreateOptions.NonDirectoryFile));
            await SendAsync(stream, TestHelpers.BuildReadRequest(MidRead, sid, tid, fp, fv, length: 4, offset: 0));

            // NO FREEZE: the READ (mid 6) answers first, while the CREATE (mid 5) is still stuck at the gate.
            byte[] first = await ReceiveAsync(stream, TimeSpan.FromSeconds(10));
            Smb2Header firstHeader = Smb2Header.Read(first);
            Assert.Equal(MidRead, firstHeader.MessageId);
            Assert.Equal(NtStatus.Success, firstHeader.Status);

            // Release the gate → the CREATE completes afterwards.
            store.ReleaseCreates();
            byte[] second = await ReceiveAsync(stream, TimeSpan.FromSeconds(10));
            Assert.Equal(MidSlowCreate, Smb2Header.Read(second).MessageId);

            await server.StopAsync();
        }
        finally
        {
            store.ReleaseCreates();
        }
    }

    /// <summary>
    /// docs/WINDOWS_COMPATIBILITY_ROADMAP.md W2.2 — <b>the boundary of the freeze fix for overridden auth</b>.
    /// <para>
    /// A per-file rights check that lives in a custom <c>IFileStore.CreateAsync</c> is latency in the CREATE
    /// dispatch, so <see cref="SmbServerOptions.ConcurrentMetadataOps"/> covers it (proven by the CREATE tests
    /// above). But <see cref="IShareAccessPolicy.AuthorizeConnect"/> runs at TREE_CONNECT, and TREE_CONNECT is
    /// a lifecycle op → <b>always a barrier, never in the concurrent path</b>. So a slow <i>synchronous</i>
    /// connect-time policy freezes the read loop even with the flag on — here it freezes an unrelated READ on a
    /// share that is already connected and working. Takeaway for a library consumer: put per-file rights in the
    /// <c>IFileStore</c> (the flag covers it) and <b>cache</b> the connect-time policy decision — the seam is
    /// synchronous and outside the flag's scope.
    /// </para>
    /// </summary>
    [Fact]
    public async Task SlowAuthorizeConnect_FreezesOtherShareIo_EvenWithConcurrentMetadataFlag()
    {
        var policy = new GatedConnectPolicy(slowShare: "Slow");
        // Flag ON — to show this freeze is NOT the metadata-barrier one and the flag does not fix it.
        await using SmbServer server = await StartAuthServerAsync(policy, concurrentMetadata: true);
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, server.Endpoint.Port);
            await using NetworkStream stream = client.GetStream();
            (ulong sid, uint filesTid) = await HandshakeAsync(stream); // connects "Files" (policy grants instantly)
            (ulong fp, ulong fv) = await OpenFastFileAsync(stream, sid, filesTid);

            // Connect the "Slow" share (blocks in AuthorizeConnect) pipelined with a READ on the already-open
            // fast file in "Files". The read loop hits the TREE_CONNECT barrier, blocks in the synchronous
            // policy, and never reads the READ frame → the unrelated, working share's I/O freezes.
            await SendAsync(stream, TestHelpers.BuildTreeConnectRequest(MidSlowCreate, sid, @"\\s\Slow"));
            await SendAsync(stream, TestHelpers.BuildReadRequest(MidRead, sid, filesTid, fp, fv, length: 4, offset: 0));

            byte[]? early = await TryReceiveAsync(stream, TimeSpan.FromSeconds(2));
            Assert.Null(early); // frozen — ConcurrentMetadataOps does not cover connect-time auth latency

            policy.Release();
            byte[] a = await ReceiveAsync(stream);
            byte[] b = await ReceiveAsync(stream);
            var mids = new[] { Smb2Header.Read(a).MessageId, Smb2Header.Read(b).MessageId };
            Assert.Contains(MidSlowCreate, mids); // the Slow TREE_CONNECT
            Assert.Contains(MidRead, mids);       // the unrelated READ, unblocked only after the policy returned

            await server.StopAsync();
        }
        finally
        {
            policy.Release(); // never leave the drain/shutdown blocked
        }
    }

    /// <summary>
    /// docs/WINDOWS_COMPATIBILITY_ROADMAP.md W6.2 — proves the dispatcher now consults the <b>async</b>
    /// authorization seam at TREE_CONNECT. The policy grants synchronously but denies asynchronously, so the
    /// connection is rejected only if <see cref="IShareAccessPolicy.AuthorizeConnectAsync"/> is the path taken
    /// (a regression to the sync <c>AuthorizeConnect</c> would wrongly grant).
    /// </summary>
    [Fact]
    public async Task AsyncSeam_IsUsedAtTreeConnect_AsyncDenyRejects()
    {
        var policy = new AsyncDenyPolicy();
        await using SmbServer server = await StartAuthServerAsync(policy, concurrentMetadata: false);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, server.Endpoint.Port);
        await using NetworkStream stream = client.GetStream();

        await SendAsync(stream, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        await ReceiveAsync(stream);
        await SendAsync(stream, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
        ulong sid = Smb2Header.Read(await ReceiveAsync(stream)).SessionId;

        await SendAsync(stream, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\s\Files"));
        Smb2Header h = Smb2Header.Read(await ReceiveAsync(stream));
        Assert.Equal(NtStatus.AccessDenied, h.Status); // async deny won → the async seam decided

        await server.StopAsync();
    }

    // ─── Host / handshake helpers ─────────────────────────────────────────

    private static async Task<SmbServer> StartAuthServerAsync(IShareAccessPolicy policy, bool concurrentMetadata)
    {
        // Both shares use an instant in-memory store (creates pre-released) — the only latency is the policy,
        // so the freeze is attributable to AuthorizeConnect, not the backend.
        var filesStore = new SlowCreateGatedStore(); filesStore.ReleaseCreates();
        var slowStore = new SlowCreateGatedStore(); slowStore.ReleaseCreates();
        SmbServer server = SmbServerBuilder.Create()
            .WithEndpoint(IPAddress.Loopback, 0)
            .UseDevAuthentication()
            .UseShareAuthorization(policy)
            .Configure(o => o.ConcurrentMetadataOps = concurrentMetadata)
            .AddShare(new Share { Name = "Files", Type = ShareType.Disk, FileStore = filesStore })
            .AddShare(new Share { Name = "Slow", Type = ShareType.Disk, FileStore = slowStore })
            .Build();
        await server.StartAsync();
        return server;
    }

    private static async Task<SmbServer> StartServerAsync(IFileStore store, bool concurrentMetadata)
    {
        SmbServer server = SmbServerBuilder.Create()
            .WithEndpoint(IPAddress.Loopback, 0)
            .UseDevAuthentication()
            .Configure(o => o.ConcurrentMetadataOps = concurrentMetadata)
            .AddShare(new Share { Name = "Files", Type = ShareType.Disk, FileStore = store })
            .Build();
        await server.StartAsync();
        return server;
    }

    private static async Task<(ulong sid, uint tid)> HandshakeAsync(NetworkStream stream)
    {
        await SendAsync(stream, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        await ReceiveAsync(stream);
        await SendAsync(stream, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
        ulong sid = Smb2Header.Read(await ReceiveAsync(stream)).SessionId;
        await SendAsync(stream, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\s\Files"));
        uint tid = Smb2Header.Read(await ReceiveAsync(stream)).TreeId;
        return (sid, tid);
    }

    private static async Task<(ulong p, ulong v)> OpenFastFileAsync(NetworkStream stream, ulong sid, uint tid)
    {
        await SendAsync(stream, TestHelpers.BuildCreateRequest(MidOpenFast, sid, tid, "fast.txt", 0x3,
            (uint)CreateDisposition.OpenIf, (uint)CreateOptions.NonDirectoryFile));
        byte[] resp = await ReceiveAsync(stream);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        const int body = Smb2Header.Size;
        ulong p = BinaryPrimitives.ReadUInt64LittleEndian(resp.AsSpan(body + 64, 8));
        ulong v = BinaryPrimitives.ReadUInt64LittleEndian(resp.AsSpan(body + 72, 8));
        return (p, v);
    }

    private static async Task SendAsync(NetworkStream stream, byte[] message)
    {
        await stream.WriteAsync(NbssFrame.Wrap(message));
        await stream.FlushAsync();
    }

    private static Task<byte[]> ReceiveAsync(NetworkStream stream) => ReceiveAsync(stream, TimeSpan.FromSeconds(10));

    private static async Task<byte[]> ReceiveAsync(NetworkStream stream, TimeSpan timeout)
    {
        var prefix = new byte[NbssFrame.HeaderLength];
        await stream.ReadExactlyAsync(prefix).AsTask().WaitAsync(timeout);
        var payload = new byte[NbssFrame.ReadLength(prefix)];
        await stream.ReadExactlyAsync(payload).AsTask().WaitAsync(timeout);
        return payload;
    }

    /// <summary>
    /// Waits up to <paramref name="timeout"/> for a frame; returns <c>null</c> on timeout (freeze). Cancels
    /// the underlying socket read itself (not just the await) so a timed-out probe consumes no bytes and
    /// leaves the stream synchronized for the next read — during a real freeze zero bytes have arrived, so
    /// the cancellation is clean.
    /// </summary>
    private static async Task<byte[]?> TryReceiveAsync(NetworkStream stream, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        var prefix = new byte[NbssFrame.HeaderLength];
        try { await stream.ReadExactlyAsync(prefix, cts.Token); }
        catch (OperationCanceledException) { return null; }

        var payload = new byte[NbssFrame.ReadLength(prefix)];
        await stream.ReadExactlyAsync(payload).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        return payload;
    }

    /// <summary>
    /// Share policy that blocks <see cref="AuthorizeConnect"/> for one named share until released — models a
    /// slow <i>synchronous</i> rights lookup (DB/LDAP) in an overridden policy. Other shares grant instantly.
    /// </summary>
    private sealed class GatedConnectPolicy(string slowShare) : IShareAccessPolicy
    {
        private readonly ManualResetEventSlim _gate = new(initialState: false);

        public void Release() => _gate.Set();

        public bool IsVisible(ShareAccessContext context) => true;

        public ShareAccessResult AuthorizeConnect(ShareAccessContext context)
        {
            if (string.Equals(context.ShareName, slowShare, StringComparison.OrdinalIgnoreCase))
                _gate.Wait(TimeSpan.FromSeconds(30)); // synchronous block: the seam has no async variant
            return ShareAccessResult.Grant();
        }
    }

    /// <summary>
    /// Grants synchronously but denies asynchronously — a probe that only rejects if the caller takes the
    /// async seam (<see cref="AuthorizeConnectAsync"/>). Used to prove W6.2 wiring.
    /// </summary>
    private sealed class AsyncDenyPolicy : IShareAccessPolicy
    {
        public bool IsVisible(ShareAccessContext context) => true;
        public ShareAccessResult AuthorizeConnect(ShareAccessContext context) => ShareAccessResult.Grant();

        public async ValueTask<ShareAccessResult> AuthorizeConnectAsync(ShareAccessContext context)
        {
            await Task.Yield();
            return ShareAccessResult.Deny();
        }
    }

    // ─── Backend: CREATE on "slow.txt" blocks until released; READ is instant ──

    private sealed class SlowCreateGatedStore : IFileStore
    {
        private readonly TaskCompletionSource _createGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private static readonly byte[] Content = Encoding.UTF8.GetBytes("data");

        public void ReleaseCreates() => _createGate.TrySetResult();

        public async ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(
            string path, FileAccessIntent access, CreateDispositionIntent disposition,
            bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
        {
            // Only the marked path stalls (simulates a slow ZFS/network metadata op); everything else — the
            // fast file we read — opens instantly, so the block is deterministic and path-scoped.
            if (path.Contains("slow", StringComparison.OrdinalIgnoreCase))
                await _createGate.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(new Handle(path), CreateOutcome.Opened));
        }

        public ValueTask<FileStoreResult<int>> ReadAsync(
            IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (offset >= Content.Length) return new(FileStoreResult<int>.Ok(0));
            int n = Math.Min(buffer.Length, Content.Length - (int)offset);
            Content.AsSpan((int)offset, n).CopyTo(buffer.Span);
            return new(FileStoreResult<int>.Ok(n));
        }

        public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
            => new(FileStoreResult<int>.Ok(data.Length));
        public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
            => new(FileStoreResult<IReadOnlyList<FileEntryInfo>>.Ok(Array.Empty<FileEntryInfo>()));
        public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default) => new(NtStatus.Success);
        public ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default) => new(NtStatus.Success);
        public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default) => new(NtStatus.Success);
        public ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default) => new(NtStatus.Success);

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
