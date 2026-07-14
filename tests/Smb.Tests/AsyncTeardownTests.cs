using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Async connection-close teardown (docs/ENTERPRISE_HARDENING_ROADMAP.md, A4): the primary per-connection
/// close path (<see cref="Smb2Dispatcher.OnConnectionClosedAsync"/>, used by the host) releases backend
/// handles via <see cref="IFileHandle.DisposeAsync"/> instead of the synchronous <c>Dispose</c>, so an
/// async backend does not sync-over-async-block during teardown. The sync <c>OnConnectionClosed</c> (used
/// by periodic sweeps / back-compat) keeps using <c>Dispose</c>.
/// </summary>
public class AsyncTeardownTests
{
    [Fact]
    public async Task OnConnectionClosedAsync_DisposesHandleAsynchronously()
    {
        var store = new RecordingStore();
        (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) = Setup(store);
        OpenFile(d, conn, sid, tid, 4, "f.txt");
        RecordingStore.Handle handle = store.Last!;

        await d.OnConnectionClosedAsync(conn);

        Assert.True(handle.DisposeAsyncCalled, "the async close path must use DisposeAsync.");
        Assert.False(handle.DisposeCalled, "the async close path must NOT fall back to sync Dispose.");
    }

    [Fact]
    public void OnConnectionClosed_Sync_UsesSyncDispose()
    {
        var store = new RecordingStore();
        (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) = Setup(store);
        OpenFile(d, conn, sid, tid, 4, "f.txt");
        RecordingStore.Handle handle = store.Last!;

        d.OnConnectionClosed(conn);

        Assert.True(handle.DisposeCalled, "the sync close path uses Dispose.");
        Assert.False(handle.DisposeAsyncCalled);
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

    private static void OpenFile(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong mid, string name)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            mid, sid, tid, name, 0x1, (uint)CreateDisposition.OpenIf, (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    private sealed class RecordingStore : IFileStore
    {
        public Handle? Last { get; private set; }

        public ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(
            string path, FileAccessIntent access, CreateDispositionIntent disposition,
            bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
        {
            Last = new Handle(path);
            return new(FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(Last, CreateOutcome.Opened)));
        }

        public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
            => new(FileStoreResult<int>.Ok(0));
        public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
            => new(FileStoreResult<int>.Ok(data.Length));
        public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
            => new(FileStoreResult<IReadOnlyList<FileEntryInfo>>.Ok(Array.Empty<FileEntryInfo>()));
        public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default) => new(NtStatus.Success);
        public ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default) => new(NtStatus.Success);
        public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default) => new(NtStatus.Success);
        public ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default) => new(NtStatus.Success);

        internal sealed class Handle(string path) : IFileHandle
        {
            public bool DisposeCalled;
            public bool DisposeAsyncCalled;
            public string Path { get; } = path;
            public bool IsDirectory => false;
            public FileEntryInfo GetInfo() => new() { Name = Path, Attributes = SmbFileAttributes.Normal };
            public void Dispose() => DisposeCalled = true;
            public ValueTask DisposeAsync() { DisposeAsyncCalled = true; return ValueTask.CompletedTask; }
        }
    }
}
