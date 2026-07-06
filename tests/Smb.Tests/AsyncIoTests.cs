using System.Buffers.Binary;
using System.Text;
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
/// Async I/O conversion (docs/ASYNC_IO_ROADMAP.md, A3): a natively asynchronous <see cref="IFileStore"/>
/// works without sync-over-async through the complete dispatcher pipeline, and the
/// <see cref="SyncFileStore"/> adapter correctly maps synchronous backends onto the
/// async contract (including CreateOutcome mapping).
/// </summary>
public class AsyncIoTests : IDisposable
{
    private readonly string _shareDir;

    public AsyncIoTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbasync_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    // ─── Natively-async store end-to-end through the dispatcher ─────────

    [Fact]
    public void AsyncStore_CreateWriteReadClose_RoundTrips()
    {
        var store = new FakeAsyncFileStore();
        (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) = Setup(store);

        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            4, sid, tid, "async.txt", desiredAccess: 0x00000003 /* read+write */,
            disposition: (uint)CreateDisposition.OverwriteIf, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        (ulong p, ulong v) = ExtractCreateFileId(create);

        byte[] payload = Encoding.UTF8.GetBytes("Hallo async Backend!");
        byte[] write = d.ProcessMessage(conn, TestHelpers.BuildWriteRequest(5, sid, tid, p, v, 0, payload));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(write).Status);

        byte[] read = d.ProcessMessage(conn, TestHelpers.BuildReadRequest(6, sid, tid, p, v, length: 256, offset: 0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(read).Status);
        Assert.Equal("Hallo async Backend!", Encoding.UTF8.GetString(ExtractReadData(read)));

        byte[] close = d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(7, sid, tid, p, v));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(close).Status);

        // The store forced real async continuations (Task.Yield) — meaning the path ran
        // truly asynchronously, not just synchronously through the ValueTask chain.
        Assert.True(store.AsyncHops > 0, "Fake store was not invoked asynchronously.");
    }

    [Fact]
    public void AsyncStore_DeleteOnClose_UsesAsyncDispose()
    {
        var store = new FakeAsyncFileStore();
        (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) = Setup(store);

        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            4, sid, tid, "temp.txt", desiredAccess: 0x00010003 /* read+write+delete */,
            disposition: (uint)CreateDisposition.OverwriteIf, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        (ulong p, ulong v) = ExtractCreateFileId(create);

        byte[] setInfo = d.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            5, sid, tid, p, v, infoType: 0x01,
            fileInfoClass: (byte)FileInformationClass.FileDispositionInformation, buffer: [1]));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(setInfo).Status);

        d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(6, sid, tid, p, v));

        // DELETE_ON_CLOSE went through the async dispose path of the handle → file is gone.
        byte[] reopen = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            7, sid, tid, "temp.txt", desiredAccess: 0x00000001,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.ObjectNameNotFound, Smb2Header.Read(reopen).Status);
    }

    // ─── SyncFileStore adapter (LocalFileStore) directly against the contract ─

    [Fact]
    public async Task SyncAdapter_MapsCreateOutcomes_AndRoundTrips()
    {
        IFileStore store = new LocalFileStore(_shareDir, readOnly: false);

        FileStoreResult<FileCreateResult> created = await store.CreateAsync(
            "adapter.txt", FileAccessIntent.ReadWrite, CreateDispositionIntent.OpenIf,
            directoryRequired: false, nonDirectoryRequired: true);
        Assert.True(created.IsSuccess);
        Assert.Equal(CreateOutcome.Created, created.Value.Action);

        FileStoreResult<int> written = await store.WriteAsync(
            created.Value.Handle, 0, Encoding.UTF8.GetBytes("Hallo"));
        Assert.Equal(5, written.Value);
        await created.Value.Handle.DisposeAsync();

        FileStoreResult<FileCreateResult> opened = await store.CreateAsync(
            "adapter.txt", FileAccessIntent.Read, CreateDispositionIntent.Open,
            directoryRequired: false, nonDirectoryRequired: true);
        Assert.True(opened.IsSuccess);
        Assert.Equal(CreateOutcome.Opened, opened.Value.Action);

        var buffer = new byte[16];
        FileStoreResult<int> read = await store.ReadAsync(opened.Value.Handle, 0, buffer);
        Assert.Equal(5, read.Value);
        Assert.Equal("Hallo", Encoding.UTF8.GetString(buffer, 0, read.Value));

        FileEntryInfo info = await opened.Value.Handle.GetInfoAsync();
        Assert.Equal(5, info.EndOfFile);
        await opened.Value.Handle.DisposeAsync();

        FileStoreResult<FileCreateResult> missing = await store.CreateAsync(
            "nonexistent.txt", FileAccessIntent.Read, CreateDispositionIntent.Open,
            directoryRequired: false, nonDirectoryRequired: true);
        Assert.Equal(NtStatus.ObjectNameNotFound, missing.Status);
    }

    // ─── Setup / parse helpers (same pattern as FileBrowseTests) ──────────

    private static (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(IFileStore store)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = store });

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

    private static byte[] ExtractReadData(byte[] response)
    {
        const int body = Smb2Header.Size;
        int dataLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(body + 4, 4));
        return response.AsSpan(80, dataLength).ToArray(); // DataOffset = 80
    }

    // ─── Natively asynchronous in-memory store ─────────────────────────────

    /// <summary>
    /// In-memory <see cref="IFileStore"/> that becomes truly asynchronous before each operation
    /// (<c>Task.Yield</c>) — like a network/cloud backend. <see cref="AsyncHops"/> counts the
    /// forced continuations (proof that the async path was actually exercised).
    /// </summary>
    private sealed class FakeAsyncFileStore : IFileStore
    {
        private readonly Dictionary<string, byte[]> _files = new(StringComparer.OrdinalIgnoreCase);
        private int _asyncHops;

        public int AsyncHops => Volatile.Read(ref _asyncHops);

        private async Task HopAsync()
        {
            await Task.Yield();
            Interlocked.Increment(ref _asyncHops);
        }

        public async ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(
            string path, FileAccessIntent access, CreateDispositionIntent disposition,
            bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
        {
            await HopAsync();
            lock (_files)
            {
                bool exists = _files.ContainsKey(path);
                CreateOutcome action;
                switch (disposition)
                {
                    case CreateDispositionIntent.Open:
                        if (!exists) return FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectNameNotFound);
                        action = CreateOutcome.Opened;
                        break;
                    case CreateDispositionIntent.Create:
                        if (exists) return FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectNameCollision);
                        _files[path] = [];
                        action = CreateOutcome.Created;
                        break;
                    case CreateDispositionIntent.OpenIf:
                        if (!exists) { _files[path] = []; action = CreateOutcome.Created; }
                        else action = CreateOutcome.Opened;
                        break;
                    default: // Overwrite / OverwriteIf / Supersede
                        if (disposition == CreateDispositionIntent.Overwrite && !exists)
                            return FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectNameNotFound);
                        _files[path] = [];
                        action = exists ? CreateOutcome.Overwritten : CreateOutcome.Created;
                        break;
                }
                return FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(new FakeHandle(this, path), action));
            }
        }

        public async ValueTask<FileStoreResult<int>> ReadAsync(
            IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await HopAsync();
            lock (_files)
            {
                if (!_files.TryGetValue(handle.Path, out byte[]? content))
                    return FileStoreResult<int>.Fail(NtStatus.ObjectNameNotFound);
                if (offset >= content.Length)
                    return FileStoreResult<int>.Ok(0);
                int n = Math.Min(buffer.Length, content.Length - (int)offset);
                content.AsSpan((int)offset, n).CopyTo(buffer.Span);
                return FileStoreResult<int>.Ok(n);
            }
        }

        public async ValueTask<FileStoreResult<int>> WriteAsync(
            IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        {
            await HopAsync();
            lock (_files)
            {
                if (!_files.TryGetValue(handle.Path, out byte[]? content))
                    return FileStoreResult<int>.Fail(NtStatus.ObjectNameNotFound);
                long end = offset + data.Length;
                if (end > content.Length)
                {
                    Array.Resize(ref content, (int)end);
                    _files[handle.Path] = content;
                }
                data.Span.CopyTo(content.AsSpan((int)offset));
                return FileStoreResult<int>.Ok(data.Length);
            }
        }

        public async ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(
            IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
        {
            await HopAsync();
            lock (_files)
            {
                var entries = new List<FileEntryInfo>();
                foreach (KeyValuePair<string, byte[]> kv in _files)
                    entries.Add(BuildInfo(kv.Key, kv.Value));
                return FileStoreResult<IReadOnlyList<FileEntryInfo>>.Ok(entries);
            }
        }

        public async ValueTask<NtStatus> SetEndOfFileAsync(
            IFileHandle handle, long length, CancellationToken cancellationToken = default)
        {
            await HopAsync();
            lock (_files)
            {
                if (!_files.TryGetValue(handle.Path, out byte[]? content))
                    return NtStatus.ObjectNameNotFound;
                Array.Resize(ref content, (int)length);
                _files[handle.Path] = content;
                return NtStatus.Success;
            }
        }

        public async ValueTask<NtStatus> RenameAsync(
            IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default)
        {
            await HopAsync();
            lock (_files)
            {
                if (!_files.Remove(handle.Path, out byte[]? content))
                    return NtStatus.ObjectNameNotFound;
                if (_files.ContainsKey(newPath) && !replaceIfExists)
                    return NtStatus.ObjectNameCollision;
                _files[newPath] = content;
                return NtStatus.Success;
            }
        }

        public async ValueTask<NtStatus> SetDeleteOnCloseAsync(
            IFileHandle handle, bool delete, CancellationToken cancellationToken = default)
        {
            await HopAsync();
            ((FakeHandle)handle).DeleteOnClose = delete;
            return NtStatus.Success;
        }

        public async ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default)
        {
            await HopAsync();
            return NtStatus.Success;
        }

        internal void Delete(string path)
        {
            lock (_files) _files.Remove(path);
        }

        internal FileEntryInfo Info(string path)
        {
            lock (_files)
                return BuildInfo(path, _files.TryGetValue(path, out byte[]? c) ? c : []);
        }

        internal async ValueTask HopPublicAsync() => await HopAsync();

        private static FileEntryInfo BuildInfo(string path, byte[] content) => new()
        {
            Name = path.Contains('\\') ? path[(path.LastIndexOf('\\') + 1)..] : path,
            Attributes = SmbFileAttributes.Normal,
            EndOfFile = content.Length,
            AllocationSize = (content.Length + 4095) / 4096 * 4096,
        };

        private sealed class FakeHandle(FakeAsyncFileStore store, string path) : IFileHandle
        {
            public string Path { get; } = path;
            public bool IsDirectory => false;
            public bool DeleteOnClose { get; set; }

            public FileEntryInfo GetInfo() => store.Info(Path);

            public async ValueTask<FileEntryInfo> GetInfoAsync(CancellationToken cancellationToken = default)
            {
                await store.HopPublicAsync();
                return store.Info(Path);
            }

            public async ValueTask DisposeAsync()
            {
                await store.HopPublicAsync();
                if (DeleteOnClose) store.Delete(Path);
            }

            public void Dispose()
            {
                if (DeleteOnClose) store.Delete(Path);
            }
        }
    }
}
