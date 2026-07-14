using System.Buffers.Binary;
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
/// [D2] Resource limits (docs/ENTERPRISE_HARDENING_ROADMAP.md): the per-session open-handle cap and the
/// QUERY_DIRECTORY materialization cap, driven end-to-end through the dispatcher, plus store-level unit
/// tests for the bounded directory enumeration (early-stop + the interface-default post-hoc truncation).
/// </summary>
public sealed class ResourceLimitTests : IDisposable
{
    private const byte FileIdBothDirectoryInformation = 37;
    private const byte SlRestartScan = 0x01;

    private readonly string _shareDir;

    public ResourceLimitTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smb-limit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
    }

    public void Dispose() { try { Directory.Delete(_shareDir, true); } catch { /* best effort */ } }

    [Fact]
    public void OpenHandleCap_RejectsOverLimitCreate_WithInsufficientResources()
    {
        var (d, conn, sid, tid) = Setup(o => o.MaxOpenHandlesPerSession = 2);

        // Two distinct opens succeed (fills the cap of 2).
        for (int i = 0; i < 2; i++)
            Assert.Equal(NtStatus.Success, Smb2Header.Read(Create(d, conn, sid, tid, mid: 10 + (ulong)i, name: $"f{i}.txt")).Status);

        // The third open exceeds the cap → STATUS_INSUFFICIENT_RESOURCES (no backend side effect).
        Assert.Equal(NtStatus.InsufficientResources, Smb2Header.Read(Create(d, conn, sid, tid, mid: 20, name: "f2.txt")).Status);
    }

    [Fact]
    public void OpenHandleCap_FreesSlotOnClose_AllowingReopen()
    {
        var (d, conn, sid, tid) = Setup(o => o.MaxOpenHandlesPerSession = 1);

        byte[] first = Create(d, conn, sid, tid, mid: 10, name: "a.txt");
        Assert.Equal(NtStatus.Success, Smb2Header.Read(first).Status);
        (ulong p, ulong v) = ReadFileId(first);

        // At the cap → a second open is refused.
        Assert.Equal(NtStatus.InsufficientResources, Smb2Header.Read(Create(d, conn, sid, tid, mid: 11, name: "b.txt")).Status);

        // Closing the first frees the slot.
        Assert.Equal(NtStatus.Success, Smb2Header.Read(
            d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(12, sid, tid, p, v))).Status);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(Create(d, conn, sid, tid, mid: 13, name: "b.txt")).Status);
    }

    [Fact]
    public void OpenHandleCap_Zero_IsUnbounded()
    {
        var (d, conn, sid, tid) = Setup(o => o.MaxOpenHandlesPerSession = 0);
        for (int i = 0; i < 20; i++)
            Assert.Equal(NtStatus.Success, Smb2Header.Read(Create(d, conn, sid, tid, mid: 10 + (ulong)i, name: $"n{i}.txt")).Status);
    }

    [Fact]
    public void DirectoryCap_Exceeded_ReturnsInsufficientResources()
    {
        for (int i = 0; i < 5; i++)
            File.WriteAllText(Path.Combine(_shareDir, $"file{i}.txt"), "x");

        // Cap of 2 (< 5 files + ".") → the scan is refused rather than materialized.
        var (d, conn, sid, tid) = Setup(o => o.MaxDirectoryEnumerationEntries = 2);
        (ulong p, ulong v) = OpenDir(d, conn, sid, tid);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryDirectoryRequest(
            10, sid, tid, p, v, FileIdBothDirectoryInformation, pattern: "*",
            outputBufferLength: 4096, flags: SlRestartScan));
        Assert.Equal(NtStatus.InsufficientResources, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void DirectoryCap_WithinLimit_Succeeds()
    {
        for (int i = 0; i < 3; i++)
            File.WriteAllText(Path.Combine(_shareDir, $"file{i}.txt"), "x");

        var (d, conn, sid, tid) = Setup(o => o.MaxDirectoryEnumerationEntries = 100);
        (ulong p, ulong v) = OpenDir(d, conn, sid, tid);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryDirectoryRequest(
            10, sid, tid, p, v, FileIdBothDirectoryInformation, "*", 4096, flags: SlRestartScan));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public async Task LocalFileStore_BoundedEnumeration_StopsEarlyAndReportsTruncation()
    {
        for (int i = 0; i < 10; i++)
            File.WriteAllText(Path.Combine(_shareDir, $"e{i}.txt"), "x");
        var store = new LocalFileStore(_shareDir, readOnly: false);
        FileStoreResult<FileCreateResult> open = await store.CreateAsync(
            "", FileAccessIntent.Read, CreateDispositionIntent.Open, directoryRequired: true, nonDirectoryRequired: false);
        Assert.True(open.IsSuccess);

        FileStoreResult<BoundedDirectoryListing> bounded = await store.QueryDirectoryAsync(open.Value.Handle, "*", maxEntries: 3);

        Assert.True(bounded.IsSuccess);
        Assert.True(bounded.Value.Truncated);
        Assert.Equal(3, bounded.Value.Entries.Count); // stopped early — the full 11 entries were never materialized
    }

    [Fact]
    public async Task InterfaceDefault_BoundedEnumeration_TruncatesAfterTheFact()
    {
        // A store that implements only the 3-arg overload exercises the interface-default bounded wrapper.
        var store = new FullListOnlyStore(entries: 8);
        FileStoreResult<BoundedDirectoryListing> bounded =
            await ((IFileStore)store).QueryDirectoryAsync(handle: null!, "*", maxEntries: 5);

        Assert.True(bounded.IsSuccess);
        Assert.True(bounded.Value.Truncated);
        Assert.Equal(5, bounded.Value.Entries.Count);
    }

    // --- helpers ---

    private static byte[] Create(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong mid, string name)
        => d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            mid, sid, tid, name, desiredAccess: 0x00000003,
            disposition: (uint)CreateDisposition.OpenIf, options: (uint)CreateOptions.NonDirectoryFile,
            shareAccess: 0x7)); // FILE_SHARE_READ|WRITE|DELETE so distinct opens don't sharing-violate

    private (ulong p, ulong v) OpenDir(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            5, sid, tid, "", desiredAccess: 0x00000001, disposition: (uint)CreateDisposition.Open,
            options: (uint)CreateOptions.DirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        return ReadFileId(create);
    }

    private static (ulong p, ulong v) ReadFileId(byte[] createResponse)
    {
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(createResponse.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(createResponse.AsSpan(body + 72, 8)));
    }

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(Action<SmbServerOptions> configure)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        configure(options);
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

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    /// <summary>A backend that returns a full list from the 3-arg overload only — to exercise the interface default.</summary>
    private sealed class FullListOnlyStore : IFileStore
    {
        private readonly IReadOnlyList<FileEntryInfo> _all;
        public FullListOnlyStore(int entries)
            => _all = Enumerable.Range(0, entries).Select(i => new FileEntryInfo { Name = $"x{i}" }).ToList();

        public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(
            IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
            => new(FileStoreResult<IReadOnlyList<FileEntryInfo>>.Ok(_all));

        // Everything else is unused by the test.
        public ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
