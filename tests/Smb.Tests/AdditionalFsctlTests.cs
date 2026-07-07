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
/// Phase 5 / M5.2 — additional FSCTLs: sparse-file control (SET_SPARSE / SET_ZERO_DATA /
/// QUERY_ALLOCATED_RANGES via <see cref="ISparseFileStore"/>), reparse points (GET/SET/DELETE via
/// <see cref="IReparsePointStore"/>) and the DFS-referral stub. Backends that do not implement the
/// seam get the correct "unsupported" status.
/// </summary>
public class AdditionalFsctlTests : IDisposable
{
    private const uint ReadAccess = 0x00000001;
    private const uint ReadWrite = 0x00000003;

    private readonly string _dir;
    private ulong _mid = 10;

    private ulong NextMid() => _mid++;

    public AdditionalFsctlTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "smbfsctl_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { /* ignore */ }
    }

    // --- pure wire round-trips ---

    [Fact]
    public void ParseSetSparse_EmptyIsTrue_ZeroIsFalse()
    {
        Assert.True(FsctlMessage.ParseSetSparse([]));
        Assert.True(FsctlMessage.ParseSetSparse([1]));
        Assert.False(FsctlMessage.ParseSetSparse([0]));
    }

    [Fact]
    public void ZeroDataAndAllocatedRanges_RoundTrip()
    {
        byte[] zero = new byte[16];
        BinaryPrimitives.WriteInt64LittleEndian(zero.AsSpan(0, 8), 100);
        BinaryPrimitives.WriteInt64LittleEndian(zero.AsSpan(8, 8), 350);
        FsctlMessage.FileRange range = FsctlMessage.ParseZeroData(zero);
        Assert.Equal(100, range.Offset);
        Assert.Equal(250, range.Length);

        byte[] built = FsctlMessage.BuildAllocatedRanges([new FsctlMessage.FileRange(0, 4096), new FsctlMessage.FileRange(8192, 512)]);
        Assert.Equal(32, built.Length);
        Assert.Equal(0, BinaryPrimitives.ReadInt64LittleEndian(built.AsSpan(0, 8)));
        Assert.Equal(4096, BinaryPrimitives.ReadInt64LittleEndian(built.AsSpan(8, 8)));
        Assert.Equal(8192, BinaryPrimitives.ReadInt64LittleEndian(built.AsSpan(16, 8)));
        Assert.Equal(512, BinaryPrimitives.ReadInt64LittleEndian(built.AsSpan(24, 8)));
    }

    // --- sparse FSCTLs over the dispatcher ---

    [Fact]
    public void SetSparse_OnCapableBackend_Succeeds()
    {
        var store = new AdvancedFsctlStore(new LocalFileStore(_dir, readOnly: false));
        var (d, conn, sid, tid) = Setup(store);
        File.WriteAllBytes(Path.Combine(_dir, "f.bin"), new byte[64]);

        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "f.bin", ReadWrite, out ulong p, out ulong v));
        byte[] resp = Ioctl(d, conn, sid, tid, p, v, FsctlMessage.FsctlSetSparse, [1]);

        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        Assert.True(store.SparsePaths.Contains("f.bin"));
    }

    [Fact]
    public void SetSparse_OnPlainBackend_NotSupported()
    {
        var (d, conn, sid, tid) = Setup(new LocalFileStore(_dir, readOnly: false));
        File.WriteAllBytes(Path.Combine(_dir, "f.bin"), new byte[64]);

        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "f.bin", ReadWrite, out ulong p, out ulong v));
        byte[] resp = Ioctl(d, conn, sid, tid, p, v, FsctlMessage.FsctlSetSparse, [1]);

        Assert.Equal(NtStatus.NotSupported, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void SetZeroData_ZeroesTheRange()
    {
        var store = new AdvancedFsctlStore(new LocalFileStore(_dir, readOnly: false));
        var (d, conn, sid, tid) = Setup(store);
        byte[] content = Enumerable.Repeat((byte)0xFF, 64).ToArray();
        File.WriteAllBytes(Path.Combine(_dir, "f.bin"), content);

        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "f.bin", ReadWrite, out ulong p, out ulong v));
        // Zero bytes [16, 48).
        byte[] zeroInput = new byte[16];
        BinaryPrimitives.WriteInt64LittleEndian(zeroInput.AsSpan(0, 8), 16);
        BinaryPrimitives.WriteInt64LittleEndian(zeroInput.AsSpan(8, 8), 48);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(Ioctl(d, conn, sid, tid, p, v, FsctlMessage.FsctlSetZeroData, zeroInput)).Status);
        Close(d, conn, sid, tid, p, v);

        byte[] after = File.ReadAllBytes(Path.Combine(_dir, "f.bin"));
        Assert.All(after[..16], b => Assert.Equal(0xFF, b));
        Assert.All(after[16..48], b => Assert.Equal(0x00, b));
        Assert.All(after[48..], b => Assert.Equal(0xFF, b));
    }

    [Fact]
    public void QueryAllocatedRanges_ReturnsRange()
    {
        var store = new AdvancedFsctlStore(new LocalFileStore(_dir, readOnly: false));
        var (d, conn, sid, tid) = Setup(store);
        File.WriteAllBytes(Path.Combine(_dir, "f.bin"), new byte[4096]);

        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "f.bin", ReadAccess, out ulong p, out ulong v));
        byte[] input = new byte[16];
        BinaryPrimitives.WriteInt64LittleEndian(input.AsSpan(0, 8), 0);
        BinaryPrimitives.WriteInt64LittleEndian(input.AsSpan(8, 8), 4096);
        byte[] resp = Ioctl(d, conn, sid, tid, p, v, FsctlMessage.FsctlQueryAllocatedRanges, input);

        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        byte[] output = IoctlOutput(resp);
        Assert.Equal(16, output.Length); // one FILE_ALLOCATED_RANGE_BUFFER
        Assert.Equal(0, BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(0, 8)));
        Assert.Equal(4096, BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(8, 8)));
    }

    // --- reparse points ---

    [Fact]
    public void GetReparsePoint_WhenNoneSet_NotAReparsePoint()
    {
        var store = new AdvancedFsctlStore(new LocalFileStore(_dir, readOnly: false));
        var (d, conn, sid, tid) = Setup(store);
        File.WriteAllBytes(Path.Combine(_dir, "f.bin"), new byte[8]);

        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "f.bin", ReadAccess, out ulong p, out ulong v));
        byte[] resp = Ioctl(d, conn, sid, tid, p, v, FsctlMessage.FsctlGetReparsePoint, []);

        Assert.Equal(NtStatus.NotAReparsePoint, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void SetThenGetReparsePoint_RoundTrips()
    {
        var store = new AdvancedFsctlStore(new LocalFileStore(_dir, readOnly: false));
        var (d, conn, sid, tid) = Setup(store);
        File.WriteAllBytes(Path.Combine(_dir, "f.bin"), new byte[8]);

        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "f.bin", ReadWrite, out ulong p, out ulong v));
        byte[] reparse = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
        Assert.Equal(NtStatus.Success, Smb2Header.Read(Ioctl(d, conn, sid, tid, p, v, FsctlMessage.FsctlSetReparsePoint, reparse)).Status);

        byte[] getResp = Ioctl(d, conn, sid, tid, p, v, FsctlMessage.FsctlGetReparsePoint, []);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(getResp).Status);
        Assert.Equal(reparse, IoctlOutput(getResp));
    }

    [Fact]
    public void GetReparsePoint_OnPlainBackend_NotAReparsePoint()
    {
        var (d, conn, sid, tid) = Setup(new LocalFileStore(_dir, readOnly: false));
        File.WriteAllBytes(Path.Combine(_dir, "f.bin"), new byte[8]);

        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "f.bin", ReadAccess, out ulong p, out ulong v));
        byte[] resp = Ioctl(d, conn, sid, tid, p, v, FsctlMessage.FsctlGetReparsePoint, []);

        Assert.Equal(NtStatus.NotAReparsePoint, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void DfsGetReferrals_ReturnsNotFound()
    {
        var (d, conn, sid, tid) = Setup(new LocalFileStore(_dir, readOnly: false));

        // DFS referrals need no file handle — the stub answers before any open lookup.
        byte[] resp = Ioctl(d, conn, sid, tid, 0, 0, FsctlMessage.FsctlDfsGetReferrals, [0, 0, 0, 0]);
        Assert.Equal(NtStatus.NotFound, Smb2Header.Read(resp).Status);
    }

    // --- helpers ---

    private byte[] Ioctl(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong p, ulong v, uint ctlCode, byte[] input)
        => d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(NextMid(), sid, tid, p, v, ctlCode, input));

    private static byte[] IoctlOutput(byte[] resp)
    {
        int outputOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 32, 4));
        int outputCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 36, 4));
        return outputCount == 0 ? [] : resp.AsSpan(outputOffset, outputCount).ToArray();
    }

    private NtStatus Open(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, string name, uint desiredAccess,
        out ulong persistent, out ulong volatileId)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            NextMid(), sid, tid, name, desiredAccess, (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile));
        Smb2Header h = Smb2Header.Read(create);
        const int body = Smb2Header.Size;
        persistent = h.Status == NtStatus.Success ? BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8)) : 0;
        volatileId = h.Status == NtStatus.Success ? BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8)) : 0;
        return h.Status;
    }

    private void Close(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong p, ulong v)
        => d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(NextMid(), sid, tid, p, v));

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(IFileStore store)
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

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    /// <summary>
    /// A test backend that layers the sparse and reparse seams over a <see cref="LocalFileStore"/>:
    /// SET_SPARSE records the path, SET_ZERO_DATA writes zeros, QUERY_ALLOCATED_RANGES reports the whole
    /// queried window as allocated, and reparse buffers are kept in a per-path dictionary.
    /// </summary>
    private sealed class AdvancedFsctlStore(IFileStore inner) : IFileStore, ISparseFileStore, IReparsePointStore
    {
        public HashSet<string> SparsePaths { get; } = new();
        private readonly Dictionary<string, byte[]> _reparse = new();

        public ValueTask<NtStatus> SetSparseAsync(IFileHandle handle, bool sparse, CancellationToken cancellationToken = default)
        {
            if (sparse) SparsePaths.Add(handle.Path); else SparsePaths.Remove(handle.Path);
            return new(NtStatus.Success);
        }

        public async ValueTask<NtStatus> SetZeroDataAsync(IFileHandle handle, long offset, long length, CancellationToken cancellationToken = default)
        {
            FileStoreResult<int> w = await inner.WriteAsync(handle, offset, new byte[length], cancellationToken).ConfigureAwait(false);
            return w.IsSuccess ? NtStatus.Success : w.Status;
        }

        public ValueTask<FileStoreResult<IReadOnlyList<FsctlMessage.FileRange>>> QueryAllocatedRangesAsync(
            IFileHandle handle, long offset, long length, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<FsctlMessage.FileRange> ranges = length > 0
                ? [new FsctlMessage.FileRange(offset, length)]
                : [];
            return new(FileStoreResult<IReadOnlyList<FsctlMessage.FileRange>>.Ok(ranges));
        }

        public ValueTask<FileStoreResult<byte[]>> GetReparsePointAsync(IFileHandle handle, CancellationToken cancellationToken = default)
            => new(_reparse.TryGetValue(handle.Path, out byte[]? data)
                ? FileStoreResult<byte[]>.Ok(data)
                : FileStoreResult<byte[]>.Fail(NtStatus.NotAReparsePoint));

        public ValueTask<NtStatus> SetReparsePointAsync(IFileHandle handle, byte[] reparseData, CancellationToken cancellationToken = default)
        {
            _reparse[handle.Path] = reparseData;
            return new(NtStatus.Success);
        }

        public ValueTask<NtStatus> DeleteReparsePointAsync(IFileHandle handle, byte[] reparseData, CancellationToken cancellationToken = default)
        {
            _reparse.Remove(handle.Path);
            return new(NtStatus.Success);
        }

        public ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
            => inner.CreateAsync(path, access, disposition, directoryRequired, nonDirectoryRequired, cancellationToken);
        public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
            => inner.ReadAsync(handle, offset, buffer, cancellationToken);
        public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
            => inner.WriteAsync(handle, offset, data, cancellationToken);
        public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
            => inner.QueryDirectoryAsync(handle, searchPattern, cancellationToken);
        public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default)
            => inner.SetEndOfFileAsync(handle, length, cancellationToken);
        public ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default)
            => inner.RenameAsync(handle, newPath, replaceIfExists, cancellationToken);
        public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default)
            => inner.SetDeleteOnCloseAsync(handle, delete, cancellationToken);
        public ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default)
            => inner.FlushAsync(handle, cancellationToken);
        public ValueTask<FileStoreResult<Smb.Protocol.Security.SecurityDescriptor>> GetSecurityAsync(IFileHandle handle, CancellationToken cancellationToken = default)
            => inner.GetSecurityAsync(handle, cancellationToken);
        public ValueTask<NtStatus> SetSecurityAsync(IFileHandle handle, Smb.Protocol.Security.SecurityDescriptor descriptor, CancellationToken cancellationToken = default)
            => inner.SetSecurityAsync(handle, descriptor, cancellationToken);
    }
}
