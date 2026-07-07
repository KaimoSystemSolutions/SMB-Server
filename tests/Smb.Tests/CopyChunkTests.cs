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
/// Phase 5 / M5.1 — server-side copy (FSCTL_SRV_REQUEST_RESUME_KEY + FSCTL_SRV_COPYCHUNK): the client
/// obtains a resume key for a source open and copies ranges into a destination open without the data
/// passing through it. Covers same-share, cross-share, the §2.2.31.1 limits, an unknown key, and the
/// backend copy-offload seam.
/// </summary>
public class CopyChunkTests : IDisposable
{
    private const uint ReadAccess = 0x00000001;
    private const uint ReadWrite = 0x00000003;

    private readonly string _dirA;
    private readonly string _dirB;
    private ulong _mid = 10; // strictly increasing (the dispatcher enforces the sequence window)

    private ulong NextMid() => _mid++;

    public CopyChunkTests()
    {
        _dirA = Path.Combine(Path.GetTempPath(), "smbcc_a_" + Guid.NewGuid().ToString("N"));
        _dirB = Path.Combine(Path.GetTempPath(), "smbcc_b_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dirA);
        Directory.CreateDirectory(_dirB);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dirA, true); } catch { /* ignore */ }
        try { Directory.Delete(_dirB, true); } catch { /* ignore */ }
    }

    // --- pure wire round-trips ---

    [Fact]
    public void ResumeKeyResponse_RoundTrips()
    {
        byte[] key = Enumerable.Range(0, 24).Select(i => (byte)i).ToArray();
        byte[] body = CopyChunkMessage.BuildResumeKeyResponse(key);

        Assert.Equal(28, body.Length);
        Assert.Equal(key, body[..24]);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(24, 4))); // ContextLength
    }

    [Fact]
    public void CopyRequest_ParsesKeyAndChunks()
    {
        byte[] key = Enumerable.Repeat((byte)0xAB, 24).ToArray();
        byte[] input = BuildCopyInput(key, [(10, 20, 100), (200, 300, 50)]);

        CopyChunkMessage.CopyRequest req = CopyChunkMessage.ParseCopyRequest(input);

        Assert.Equal(key, req.SourceKey);
        Assert.Equal(2, req.Chunks.Count);
        Assert.Equal(new CopyChunkMessage.Chunk(10, 20, 100), req.Chunks[0]);
        Assert.Equal(new CopyChunkMessage.Chunk(200, 300, 50), req.Chunks[1]);
    }

    // --- end-to-end over the dispatcher ---

    [Fact]
    public void CopyChunk_CopiesWithinShare()
    {
        byte[] content = System.Text.Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog.");
        File.WriteAllBytes(Path.Combine(_dirA, "src.txt"), content);

        var (d, conn, sid, tidA, _) = Setup();
        byte[] key = ResumeKey(d, conn, sid, tidA, "src.txt", out _, out _);
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tidA, "dst.txt", ReadWrite, out ulong dp, out ulong dv,
            disposition: (uint)CreateDisposition.Create));

        // Copy the whole source into the destination as two chunks.
        (uint chunks, uint total, NtStatus status) = CopyChunk(d, conn, sid, tidA, dp, dv, key,
            [(0, 0, 20), (20, 20, (uint)(content.Length - 20))]);

        Assert.Equal(NtStatus.Success, status);
        Assert.Equal(2u, chunks);
        Assert.Equal((uint)content.Length, total);
        Close(d, conn, sid, tidA, dp, dv);
        Assert.Equal(content, File.ReadAllBytes(Path.Combine(_dirA, "dst.txt")));
    }

    [Fact]
    public void CopyChunk_CrossShare_UsesReadWriteFallback()
    {
        byte[] content = Enumerable.Range(0, 5000).Select(i => (byte)i).ToArray();
        File.WriteAllBytes(Path.Combine(_dirA, "big.bin"), content);

        var (d, conn, sid, tidA, tidB) = Setup();
        byte[] key = ResumeKey(d, conn, sid, tidA, "big.bin", out _, out _);
        // Destination lives on the *other* share → different store instance, fallback loop.
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tidB, "copy.bin", ReadWrite, out ulong dp, out ulong dv,
            disposition: (uint)CreateDisposition.Create));

        (uint chunks, uint total, NtStatus status) = CopyChunk(d, conn, sid, tidB, dp, dv, key,
            [(0, 0, (uint)content.Length)]);

        Assert.Equal(NtStatus.Success, status);
        Assert.Equal(1u, chunks);
        Assert.Equal((uint)content.Length, total);
        Close(d, conn, sid, tidB, dp, dv);
        Assert.Equal(content, File.ReadAllBytes(Path.Combine(_dirB, "copy.bin")));
    }

    [Fact]
    public void CopyChunk_TooManyChunks_ReturnsInvalidParameterWithMaxima()
    {
        File.WriteAllBytes(Path.Combine(_dirA, "src.txt"), new byte[100]);

        var (d, conn, sid, tidA, _) = Setup();
        byte[] key = ResumeKey(d, conn, sid, tidA, "src.txt", out _, out _);
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tidA, "dst.txt", ReadWrite, out ulong dp, out ulong dv,
            disposition: (uint)CreateDisposition.Create));

        // 17 chunks > MaxChunks (16) → rejected before any I/O, maxima reported.
        var chunks = Enumerable.Range(0, 17).Select(i => ((ulong)i, (ulong)i, 1u)).ToArray();
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            NextMid(), sid, tidA, dp, dv, CopyChunkMessage.FsctlSrvCopyChunk, BuildCopyInput(key, chunks)));

        Assert.Equal(NtStatus.InvalidParameter, Smb2Header.Read(resp).Status);
        byte[] output = IoctlOutput(resp);
        Assert.Equal(CopyChunkMessage.MaxChunks, BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(0, 4)));
        Assert.Equal(CopyChunkMessage.MaxChunkSize, BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(4, 4)));
        Assert.Equal(CopyChunkMessage.MaxTotalSize, BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(8, 4)));
    }

    [Fact]
    public void CopyChunk_UnknownResumeKey_ObjectNameNotFound()
    {
        var (d, conn, sid, tidA, _) = Setup();
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tidA, "dst.txt", ReadWrite, out ulong dp, out ulong dv,
            disposition: (uint)CreateDisposition.Create));

        byte[] bogus = Enumerable.Repeat((byte)0x99, 24).ToArray();
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            NextMid(), sid, tidA, dp, dv, CopyChunkMessage.FsctlSrvCopyChunk, BuildCopyInput(bogus, [(0, 0, 1)])));

        Assert.Equal(NtStatus.ObjectNameNotFound, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void CopyChunk_UsesBackendOffloadWhenAvailable()
    {
        byte[] content = System.Text.Encoding.ASCII.GetBytes("offloaded copy path");
        File.WriteAllBytes(Path.Combine(_dirA, "src.txt"), content);

        var offloadStore = new OffloadRecordingStore(new LocalFileStore(_dirA, readOnly: false));
        var (d, conn, sid, tidA, _) = Setup(offloadStore);

        byte[] key = ResumeKey(d, conn, sid, tidA, "src.txt", out _, out _);
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tidA, "dst.txt", ReadWrite, out ulong dp, out ulong dv,
            disposition: (uint)CreateDisposition.Create));

        (uint chunks, uint total, NtStatus status) = CopyChunk(d, conn, sid, tidA, dp, dv, key,
            [(0, 0, (uint)content.Length)]);

        Assert.Equal(NtStatus.Success, status);
        Assert.Equal(1u, chunks);
        Assert.Equal((uint)content.Length, total);
        Assert.True(offloadStore.OffloadCalled); // same-store copy took the native offload seam
        Close(d, conn, sid, tidA, dp, dv);
        Assert.Equal(content, File.ReadAllBytes(Path.Combine(_dirA, "dst.txt")));
    }

    // --- helpers ---

    /// <summary>Opens <paramref name="name"/> and requests its resume key; returns the 24-byte key.</summary>
    private byte[] ResumeKey(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, string name,
        out ulong persistent, out ulong volatileId)
    {
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, name, ReadAccess, out persistent, out volatileId));
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            NextMid(), sid, tid, persistent, volatileId, CopyChunkMessage.FsctlSrvRequestResumeKey, []));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        return IoctlOutput(resp)[..24];
    }

    private (uint Chunks, uint Total, NtStatus Status) CopyChunk(
        Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong dp, ulong dv,
        byte[] sourceKey, (ulong SourceOffset, ulong TargetOffset, uint Length)[] chunks)
    {
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            NextMid(), sid, tid, dp, dv, CopyChunkMessage.FsctlSrvCopyChunk, BuildCopyInput(sourceKey, chunks)));
        NtStatus status = Smb2Header.Read(resp).Status;
        if (status != NtStatus.Success)
            return (0, 0, status);
        byte[] output = IoctlOutput(resp);
        return (BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(0, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(8, 4)),
                status);
    }

    private static byte[] BuildCopyInput(byte[] sourceKey, (ulong SourceOffset, ulong TargetOffset, uint Length)[] chunks)
    {
        var w = new Smb.Protocol.Wire.GrowableWriter(32 + chunks.Length * 24);
        w.WriteBytes(sourceKey);
        w.WriteUInt32((uint)chunks.Length);
        w.WriteUInt32(0); // Reserved
        foreach ((ulong src, ulong tgt, uint len) in chunks)
        {
            w.WriteUInt64(src);
            w.WriteUInt64(tgt);
            w.WriteUInt32(len);
            w.WriteUInt32(0); // Reserved
        }
        return w.ToArray();
    }

    private static byte[] IoctlOutput(byte[] resp)
    {
        int outputOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 32, 4));
        int outputCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 36, 4));
        return outputCount == 0 ? [] : resp.AsSpan(outputOffset, outputCount).ToArray();
    }

    private NtStatus Open(
        Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, string name, uint desiredAccess,
        out ulong persistent, out ulong volatileId,
        uint disposition = (uint)CreateDisposition.Open, uint options = (uint)CreateOptions.NonDirectoryFile)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            NextMid(), sid, tid, name, desiredAccess, disposition, options));
        Smb2Header h = Smb2Header.Read(create);
        const int body = Smb2Header.Size;
        persistent = h.Status == NtStatus.Success ? BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8)) : 0;
        volatileId = h.Status == NtStatus.Success ? BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8)) : 0;
        return h.Status;
    }

    private void Close(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong p, ulong v)
        => d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(NextMid(), sid, tid, p, v));

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tidA, uint tidB) Setup(IFileStore? storeA = null)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = storeA ?? new LocalFileStore(_dirA, readOnly: false) });
        options.Shares.Add(new Share { Name = "Files2", Type = ShareType.Disk, FileStore = new LocalFileStore(_dirB, readOnly: false) });

        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();

        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        uint tidA = Smb2Header.Read(dispatcher.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\s\Files"))).TreeId;
        uint tidB = Smb2Header.Read(dispatcher.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(4, sessionId, @"\\s\Files2"))).TreeId;
        return (dispatcher, conn, sessionId, tidA, tidB);
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    /// <summary>A decorator that reports it handled the copy natively via <see cref="IFileStore.CopyRangeAsync"/>.</summary>
    private sealed class OffloadRecordingStore(IFileStore inner) : IFileStore
    {
        public bool OffloadCalled { get; private set; }

        public async ValueTask<FileStoreResult<long>> CopyRangeAsync(
            IFileHandle source, long sourceOffset, IFileHandle destination, long destinationOffset,
            long length, CancellationToken cancellationToken = default)
        {
            OffloadCalled = true;
            // Do the copy by delegating to the inner store's read/write.
            var buffer = new byte[length];
            FileStoreResult<int> read = await inner.ReadAsync(source, sourceOffset, buffer, cancellationToken).ConfigureAwait(false);
            if (!read.IsSuccess) return FileStoreResult<long>.Fail(read.Status);
            FileStoreResult<int> written = await inner.WriteAsync(destination, destinationOffset, buffer.AsMemory(0, read.Value), cancellationToken).ConfigureAwait(false);
            if (!written.IsSuccess) return FileStoreResult<long>.Fail(written.Status);
            return FileStoreResult<long>.Ok(written.Value);
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
