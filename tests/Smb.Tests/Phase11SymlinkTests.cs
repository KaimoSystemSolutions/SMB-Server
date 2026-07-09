using System.Buffers.Binary;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Security;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 11 / M11.2 — reparse point / symlink responses. When a component of a CREATE path is a
/// symbolic link (reported by an opt-in <see cref="ISymlinkResolver"/> backend), the server answers
/// <c>STATUS_STOPPED_ON_SYMLINK</c> with a SYMLINK_ERROR_RESPONSE (MS-SMB2 §2.2.2.2.1) instead of
/// silently following it; <c>FILE_OPEN_REPARSE_POINT</c> opens the link itself, and non-symlink backends
/// are unaffected.
/// </summary>
public class Phase11SymlinkTests : IDisposable
{
    private const uint ReadAccess = 0x00000001;

    private readonly string _dir;
    private ulong _mid = 10;

    private ulong NextMid() => _mid++;

    public Phase11SymlinkTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "smbsymlink_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { /* ignore */ }
    }

    // --- pure wire round-trips ---

    [Fact]
    public void SymlinkErrorResponse_Absolute_RoundTrips()
    {
        byte[] body = SymlinkErrorResponse.Build(@"\??\C:\real\target", @"C:\real\target", unparsedPathLength: 8, relative: false);
        SymlinkErrorResponse.Parsed p = SymlinkErrorResponse.Parse(body);

        Assert.Equal(@"\??\C:\real\target", p.SubstituteName);
        Assert.Equal(@"C:\real\target", p.PrintName);
        Assert.Equal(8, p.UnparsedPathLength);
        Assert.False(p.IsRelative);
    }

    [Fact]
    public void SymlinkErrorResponse_Relative_SetsFlag()
    {
        byte[] body = SymlinkErrorResponse.Build(@"..\peer", @"..\peer", unparsedPathLength: 0, relative: true);
        SymlinkErrorResponse.Parsed p = SymlinkErrorResponse.Parse(body);

        Assert.Equal(@"..\peer", p.SubstituteName);
        Assert.True(p.IsRelative);
        Assert.Equal(0, p.UnparsedPathLength);
        // SymLinkErrorTag / ReparseTag at the fixed offsets.
        Assert.Equal(SymlinkErrorResponse.SymLinkErrorTag, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(4, 4)));
        Assert.Equal(SymlinkErrorResponse.IoReparseTagSymlink, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(8, 4)));
    }

    [Fact]
    public void ErrorContext_WrapsAndUnwrapsSymlinkData()
    {
        byte[] symlink = SymlinkErrorResponse.Build(@"\??\C:\t", @"C:\t", 4, relative: false);
        byte[] body = ErrorResponse.BuildBodyWithContext(symlink);

        // ErrorContextCount == 1, and the unwrapped payload equals the original SYMLINK_ERROR_RESPONSE.
        Assert.Equal(1, body[2]);
        Assert.Equal(symlink, ErrorResponse.ReadErrorData(body));

        // The raw-ErrorData path (older dialects) round-trips through the same reader.
        byte[] raw = ErrorResponse.BuildBody(symlink);
        Assert.Equal(0, raw[2]);
        Assert.Equal(symlink, ErrorResponse.ReadErrorData(raw));
    }

    // --- CREATE over the dispatcher ---

    [Fact]
    public void Create_OnSymlinkPath_StoppedOnSymlink()
    {
        var target = new SymlinkTarget(@"\??\C:\elsewhere", @"C:\elsewhere", UnparsedPathLength: 0, IsRelative: false);
        var store = new SymlinkStore(new LocalFileStore(_dir, readOnly: false), "link.txt", target);
        var (d, conn, sid, tid) = Setup(store);

        byte[] resp = Create(d, conn, sid, tid, "link.txt", (uint)CreateOptions.NonDirectoryFile);
        Assert.Equal(NtStatus.StoppedOnSymlink, Smb2Header.Read(resp).Status);

        // On 3.1.1 the SYMLINK_ERROR_RESPONSE is wrapped in an SMB2_ERROR_CONTEXT (§2.2.2.1);
        // ReadErrorData unwraps it. The body should carry ErrorContextCount = 1.
        Assert.Equal(1, resp[Smb2Header.Size + 2]);
        SymlinkErrorResponse.Parsed p = SymlinkErrorResponse.Parse(ErrorResponse.ReadErrorData(resp.AsSpan(Smb2Header.Size)));
        Assert.Equal(@"\??\C:\elsewhere", p.SubstituteName);
        Assert.Equal(@"C:\elsewhere", p.PrintName);
        Assert.False(p.IsRelative);
    }

    [Fact]
    public void Create_WithOpenReparsePoint_OpensLinkItself()
    {
        var target = new SymlinkTarget(@"\??\C:\elsewhere", null, 0, false);
        var store = new SymlinkStore(new LocalFileStore(_dir, readOnly: false), "link.txt", target);
        var (d, conn, sid, tid) = Setup(store);
        File.WriteAllBytes(Path.Combine(_dir, "link.txt"), new byte[4]);

        // FILE_OPEN_REPARSE_POINT bypasses the symlink interception → the link is opened normally.
        byte[] resp = Create(d, conn, sid, tid, "link.txt",
            (uint)(CreateOptions.NonDirectoryFile | CreateOptions.OpenReparsePoint));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void Create_NonLinkPath_ResolvesNormally()
    {
        var target = new SymlinkTarget(@"\??\C:\elsewhere", null, 0, false);
        var store = new SymlinkStore(new LocalFileStore(_dir, readOnly: false), "link.txt", target);
        var (d, conn, sid, tid) = Setup(store);
        File.WriteAllBytes(Path.Combine(_dir, "regular.txt"), new byte[4]);

        byte[] resp = Create(d, conn, sid, tid, "regular.txt", (uint)CreateOptions.NonDirectoryFile);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void Create_OnPlainBackend_NotIntercepted()
    {
        var (d, conn, sid, tid) = Setup(new LocalFileStore(_dir, readOnly: false));
        File.WriteAllBytes(Path.Combine(_dir, "link.txt"), new byte[4]);

        // No ISymlinkResolver → never STOPPED_ON_SYMLINK.
        byte[] resp = Create(d, conn, sid, tid, "link.txt", (uint)CreateOptions.NonDirectoryFile);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
    }

    // --- helpers ---

    private byte[] Create(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, string name, uint options)
        => d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            NextMid(), sid, tid, name, ReadAccess, (uint)CreateDisposition.Open, options));

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

    /// <summary>A <see cref="LocalFileStore"/> wrapper that reports one configured path as a symlink.</summary>
    private sealed class SymlinkStore(IFileStore inner, string linkPath, SymlinkTarget target) : IFileStore, ISymlinkResolver
    {
        public ValueTask<SymlinkTarget?> ResolveSymlinkAsync(string path, CancellationToken cancellationToken = default)
            => new(string.Equals(path, linkPath, StringComparison.OrdinalIgnoreCase) ? target : null);

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
        public ValueTask<FileStoreResult<SecurityDescriptor>> GetSecurityAsync(IFileHandle handle, CancellationToken cancellationToken = default)
            => inner.GetSecurityAsync(handle, cancellationToken);
        public ValueTask<NtStatus> SetSecurityAsync(IFileHandle handle, SecurityDescriptor descriptor, CancellationToken cancellationToken = default)
            => inner.SetSecurityAsync(handle, descriptor, cancellationToken);
    }
}
