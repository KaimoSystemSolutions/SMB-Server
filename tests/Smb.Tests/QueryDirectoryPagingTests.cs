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
/// End-to-end QUERY_DIRECTORY paging + stable FileId (O2) and CREATE share-mode / sharing-violation
/// (O5), driven through the dispatcher against a writable local folder backend.
/// </summary>
public sealed class QueryDirectoryPagingTests : IDisposable
{
    private const byte FileIdBothDirectoryInformation = 37;
    private const byte SlRestartScan = 0x01;
    private const byte SlReturnSingleEntry = 0x02;

    private readonly string _shareDir;

    public QueryDirectoryPagingTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smb-page-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
    }

    public void Dispose() { try { Directory.Delete(_shareDir, true); } catch { /* best effort */ } }

    [Fact]
    public void LargeDirectory_IsPagedAcrossQueries_NeverInvalidParameter()
    {
        for (int i = 0; i < 40; i++)
            File.WriteAllText(Path.Combine(_shareDir, $"file{i:D3}.txt"), "x");

        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = OpenDir(d, conn, sid, tid);

        int totalEntries = 0, pages = 0;
        for (ulong mid = 10; mid < 500; mid++)
        {
            byte flags = mid == 10 ? SlRestartScan : (byte)0;
            byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryDirectoryRequest(
                mid, sid, tid, p, v, FileIdBothDirectoryInformation, pattern: "*",
                outputBufferLength: 512, flags: flags));
            NtStatus status = Smb2Header.Read(resp).Status;
            if (status == NtStatus.NoMoreFiles) break;
            Assert.Equal(NtStatus.Success, status); // never INVALID_PARAMETER (the old single-buffer bug)
            pages++;
            totalEntries += CountEntries(resp);
        }

        Assert.True(pages > 1, "the listing should span more than one page at 512-byte buffers");
        Assert.Equal(40 + 1, totalEntries); // 40 files + "." (the share root has no ".." entry)
    }

    [Fact]
    public void SingleEntryFlag_ReturnsExactlyOneEntry()
    {
        for (int i = 0; i < 3; i++)
            File.WriteAllText(Path.Combine(_shareDir, $"f{i}.txt"), "x");

        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = OpenDir(d, conn, sid, tid);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryDirectoryRequest(
            10, sid, tid, p, v, FileIdBothDirectoryInformation, "*", 4096,
            flags: (byte)(SlRestartScan | SlReturnSingleEntry)));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        Assert.Equal(1, CountEntries(resp));
    }

    [Fact]
    public void OutputBuffer_TooSmallForOneEntry_ReturnsInfoLengthMismatch()
    {
        File.WriteAllText(Path.Combine(_shareDir, "some-long-named-file.txt"), "x");
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = OpenDir(d, conn, sid, tid);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryDirectoryRequest(
            10, sid, tid, p, v, FileIdBothDirectoryInformation, "*", outputBufferLength: 8, flags: SlRestartScan));
        Assert.Equal(NtStatus.InfoLengthMismatch, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void SecondOpen_WithExclusiveShare_GetsSharingViolation()
    {
        var (d, conn, sid, tid) = Setup();

        // First open: read+write, shares NOTHING (exclusive).
        byte[] o1 = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            10, sid, tid, "locked.txt", desiredAccess: 0x00000003,
            disposition: (uint)CreateDisposition.OpenIf, options: (uint)CreateOptions.NonDirectoryFile,
            shareAccess: 0x0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(o1).Status);

        // Second open of the SAME file → sharing violation (not silently allowed).
        byte[] o2 = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            11, sid, tid, "locked.txt", desiredAccess: 0x00000001,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile,
            shareAccess: 0x0));
        Assert.Equal(NtStatus.SharingViolation, Smb2Header.Read(o2).Status);
    }

    [Fact]
    public void SharingViolation_ClearsAfterClose()
    {
        var (d, conn, sid, tid) = Setup();
        byte[] o1 = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            10, sid, tid, "f.txt", 0x00000003, (uint)CreateDisposition.OpenIf,
            (uint)CreateOptions.NonDirectoryFile, shareAccess: 0x0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(o1).Status);
        (ulong p, ulong v) = ReadFileId(o1);

        Assert.Equal(NtStatus.Success, Smb2Header.Read(
            d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(11, sid, tid, p, v))).Status);

        // After CLOSE the exclusive reservation is released → reopening succeeds.
        byte[] o2 = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            12, sid, tid, "f.txt", 0x00000003, (uint)CreateDisposition.Open,
            (uint)CreateOptions.NonDirectoryFile, shareAccess: 0x0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(o2).Status);
    }

    // --- helpers ---

    private static int CountEntries(byte[] response)
    {
        const int bufStart = Smb2Header.Size + 8; // header(64) + StructureSize(2)+OutputBufferOffset(2)+OutputBufferLength(4)
        uint bufLen = BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(Smb2Header.Size + 4, 4));
        int count = 0, pos = bufStart, end = bufStart + (int)bufLen;
        while (pos + 4 <= end)
        {
            uint next = BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(pos, 4)); // NextEntryOffset
            count++;
            if (next == 0) break;
            pos += (int)next;
        }
        return count;
    }

    private static (ulong p, ulong v) ReadFileId(byte[] createResponse)
    {
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(createResponse.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(createResponse.AsSpan(body + 72, 8)));
    }

    private (ulong p, ulong v) OpenDir(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            5, sid, tid, "", desiredAccess: 0x00000001, disposition: (uint)CreateDisposition.Open,
            options: (uint)CreateOptions.DirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        return ReadFileId(create);
    }

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
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
}
