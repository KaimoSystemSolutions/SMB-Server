using System.Buffers.Binary;
using System.Text;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Messages.Fscc;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 9 — alternate data streams (M9.1) and extended attributes (M9.2) over the dispatcher, plus the
/// pure wire structures. Streams: create/write/read/enumerate/delete a named stream; EAs: set/get/delete.
/// </summary>
public class Phase9StreamsAndEaTests : IDisposable
{
    private readonly string _shareDir;
    private const byte InfoTypeFile = 0x01;
    private const uint FullAccess = 0x001F01FF;

    public Phase9StreamsAndEaTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbp9_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "doc.txt"), "hello");
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    // ---- Pure wire structures -------------------------------------------------

    [Fact]
    public void StreamInformation_RoundTripsTwoStreams()
    {
        byte[] buf = StreamInformation.Build([
            new FsccStreamEntry(string.Empty, 5, 4096),
            new FsccStreamEntry("meta", 3, 4096),
        ]);

        var names = ParseStreamNames(buf);
        Assert.Equal(new[] { "::$DATA", ":meta:$DATA" }, names);
    }

    [Fact]
    public void FullEaInformation_RoundTrips()
    {
        var input = new List<FsccEaEntry>
        {
            new(0x00, "AUTHOR", Encoding.ASCII.GetBytes("alice")),
            new(0x80, "ZONE", [0x03]),
        };
        byte[] buf = FullEaInformation.Build(input);
        IReadOnlyList<FsccEaEntry> parsed = FullEaInformation.Parse(buf);

        Assert.Equal(2, parsed.Count);
        Assert.Equal("AUTHOR", parsed[0].Name);
        Assert.Equal("alice", Encoding.ASCII.GetString(parsed[0].Value));
        Assert.Equal("ZONE", parsed[1].Name);
        Assert.Equal(0x80, parsed[1].Flags);
        Assert.Equal(new byte[] { 0x03 }, parsed[1].Value);
    }

    // ---- Named streams (M9.1) -------------------------------------------------

    [Fact]
    public void NamedStream_WriteReadEnumerate()
    {
        var (d, conn, sid, tid) = Setup();

        // Create the named stream doc.txt:meta and write to it.
        (ulong p, ulong v) = Open(d, conn, sid, tid, "doc.txt:meta",
            disposition: (uint)CreateDisposition.Create, mid: 20);
        byte[] payload = Encoding.ASCII.GetBytes("streamdata");
        byte[] wr = d.ProcessMessage(conn, TestHelpers.BuildWriteRequest(21, sid, tid, p, v, 0, payload));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(wr).Status);

        // Read it back.
        byte[] rd = d.ProcessMessage(conn, TestHelpers.BuildReadRequest(22, sid, tid, p, v, (uint)payload.Length, 0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(rd).Status);
        Assert.Equal("streamdata", Encoding.ASCII.GetString(ReadPayload(rd)));

        // Enumerate the base file's streams: default + :meta.
        (ulong bp, ulong bv) = Open(d, conn, sid, tid, "doc.txt",
            disposition: (uint)CreateDisposition.Open, mid: 23);
        byte[] q = d.ProcessMessage(conn, TestHelpers.BuildQueryInfoRequest(
            24, sid, tid, bp, bv, InfoTypeFile,
            fileInfoClass: (byte)FileInformationClass.FileStreamInformation, outputBufferLength: 65536));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(q).Status);
        var names = ParseStreamNames(QueryPayload(q));
        Assert.Contains("::$DATA", names);
        Assert.Contains(":meta:$DATA", names);
    }

    [Fact]
    public void NamedStream_DeleteOnClose_RemovesOnlyTheStream()
    {
        var (d, conn, sid, tid) = Setup();

        // Create the stream, then re-open it with DELETE_ON_CLOSE and close → the stream is gone.
        (ulong p, ulong v) = Open(d, conn, sid, tid, "doc.txt:tmp",
            disposition: (uint)CreateDisposition.Create, mid: 30);
        d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(31, sid, tid, p, v));

        (ulong dp, ulong dv) = Open(d, conn, sid, tid, "doc.txt:tmp",
            disposition: (uint)CreateDisposition.Open, mid: 32,
            options: (uint)(CreateOptions.NonDirectoryFile | CreateOptions.DeleteOnClose));
        d.ProcessMessage(conn, TestHelpers.BuildCloseRequest(33, sid, tid, dp, dv));

        // Re-opening the stream now fails; the base file still opens fine.
        byte[] gone = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            34, sid, tid, "doc.txt:tmp", desiredAccess: FullAccess,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.ObjectNameNotFound, Smb2Header.Read(gone).Status);

        byte[] baseOk = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            35, sid, tid, "doc.txt", desiredAccess: FullAccess,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(baseOk).Status);
    }

    [Fact]
    public void OpenNamedStream_OnNonAdsBackend_NotSupported()
    {
        var (d, conn, sid, tid) = Setup(useNamedStreams: false);
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            40, sid, tid, "doc.txt:meta", desiredAccess: FullAccess,
            disposition: (uint)CreateDisposition.Create, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.NotSupported, Smb2Header.Read(resp).Status);
    }

    // ---- Extended attributes (M9.2) ------------------------------------------

    [Fact]
    public void ExtendedAttributes_SetGetDelete()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = Open(d, conn, sid, tid, "doc.txt",
            disposition: (uint)CreateDisposition.Open, mid: 50);

        // Set two EAs.
        byte[] setBuf = FullEaInformation.Build([
            new FsccEaEntry(0, "AUTHOR", Encoding.ASCII.GetBytes("alice")),
            new FsccEaEntry(0, "ZONE", [0x03]),
        ]);
        byte[] set = d.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            51, sid, tid, p, v, InfoTypeFile,
            fileInfoClass: (byte)FileInformationClass.FileFullEaInformation, buffer: setBuf));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(set).Status);

        // Read them back.
        IReadOnlyList<FsccEaEntry> got = QueryEas(d, conn, sid, tid, p, v, mid: 52);
        Assert.Equal(2, got.Count);
        Assert.Equal("alice", Encoding.ASCII.GetString(got.First(e => e.Name == "AUTHOR").Value));

        // Delete AUTHOR (zero-length value), leaving ZONE.
        byte[] delBuf = FullEaInformation.Build([new FsccEaEntry(0, "AUTHOR", [])]);
        d.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            53, sid, tid, p, v, InfoTypeFile,
            fileInfoClass: (byte)FileInformationClass.FileFullEaInformation, buffer: delBuf));

        IReadOnlyList<FsccEaEntry> after = QueryEas(d, conn, sid, tid, p, v, mid: 54);
        Assert.Single(after);
        Assert.Equal("ZONE", after[0].Name);
    }

    [Fact]
    public void QueryEa_OnBackendWithoutEas_ReturnsEmpty()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = Open(d, conn, sid, tid, "doc.txt",
            disposition: (uint)CreateDisposition.Open, mid: 60);
        Assert.Empty(QueryEas(d, conn, sid, tid, p, v, mid: 61));
    }

    // ---- helpers --------------------------------------------------------------

    private static IReadOnlyList<FsccEaEntry> QueryEas(
        Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong p, ulong v, ulong mid)
    {
        byte[] q = d.ProcessMessage(conn, TestHelpers.BuildQueryInfoRequest(
            mid, sid, tid, p, v, InfoTypeFile,
            fileInfoClass: (byte)FileInformationClass.FileFullEaInformation, outputBufferLength: 65536));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(q).Status);
        byte[] payload = QueryPayload(q);
        return payload.Length == 0 ? [] : FullEaInformation.Parse(payload);
    }

    private static string[] ParseStreamNames(byte[] buffer)
    {
        var names = new List<string>();
        int offset = 0;
        while (offset < buffer.Length)
        {
            uint next = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4));
            int nameLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset + 4, 4));
            names.Add(Encoding.Unicode.GetString(buffer.AsSpan(offset + 24, nameLen)));
            if (next == 0) break;
            offset += (int)next;
        }
        return names.ToArray();
    }

    private static byte[] QueryPayload(byte[] resp)
    {
        int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 4, 4));
        return resp.AsSpan(Smb2Header.Size + 8, len).ToArray();
    }

    private static byte[] ReadPayload(byte[] resp)
    {
        // READ Response: StructureSize(2) DataOffset(1) Reserved(1) DataLength(4) ...
        int dataOffset = resp[Smb2Header.Size + 2];
        int dataLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 4, 4));
        return resp.AsSpan(dataOffset, dataLen).ToArray();
    }

    private static (ulong p, ulong v) Open(
        Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, string name, uint disposition, ulong mid,
        uint options = (uint)CreateOptions.NonDirectoryFile)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            mid, sid, tid, name, desiredAccess: FullAccess, disposition: disposition, options: options));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8)));
    }

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(bool useNamedStreams = true)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());
        IFileStore store = useNamedStreams
            ? new LocalFileStore(_shareDir, readOnly: false)
            : new NoStreamsFileStore(_shareDir);
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

    /// <summary>A disk backend that deliberately does not implement <see cref="INamedStreamStore"/>.</summary>
    private sealed class NoStreamsFileStore(string root) : IFileStore
    {
        private readonly LocalFileStore _inner = new(root, readOnly: false);

        public ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
            => _inner.CreateAsync(path, access, disposition, directoryRequired, nonDirectoryRequired, cancellationToken);
        public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _inner.ReadAsync(handle, offset, buffer, cancellationToken);
        public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
            => _inner.WriteAsync(handle, offset, data, cancellationToken);
        public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
            => _inner.QueryDirectoryAsync(handle, searchPattern, cancellationToken);
        public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default)
            => _inner.SetEndOfFileAsync(handle, length, cancellationToken);
        public ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default)
            => _inner.RenameAsync(handle, newPath, replaceIfExists, cancellationToken);
        public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default)
            => _inner.SetDeleteOnCloseAsync(handle, delete, cancellationToken);
        public ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default)
            => _inner.FlushAsync(handle, cancellationToken);
    }
}
