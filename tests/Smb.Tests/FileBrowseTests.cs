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
/// Full path with real credentials: NEGOTIATE → NTLM login → TREE_CONNECT →
/// CREATE/QUERY_DIRECTORY/READ/CLOSE over a locally backed folder.
/// </summary>
public class FileBrowseTests : IDisposable
{
    private readonly string _shareDir;

    public FileBrowseTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbtest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "hello.txt"), "Hello SMB!");
        File.WriteAllBytes(Path.Combine(_shareDir, "data.bin"), [1, 2, 3, 4, 5]);
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void Login_Mount_List_Read_Works()
    {
        // --- Server with real NTLM + local folder backend ---
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "S3cret!");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false, // test focuses on file I/O; signing path is tested separately
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_shareDir, readOnly: true) });

        var state = new SmbServerState(options);
        var dispatcher = new Smb2Dispatcher(state);
        var conn = new SmbConnection();

        // --- NEGOTIATE ---
        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));

        // --- NTLM login with credentials ---
        var client = new NtlmClient("DOM", "alice", "S3cret!");
        byte[] r1 = dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        var h1 = Smb2Header.Read(r1);
        Assert.Equal(NtStatus.MoreProcessingRequired, h1.Status);
        ulong sessionId = h1.SessionId;
        byte[] challenge = ExtractSecurityBuffer(r1);

        byte[] r2 = dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(challenge)));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(r2).Status);

        // --- TREE_CONNECT \\server\Files ---
        byte[] tc = dispatcher.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\server\Files"));
        var tcHeader = Smb2Header.Read(tc);
        Assert.Equal(NtStatus.Success, tcHeader.Status);
        uint treeId = tcHeader.TreeId;

        // --- CREATE (open root directory) ---
        byte[] openDir = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            4, sessionId, treeId, name: "", desiredAccess: 0x00000001,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.DirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(openDir).Status);
        (ulong dirPersistent, ulong dirVolatile) = ExtractCreateFileId(openDir);

        // --- QUERY_DIRECTORY ---
        byte[] list = dispatcher.ProcessMessage(conn, TestHelpers.BuildQueryDirectoryRequest(
            5, sessionId, treeId, dirPersistent, dirVolatile,
            (byte)FileInformationClass.FileIdBothDirectoryInformation, "*", outputBufferLength: 65536));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(list).Status);
        List<string> names = ParseDirectoryNames(list);
        Assert.Contains("hello.txt", names);
        Assert.Contains("data.bin", names);

        // --- CREATE (open file) + READ + CLOSE ---
        byte[] openFile = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            6, sessionId, treeId, name: "hello.txt", desiredAccess: 0x00000001,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(openFile).Status);
        (ulong filePersistent, ulong fileVolatile) = ExtractCreateFileId(openFile);

        byte[] read = dispatcher.ProcessMessage(conn, TestHelpers.BuildReadRequest(
            7, sessionId, treeId, filePersistent, fileVolatile, length: 256, offset: 0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(read).Status);
        Assert.Equal("Hello SMB!", Encoding.UTF8.GetString(ExtractReadData(read)));

        byte[] close = dispatcher.ProcessMessage(conn, TestHelpers.BuildCloseRequest(8, sessionId, treeId, filePersistent, fileVolatile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(close).Status);
    }

    [Fact]
    public void Write_Then_Delete_Works_OnWritableShare()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_shareDir, readOnly: false) });
        var state = new SmbServerState(options);
        var dispatcher = new Smb2Dispatcher(state);
        var conn = new SmbConnection();

        (ulong sessionId, uint treeId) = LoginAndConnect(dispatcher, conn);

        // --- Write file ---
        byte[] create = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            4, sessionId, treeId, "new.txt", desiredAccess: 0x00000003 /* read+write */,
            disposition: (uint)CreateDisposition.OverwriteIf, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        (ulong p, ulong v) = ExtractCreateFileId(create);

        byte[] payload = Encoding.UTF8.GetBytes("Test123");
        byte[] write = dispatcher.ProcessMessage(conn, TestHelpers.BuildWriteRequest(5, sessionId, treeId, p, v, 0, payload));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(write).Status);
        dispatcher.ProcessMessage(conn, TestHelpers.BuildCloseRequest(6, sessionId, treeId, p, v));

        Assert.Equal("Test123", File.ReadAllText(Path.Combine(_shareDir, "new.txt")));

        // --- Delete file (SET_INFO FileDispositionInformation + CLOSE) ---
        byte[] openForDelete = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            7, sessionId, treeId, "new.txt", desiredAccess: 0x00010000 /* DELETE */,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        (ulong dp, ulong dv) = ExtractCreateFileId(openForDelete);

        byte[] setInfo = dispatcher.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            8, sessionId, treeId, dp, dv, infoType: 0x01,
            fileInfoClass: (byte)FileInformationClass.FileDispositionInformation, buffer: [1]));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(setInfo).Status);
        dispatcher.ProcessMessage(conn, TestHelpers.BuildCloseRequest(9, sessionId, treeId, dp, dv));

        Assert.False(File.Exists(Path.Combine(_shareDir, "new.txt")), "File should be gone after DELETE_ON_CLOSE.");
    }

    /// <summary>
    /// A truncating open must leave no tail of the previous, longer content behind.
    /// <para>
    /// The Windows redirector does not implement <c>FileMode.Truncate</c> (and an app saving a shorter file)
    /// with FILE_OVERWRITE. It opens FILE_OPEN, sends SET_INFO <b>FileAllocationInformation</b> with the new
    /// size (0 here), then writes the new, shorter content — exactly the three messages replayed below. The
    /// server used to accept FileAllocationInformation as a no-op, so the file kept its old length and the
    /// new write only overwrote a prefix: writing "BB" over "AAAAAAAAAA" left "BBAAAAAAAA" on disk.
    /// </para>
    /// </summary>
    [Fact]
    public void TruncatingOpen_ViaAllocationInformation_DropsTheOldTail()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_shareDir, readOnly: false) });
        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();
        (ulong sessionId, uint treeId) = LoginAndConnect(dispatcher, conn);

        File.WriteAllText(Path.Combine(_shareDir, "doc.txt"), "AAAAAAAAAA"); // 10 bytes of old content

        // 1) FILE_OPEN with write access — no truncation disposition, just as the redirector sends.
        byte[] create = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            4, sessionId, treeId, "doc.txt", desiredAccess: 0x00000003 /* read+write */,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        (ulong p, ulong v) = ExtractCreateFileId(create);

        // 2) SET_INFO FileAllocationInformation = 0 → the truncation request.
        byte[] alloc = new byte[8]; // AllocationSize = 0
        byte[] setInfo = dispatcher.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            5, sessionId, treeId, p, v, infoType: 0x01,
            fileInfoClass: (byte)FileInformationClass.FileAllocationInformation, buffer: alloc));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(setInfo).Status);

        // 3) Write the new, shorter content at offset 0.
        byte[] write = dispatcher.ProcessMessage(conn, TestHelpers.BuildWriteRequest(
            6, sessionId, treeId, p, v, 0, Encoding.UTF8.GetBytes("BB")));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(write).Status);
        dispatcher.ProcessMessage(conn, TestHelpers.BuildCloseRequest(7, sessionId, treeId, p, v));

        Assert.Equal("BB", File.ReadAllText(Path.Combine(_shareDir, "doc.txt")));
    }

    /// <summary>
    /// The counterpart: FileAllocationInformation asking for a size at or above the current end-of-file is a
    /// reservation hint only and must not change the file's content or length. Guards against "fix truncation"
    /// turning every allocation set into a truncation.
    /// </summary>
    [Fact]
    public void AllocationInformation_GrowOrEqual_LeavesContentUnchanged()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_shareDir, readOnly: false) });
        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();
        (ulong sessionId, uint treeId) = LoginAndConnect(dispatcher, conn);

        File.WriteAllText(Path.Combine(_shareDir, "keep.txt"), "HELLO"); // 5 bytes

        byte[] create = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            4, sessionId, treeId, "keep.txt", desiredAccess: 0x00000003,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        (ulong p, ulong v) = ExtractCreateFileId(create);

        byte[] alloc = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(alloc, 4096); // reserve well above EOF
        byte[] setInfo = dispatcher.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            5, sessionId, treeId, p, v, infoType: 0x01,
            fileInfoClass: (byte)FileInformationClass.FileAllocationInformation, buffer: alloc));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(setInfo).Status);
        dispatcher.ProcessMessage(conn, TestHelpers.BuildCloseRequest(6, sessionId, treeId, p, v));

        Assert.Equal("HELLO", File.ReadAllText(Path.Combine(_shareDir, "keep.txt")));
    }

    [Fact]
    public void CreateDirectory_Then_List_Works()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_shareDir, readOnly: false) });
        var state = new SmbServerState(options);
        var dispatcher = new Smb2Dispatcher(state);
        var conn = new SmbConnection();

        (ulong sessionId, uint treeId) = LoginAndConnect(dispatcher, conn);

        // mkdir
        byte[] mkdir = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            4, sessionId, treeId, "newFolder", desiredAccess: 0x001F01FF,
            disposition: (uint)CreateDisposition.Create, options: (uint)CreateOptions.DirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(mkdir).Status);
        Assert.True(Directory.Exists(Path.Combine(_shareDir, "newFolder")));
        (ulong p, ulong v) = ExtractCreateFileId(mkdir);

        // List the new (empty) directory → expect "." and "..".
        byte[] list = dispatcher.ProcessMessage(conn, TestHelpers.BuildQueryDirectoryRequest(
            5, sessionId, treeId, p, v,
            (byte)FileInformationClass.FileIdBothDirectoryInformation, "*", outputBufferLength: 65536));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(list).Status);
        List<string> names = ParseDirectoryNames(list);
        Assert.Contains(".", names);
        Assert.Contains("..", names);

        dispatcher.ProcessMessage(conn, TestHelpers.BuildCloseRequest(6, sessionId, treeId, p, v));
    }

    /// <summary>
    /// A specific-name search pattern must return only the matching entry — never the synthesized
    /// "." / ".." (they are matched against the pattern like any other name, FsRtlIsNameInExpression
    /// semantics). This was Explorer's new-folder bug: its post-CREATE lookup with the exact folder
    /// name (+ SL_RETURN_SINGLE_ENTRY) got "." as the single entry, so the freshly created folder
    /// displayed as "." and the inline-rename box never opened.
    /// </summary>
    [Fact]
    public void QueryDirectory_SpecificName_ReturnsOnlyThatEntry_WithoutDotSynthesis()
    {
        var (dispatcher, conn, sessionId, treeId) = WritableShare();
        Directory.CreateDirectory(Path.Combine(_shareDir, "Neuer Ordner"));

        (ulong p, ulong v) = OpenRootDirectory(dispatcher, conn, sessionId, treeId, mid: 4);
        byte[] list = dispatcher.ProcessMessage(conn, TestHelpers.BuildQueryDirectoryRequest(
            5, sessionId, treeId, p, v,
            (byte)FileInformationClass.FileIdBothDirectoryInformation, "Neuer Ordner", outputBufferLength: 65536));

        Assert.Equal(NtStatus.Success, Smb2Header.Read(list).Status);
        Assert.Equal(["Neuer Ordner"], ParseDirectoryNames(list));
    }

    /// <summary>The exact Explorer shape: specific name + SL_RETURN_SINGLE_ENTRY → the real entry, not ".".</summary>
    [Fact]
    public void QueryDirectory_SpecificName_SingleEntry_ReturnsTheRealEntry()
    {
        var (dispatcher, conn, sessionId, treeId) = WritableShare();
        Directory.CreateDirectory(Path.Combine(_shareDir, "Neuer Ordner"));

        (ulong p, ulong v) = OpenRootDirectory(dispatcher, conn, sessionId, treeId, mid: 4);
        byte[] list = dispatcher.ProcessMessage(conn, TestHelpers.BuildQueryDirectoryRequest(
            5, sessionId, treeId, p, v,
            (byte)FileInformationClass.FileIdBothDirectoryInformation, "Neuer Ordner", outputBufferLength: 65536,
            flags: QueryDirectoryMessage.FlagReturnSingleEntry));

        Assert.Equal(NtStatus.Success, Smb2Header.Read(list).Status);
        Assert.Equal(["Neuer Ordner"], ParseDirectoryNames(list));
    }

    /// <summary>
    /// A specific pattern matching nothing must yield STATUS_NO_SUCH_FILE on the first scan call —
    /// the unconditional "." synthesis previously made the listing non-empty and masked this status.
    /// </summary>
    [Fact]
    public void QueryDirectory_NonMatchingSpecificName_ReturnsNoSuchFile()
    {
        var (dispatcher, conn, sessionId, treeId) = WritableShare();

        (ulong p, ulong v) = OpenRootDirectory(dispatcher, conn, sessionId, treeId, mid: 4);
        byte[] list = dispatcher.ProcessMessage(conn, TestHelpers.BuildQueryDirectoryRequest(
            5, sessionId, treeId, p, v,
            (byte)FileInformationClass.FileIdBothDirectoryInformation, "does-not-exist", outputBufferLength: 65536));

        Assert.Equal(NtStatus.NoSuchFile, Smb2Header.Read(list).Status);
    }

    private (Smb2Dispatcher dispatcher, SmbConnection conn, ulong sessionId, uint treeId) WritableShare()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_shareDir, readOnly: false) });
        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();
        (ulong sessionId, uint treeId) = LoginAndConnect(dispatcher, conn);
        return (dispatcher, conn, sessionId, treeId);
    }

    private static (ulong p, ulong v) OpenRootDirectory(Smb2Dispatcher dispatcher, SmbConnection conn,
        ulong sessionId, uint treeId, ulong mid)
    {
        byte[] openDir = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            mid, sessionId, treeId, name: "", desiredAccess: 0x00000001,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.DirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(openDir).Status);
        return ExtractCreateFileId(openDir);
    }

    private (ulong sessionId, uint treeId) LoginAndConnect(Smb2Dispatcher dispatcher, SmbConnection conn)
    {
        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        uint treeId = Smb2Header.Read(dispatcher.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\s\Files"))).TreeId;
        return (sessionId, treeId);
    }

    [Fact]
    public void Read_NonexistentFile_ReturnsObjectNameNotFound()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_shareDir, true) });
        var state = new SmbServerState(options);
        var dispatcher = new Smb2Dispatcher(state);
        var conn = new SmbConnection();

        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");

        byte[] r1 = dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        byte[] challenge = ExtractSecurityBuffer(r1);
        dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(challenge)));

        uint treeId = Smb2Header.Read(dispatcher.ProcessMessage(conn,
            TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\s\Files"))).TreeId;

        byte[] open = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            4, sessionId, treeId, "missing.txt", 0x1, (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.ObjectNameNotFound, Smb2Header.Read(open).Status);
    }

    // --- Parse helpers ---

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    private static (ulong persistent, ulong vol) ExtractCreateFileId(byte[] response)
    {
        // CREATE response: FileId persistent at body offset 64, volatile at 72.
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

    private static List<string> ParseDirectoryNames(byte[] response)
    {
        const int body = Smb2Header.Size;
        int bufLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(body + 4, 4));
        ReadOnlySpan<byte> buffer = response.AsSpan(72, bufLen); // OutputBufferOffset = 72

        var names = new List<string>();
        int pos = 0;
        while (pos < buffer.Length)
        {
            int next = (int)BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(pos, 4));
            int nameLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(pos + 60, 4));
            // FileIdBothDirectoryInformation: name starts at entry offset 104.
            names.Add(Encoding.Unicode.GetString(buffer.Slice(pos + 104, nameLen)));
            if (next == 0) break;
            pos += next;
        }
        return names;
    }
}
