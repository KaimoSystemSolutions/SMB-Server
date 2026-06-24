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
/// Voller Pfad mit echten Credentials: NEGOTIATE → NTLM-Login → TREE_CONNECT →
/// CREATE/QUERY_DIRECTORY/READ/CLOSE über einen lokal hinterlegten Ordner.
/// </summary>
public class FileBrowseTests : IDisposable
{
    private readonly string _shareDir;

    public FileBrowseTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbtest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "hello.txt"), "Hallo SMB!");
        File.WriteAllBytes(Path.Combine(_shareDir, "data.bin"), [1, 2, 3, 4, 5]);
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void Login_Mount_List_Read_Works()
    {
        // --- Server mit echtem NTLM + lokalem Ordner-Backend ---
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "S3cret!");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false, // Test fokussiert auf Datei-I/O; Signing-Pfad ist separat getestet
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_shareDir, readOnly: true) });

        var state = new SmbServerState(options);
        var dispatcher = new Smb2Dispatcher(state);
        var conn = new SmbConnection();

        // --- NEGOTIATE ---
        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));

        // --- NTLM-Login mit Credentials ---
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

        // --- CREATE (Wurzelverzeichnis öffnen) ---
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

        // --- CREATE (Datei öffnen) + READ + CLOSE ---
        byte[] openFile = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            6, sessionId, treeId, name: "hello.txt", desiredAccess: 0x00000001,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(openFile).Status);
        (ulong filePersistent, ulong fileVolatile) = ExtractCreateFileId(openFile);

        byte[] read = dispatcher.ProcessMessage(conn, TestHelpers.BuildReadRequest(
            7, sessionId, treeId, filePersistent, fileVolatile, length: 256, offset: 0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(read).Status);
        Assert.Equal("Hallo SMB!", Encoding.UTF8.GetString(ExtractReadData(read)));

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

        // --- Datei schreiben ---
        byte[] create = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            4, sessionId, treeId, "neu.txt", desiredAccess: 0x00000003 /* read+write */,
            disposition: (uint)CreateDisposition.OverwriteIf, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        (ulong p, ulong v) = ExtractCreateFileId(create);

        byte[] payload = Encoding.UTF8.GetBytes("Test123");
        byte[] write = dispatcher.ProcessMessage(conn, TestHelpers.BuildWriteRequest(5, sessionId, treeId, p, v, 0, payload));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(write).Status);
        dispatcher.ProcessMessage(conn, TestHelpers.BuildCloseRequest(6, sessionId, treeId, p, v));

        Assert.Equal("Test123", File.ReadAllText(Path.Combine(_shareDir, "neu.txt")));

        // --- Datei löschen (SET_INFO FileDispositionInformation + CLOSE) ---
        byte[] openForDelete = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            7, sessionId, treeId, "neu.txt", desiredAccess: 0x00010000 /* DELETE */,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        (ulong dp, ulong dv) = ExtractCreateFileId(openForDelete);

        byte[] setInfo = dispatcher.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            8, sessionId, treeId, dp, dv, infoType: 0x01,
            fileInfoClass: (byte)FileInformationClass.FileDispositionInformation, buffer: [1]));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(setInfo).Status);
        dispatcher.ProcessMessage(conn, TestHelpers.BuildCloseRequest(9, sessionId, treeId, dp, dv));

        Assert.False(File.Exists(Path.Combine(_shareDir, "neu.txt")), "Datei sollte nach DELETE_ON_CLOSE weg sein.");
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
            4, sessionId, treeId, "neuerOrdner", desiredAccess: 0x001F01FF,
            disposition: (uint)CreateDisposition.Create, options: (uint)CreateOptions.DirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(mkdir).Status);
        Assert.True(Directory.Exists(Path.Combine(_shareDir, "neuerOrdner")));
        (ulong p, ulong v) = ExtractCreateFileId(mkdir);

        // Das neue (leere) Verzeichnis listen → "." und ".." erwartet.
        byte[] list = dispatcher.ProcessMessage(conn, TestHelpers.BuildQueryDirectoryRequest(
            5, sessionId, treeId, p, v,
            (byte)FileInformationClass.FileIdBothDirectoryInformation, "*", outputBufferLength: 65536));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(list).Status);
        List<string> names = ParseDirectoryNames(list);
        Assert.Contains(".", names);
        Assert.Contains("..", names);

        dispatcher.ProcessMessage(conn, TestHelpers.BuildCloseRequest(6, sessionId, treeId, p, v));
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

    // --- Parse-Hilfen ---

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    private static (ulong persistent, ulong vol) ExtractCreateFileId(byte[] response)
    {
        // CREATE-Response: FileId persistent bei Body-Offset 64, volatile bei 72.
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
            // FileIdBothDirectoryInformation: Name beginnt bei Eintrags-Offset 104.
            names.Add(Encoding.Unicode.GetString(buffer.Slice(pos + 104, nameLen)));
            if (next == 0) break;
            pos += next;
        }
        return names;
    }
}
