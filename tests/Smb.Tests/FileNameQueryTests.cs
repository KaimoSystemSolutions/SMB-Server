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
/// Handle-based name queries: QUERY_INFO FileNameInformation (9), FileAllInformation's name section
/// (18) and FileNormalizedNameInformation (48) must answer with the path relative to the SHARE ROOT,
/// leading backslash included (MS-FSCC §2.1.7 / §2.4.34), and 48 only exists on the 3.1.1 dialect
/// (MS-SMB2 §3.3.5.20.1).
/// <para>
/// Found in the 2026-07-16 manual Explorer capture: the server declined class 48 outright and
/// answered 9/18 with the LEAF name. GetFinalPathNameByHandle — which Office's save path, the
/// shell's shortcut handling and every Windows.Storage-based app (Windows 11 Notepad) call while
/// opening a file — reconstructs the file's full UNC path from these answers. With the leaf-only
/// name the client rebuilt wrong paths and re-opened them: CREATEs for <c>Files\doc.pptx</c>
/// (share component doubled) and for <c>""</c> with NonDirectoryFile (leaf lost, share root opened
/// as a file), both failing — surfacing as "file not found" dialogs on files that plainly exist,
/// and as ~1 s retry loops (Office re-runs its lock-file open when class 48 fails).
/// </para>
/// </summary>
public class FileNameQueryTests : IDisposable
{
    private const byte InfoTypeFile = 0x01;
    private const uint FullAccess = 0x001F01FF;

    private readonly string _shareDir;

    public FileNameQueryTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbnq_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(_shareDir, "sub"));
        Directory.CreateDirectory(Path.Combine(_shareDir, "sub2"));
        File.WriteAllText(Path.Combine(_shareDir, "sub", "notes.txt"), "x");
        File.WriteAllText(Path.Combine(_shareDir, "root.txt"), "x");
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void FileNameInformation_ReturnsShareRelativePath_WithLeadingBackslash()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = Open(d, conn, sid, tid, @"sub\notes.txt", mid: 10);

        Assert.Equal(@"\sub\notes.txt", QueryName(d, conn, sid, tid, p, v,
            (byte)FileInformationClass.FileNameInformation, mid: 11));
    }

    /// <summary>
    /// The normalized name comes back WITHOUT the leading backslash: the redirector appends it to
    /// <c>\\server\share</c> with its own separator (measured — a leading backslash doubles into
    /// <c>…\share\\dir\file</c> in GetFinalPathNameByHandle's result; the battery asserts the
    /// composed path exactly).
    /// </summary>
    [Fact]
    public void FileNormalizedNameInformation_OnSmb311_ReturnsShareRelativePath()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = Open(d, conn, sid, tid, @"sub\notes.txt", mid: 20);

        Assert.Equal(@"sub\notes.txt", QueryName(d, conn, sid, tid, p, v,
            (byte)FileInformationClass.FileNormalizedNameInformation, mid: 21));
    }

    /// <summary>§3.3.5.20.1: on a dialect below 3.1.1 the class is recognized but unsupported.</summary>
    [Fact]
    public void FileNormalizedNameInformation_OnOlderDialect_IsNotSupported()
    {
        var (d, conn, sid, tid) = Setup(dialect: SmbDialect.Smb302);
        (ulong p, ulong v) = Open(d, conn, sid, tid, @"sub\notes.txt", mid: 30);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryInfoRequest(
            31, sid, tid, p, v, InfoTypeFile,
            fileInfoClass: (byte)FileInformationClass.FileNormalizedNameInformation, outputBufferLength: 65536));

        Assert.Equal(NtStatus.NotSupported, Smb2Header.Read(resp).Status);
    }

    /// <summary>The name section embedded in FileAllInformation must carry the same relative path.</summary>
    [Fact]
    public void FileAllInformation_NameSection_IsShareRelative()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = Open(d, conn, sid, tid, @"sub\notes.txt", mid: 40);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryInfoRequest(
            41, sid, tid, p, v, InfoTypeFile,
            fileInfoClass: (byte)FileInformationClass.FileAllInformation, outputBufferLength: 65536));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);

        byte[] payload = QueryPayload(resp);
        // FileAllInformation: Basic(40) Standard(24) Internal(8) Ea(4) Access(4) Position(8) Mode(4)
        // Alignment(4) → the name section starts at offset 96 (MS-FSCC §2.4.2).
        int nameLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(96, 4));
        string name = Encoding.Unicode.GetString(payload.AsSpan(100, nameLen));
        Assert.Equal(@"\sub\notes.txt", name);
    }

    /// <summary>The share root itself reports "\" (not an empty string, not a leaf).</summary>
    [Fact]
    public void FileNameInformation_OnShareRoot_IsSingleBackslash()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = Open(d, conn, sid, tid, "", mid: 50, options: (uint)CreateOptions.DirectoryFile);

        Assert.Equal(@"\", QueryName(d, conn, sid, tid, p, v,
            (byte)FileInformationClass.FileNameInformation, mid: 51));
    }

    /// <summary>
    /// After a rename over the handle, the normalized name must report the NEW location —
    /// IFileHandle.Path relocates, and Office queries the name right after its temp→final rename.
    /// </summary>
    [Fact]
    public void FileNormalizedNameInformation_AfterRename_ReportsNewPath()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = Open(d, conn, sid, tid, @"sub\notes.txt", mid: 60, access: FullAccess);

        byte[] rename = BuildRenameBuffer(@"sub2\renamed.txt");
        byte[] setResp = d.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            61, sid, tid, p, v, InfoTypeFile,
            fileInfoClass: (byte)FileInformationClass.FileRenameInformation, buffer: rename));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(setResp).Status);

        Assert.Equal(@"sub2\renamed.txt", QueryName(d, conn, sid, tid, p, v,
            (byte)FileInformationClass.FileNormalizedNameInformation, mid: 62));
    }

    /// <summary>
    /// QUERY_INFO FileSystem/FileFsObjectIdInformation (class 8, MS-FSCC §2.5.6) — the volume
    /// object id the shell's link tracking asks for after essentially every attribute open in a
    /// packaged-app flow (measured: six declines per double-click before the flow aborted with
    /// "Datei … kann nicht gefunden werden"). Must answer 64 bytes and be stable across queries.
    /// </summary>
    [Fact]
    public void FileFsObjectIdInformation_IsAnsweredAndStable()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = Open(d, conn, sid, tid, @"sub\notes.txt", mid: 70);

        byte[] first = QueryFs(d, conn, sid, tid, p, v, fsInfoClass: 8, mid: 71);
        byte[] second = QueryFs(d, conn, sid, tid, p, v, fsInfoClass: 8, mid: 72);

        Assert.Equal(64, first.Length);                       // FILE_FS_OBJECTID_INFORMATION
        Assert.Equal(first, second);                          // stable across queries
        Assert.Contains(first.AsSpan(0, 16).ToArray(), b => b != 0); // a real id, not all-zero
    }

    private static byte[] QueryFs(
        Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong p, ulong v, byte fsInfoClass, ulong mid)
    {
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryInfoRequest(
            mid, sid, tid, p, v, infoType: 0x02 /* FILESYSTEM */, fsInfoClass, outputBufferLength: 65536));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        return QueryPayload(resp);
    }

    // ---- helpers --------------------------------------------------------------

    private static string QueryName(
        Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong p, ulong v, byte fileInfoClass, ulong mid)
    {
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryInfoRequest(
            mid, sid, tid, p, v, InfoTypeFile, fileInfoClass, outputBufferLength: 65536));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);

        byte[] payload = QueryPayload(resp);
        int nameLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(0, 4));
        return Encoding.Unicode.GetString(payload.AsSpan(4, nameLen));
    }

    private static byte[] BuildRenameBuffer(string newPath)
    {
        byte[] name = Encoding.Unicode.GetBytes(newPath);
        var buf = new byte[20 + name.Length];
        // ReplaceIfExists = 0, Reserved(7), RootDirectory(8) = 0
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(16, 4), (uint)name.Length);
        name.CopyTo(buf, 20);
        return buf;
    }

    private static byte[] QueryPayload(byte[] resp)
    {
        int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 4, 4));
        return resp.AsSpan(Smb2Header.Size + 8, len).ToArray();
    }

    private static (ulong p, ulong v) Open(
        Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, string name, ulong mid,
        uint options = (uint)CreateOptions.NonDirectoryFile, uint access = FullAccess)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            mid, sid, tid, name, desiredAccess: access,
            disposition: (uint)CreateDisposition.Open, options: options));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8)));
    }

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(SmbDialect dialect = SmbDialect.Smb311)
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

        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();

        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([dialect]));
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
