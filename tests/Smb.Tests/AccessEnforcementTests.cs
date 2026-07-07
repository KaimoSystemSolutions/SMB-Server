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
/// Phase 3 / M3.3 — per-file DACL enforcement over the dispatcher: the access granted at CREATE is
/// evaluated against the caller's SIDs, then enforced on READ / WRITE / SET_INFO, and new files inherit
/// their parent directory's inheritable ACEs.
/// </summary>
public class AccessEnforcementTests : IDisposable
{
    private const byte InfoTypeSecurity = 0x03;
    private const uint DaclOnly = 0x4;
    private const uint MaximumAllowed = 0x02000000;
    private const uint ReadWrite = 0x00000003;

    private static readonly Sid AliceSid = Sid.FromString("S-1-5-21-1-2-3-1001");

    private readonly string _shareDir;
    private ulong _mid = 10; // monotonically increasing (the dispatcher enforces the sequence window)

    private ulong NextMid() => _mid++;

    public AccessEnforcementTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbacl_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "doc.txt"), "hello");
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void ReadOnlyDacl_DeniesWriteOpen()
    {
        var (d, conn, sid, tid) = Setup();
        SetAliceReadOnlyDacl(d, conn, sid, tid);

        // Alice may open for read, but a read+write open is denied by the DACL.
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "doc.txt", 0x00000001, out _, out _));
        Assert.Equal(NtStatus.AccessDenied, Open(d, conn, sid, tid, "doc.txt", ReadWrite, out _, out _));
    }

    [Fact]
    public void ReadOnlyDacl_AllowsRead_DeniesWrite_PerOperation()
    {
        var (d, conn, sid, tid) = Setup();
        SetAliceReadOnlyDacl(d, conn, sid, tid);

        // MAXIMUM_ALLOWED resolves to exactly the DACL-permitted rights (read only here).
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "doc.txt", MaximumAllowed, out ulong p, out ulong v));

        byte[] read = d.ProcessMessage(conn, TestHelpers.BuildReadRequest(NextMid(), sid, tid, p, v, length: 5, offset: 0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(read).Status);

        byte[] write = d.ProcessMessage(conn, TestHelpers.BuildWriteRequest(NextMid(), sid, tid, p, v, offset: 0, data: [1, 2, 3]));
        Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(write).Status);
    }

    [Fact]
    public void DenyAce_OverridesAllowAce()
    {
        var (d, conn, sid, tid) = Setup();

        // Canonical order: deny (write) before allow (everyone full) → write is denied, read still allowed.
        var dacl = new Acl
        {
            Aces =
            [
                Ace.Deny(AliceSid, AccessMask.WriteAccess),
                Ace.Allow(WellKnownSids.Everyone, AccessMask.FileAllAccess),
            ],
        };
        SetDacl(d, conn, sid, tid, dacl);

        Assert.Equal(NtStatus.AccessDenied, Open(d, conn, sid, tid, "doc.txt", 0x00000002 /* write */, out _, out _));
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "doc.txt", 0x00000001 /* read */, out _, out _));
    }

    [Fact]
    public void DeleteDisposition_RequiresDeleteAccess()
    {
        var (d, conn, sid, tid) = Setup();

        // Open without DELETE in the granted access → SET_INFO delete-disposition is refused.
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "doc.txt", ReadWrite, out ulong p, out ulong v));
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            NextMid(), sid, tid, p, v, infoType: 0x01 /* File */,
            fileInfoClass: (byte)FileInformationClass.FileDispositionInformation, buffer: [1]));
        Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(resp).Status);

        // With DELETE granted it is accepted.
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "doc.txt", 0x00010000 | ReadWrite, out ulong p2, out ulong v2));
        byte[] ok = d.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            NextMid(), sid, tid, p2, v2, infoType: 0x01,
            fileInfoClass: (byte)FileInformationClass.FileDispositionInformation, buffer: [1]));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(ok).Status);
    }

    [Fact]
    public void NewFile_InheritsParentDirectoryAce()
    {
        var (d, conn, sid, tid) = Setup();

        // Put an inheritable full-control ACE for Alice on the share root.
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "", 0x001F01FF,
            out ulong rp, out ulong rv, options: (uint)CreateOptions.DirectoryFile));
        var rootDacl = new Acl
        {
            Aces = [Ace.Allow(AliceSid, AccessMask.FileAllAccess, AceFlags.ObjectInherit | AceFlags.ContainerInherit)],
        };
        byte[] setRoot = d.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            NextMid(), sid, tid, rp, rv, infoType: InfoTypeSecurity, fileInfoClass: 0,
            buffer: SecurityDescriptor.Create(null, null, rootDacl).ToBytes(), additionalInformation: DaclOnly));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(setRoot).Status);
        Close(d, conn, sid, tid, rp, rv);

        // Create a brand-new file under the root; it must succeed and carry the inherited ACE.
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "fresh.txt", ReadWrite,
            out ulong p, out ulong v, disposition: (uint)CreateDisposition.Create,
            options: (uint)CreateOptions.NonDirectoryFile));

        SecurityDescriptor sd = QuerySecurity(d, conn, sid, tid, p, v);
        Ace inherited = Assert.Single(sd.Dacl!.Aces);
        Assert.Equal(AliceSid, inherited.Sid);
        Assert.Equal(AccessMask.FileAllAccess, inherited.AccessMask);
        Assert.True(inherited.Flags.HasFlag(AceFlags.Inherited));
    }

    // --- helpers ---

    private void SetAliceReadOnlyDacl(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid)
        => SetDacl(d, conn, sid, tid, new Acl { Aces = [Ace.Allow(AliceSid, AccessMask.FileGenericRead)] });

    private void SetDacl(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, Acl dacl)
    {
        Assert.Equal(NtStatus.Success, Open(d, conn, sid, tid, "doc.txt", ReadWrite, out ulong p, out ulong v));
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            NextMid(), sid, tid, p, v, infoType: InfoTypeSecurity, fileInfoClass: 0,
            buffer: SecurityDescriptor.Create(null, null, dacl).ToBytes(), additionalInformation: DaclOnly));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        Close(d, conn, sid, tid, p, v);
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

    private SecurityDescriptor QuerySecurity(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong p, ulong v)
    {
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryInfoRequest(
            NextMid(), sid, tid, p, v, infoType: InfoTypeSecurity, fileInfoClass: 0,
            outputBufferLength: 65536, additionalInformation: DaclOnly));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 4, 4));
        return SecurityDescriptor.Parse(resp.AsSpan(Smb2Header.Size + 8, len));
    }

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw", userSid: AliceSid.ToString());
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
