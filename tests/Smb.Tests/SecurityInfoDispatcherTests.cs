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
/// Phase 3 / M3.2 — QUERY_INFO / SET_INFO with InfoType Security over the dispatcher: read the
/// descriptor of an open handle, replace its DACL, and read it back.
/// </summary>
public class SecurityInfoDispatcherTests : IDisposable
{
    private readonly string _shareDir;
    private const byte InfoTypeSecurity = 0x03;
    private const uint OwnerGroupDacl = 0x1 | 0x2 | 0x4;
    private const uint DaclOnly = 0x4;
    private const uint FullControl = 0x001F01FF;

    public SecurityInfoDispatcherTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbsec_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "doc.txt"), "hello");
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void QuerySecurity_ReturnsDefaultDescriptor()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = OpenDoc(d, conn, sid, tid);

        SecurityDescriptor sd = QuerySecurity(d, conn, sid, tid, p, v, OwnerGroupDacl, mid: 11);

        Assert.Equal(WellKnownSids.LocalSystem, sd.Owner);
        Assert.NotNull(sd.Dacl);
        Assert.Single(sd.Dacl!.Aces);
        Assert.Equal(WellKnownSids.Everyone, sd.Dacl.Aces[0].Sid);       // default: everyone full control
        Assert.Equal(FullControl, sd.Dacl.Aces[0].AccessMask);
    }

    [Fact]
    public void SetSecurity_ReplacesDacl_AndPersists()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = OpenDoc(d, conn, sid, tid);

        // New DACL: only BUILTIN\Administrators, full control.
        var newDacl = new Acl { Aces = [Ace.Allow(WellKnownSids.BuiltinAdministrators, FullControl)] };
        SecurityDescriptor toSet = SecurityDescriptor.Create(null, null, newDacl);

        byte[] setResp = d.ProcessMessage(conn, TestHelpers.BuildSetInfoRequest(
            11, sid, tid, p, v, infoType: InfoTypeSecurity, fileInfoClass: 0, buffer: toSet.ToBytes(),
            additionalInformation: DaclOnly));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(setResp).Status);

        // Read back: DACL replaced, owner/group preserved from the default descriptor.
        SecurityDescriptor after = QuerySecurity(d, conn, sid, tid, p, v, OwnerGroupDacl, mid: 12);
        Assert.Single(after.Dacl!.Aces);
        Assert.Equal(WellKnownSids.BuiltinAdministrators, after.Dacl.Aces[0].Sid);
        Assert.Equal(WellKnownSids.LocalSystem, after.Owner);            // untouched by a DACL-only set
    }

    [Fact]
    public void QuerySecurity_BufferTooSmall_IsReported()
    {
        var (d, conn, sid, tid) = Setup();
        (ulong p, ulong v) = OpenDoc(d, conn, sid, tid);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryInfoRequest(
            11, sid, tid, p, v, infoType: InfoTypeSecurity, fileInfoClass: 0,
            outputBufferLength: 8, additionalInformation: OwnerGroupDacl)); // far too small

        Assert.Equal(NtStatus.BufferTooSmall, Smb2Header.Read(resp).Status);
    }

    // --- helpers ---

    private static SecurityDescriptor QuerySecurity(
        Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong p, ulong v, uint which, ulong mid)
    {
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildQueryInfoRequest(
            mid, sid, tid, p, v, infoType: InfoTypeSecurity, fileInfoClass: 0,
            outputBufferLength: 65536, additionalInformation: which));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);

        int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 4, 4));
        return SecurityDescriptor.Parse(resp.AsSpan(Smb2Header.Size + 8, len));
    }

    private static (ulong p, ulong v) OpenDoc(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            10, sid, tid, "doc.txt", desiredAccess: 0x00000003,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8)));
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
