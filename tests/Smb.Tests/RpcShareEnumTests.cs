using System.Buffers.Binary;
using System.Text;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Rpc;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

public class RpcShareEnumTests
{
    // --- DCERPC-Test-PDUs (Client-Seite) ---

    private static byte[] DcerpcHeader(byte ptype, uint callId)
    {
        var h = new byte[16];
        h[0] = 5; h[1] = 0; h[2] = ptype; h[3] = 0x03;
        h[4] = 0x10; // packed_drep
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(12, 4), callId);
        return h;
    }

    private static byte[] BindPdu(uint callId)
    {
        // 16-Byte-Header (ptype=11) + minimaler Body (Server ignoriert den Body).
        var body = new byte[8];
        return TestHelpers.Concat(DcerpcHeader(11, callId), body);
    }

    private static byte[] RequestPdu(uint callId, ushort opnum)
    {
        var body = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(6, 2), opnum); // opnum bei Offset 22
        return TestHelpers.Concat(DcerpcHeader(0, callId), body);
    }

    private static bool Contains(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
            if (haystack.Slice(i, needle.Length).SequenceEqual(needle)) return true;
        return false;
    }

    [Fact]
    public void SrvsvcEndpoint_Bind_ThenNetrShareEnum_ReturnsShares()
    {
        var endpoint = new SrvsvcEndpoint(
        [
            new ShareEntry("Files", SrvsvcEndpoint.StypeDisktree, "Daten"),
            new ShareEntry("IPC$", SrvsvcEndpoint.StypeIpc | SrvsvcEndpoint.StypeSpecial, "Remote IPC"),
        ]);

        byte[] bindAck = endpoint.HandlePdu(BindPdu(1));
        Assert.Equal((byte)DcerpcPduType.BindAck, bindAck[2]);

        byte[] response = endpoint.HandlePdu(RequestPdu(2, 15));
        Assert.Equal((byte)DcerpcPduType.Response, response[2]);

        // NDR-Stub beginnt nach dem 24-Byte-Response-Header: EntriesRead bei Offset 24+12.
        int entriesRead = BinaryPrimitives.ReadInt32LittleEndian(response.AsSpan(24 + 12, 4));
        Assert.Equal(2, entriesRead);
        Assert.True(Contains(response, Encoding.Unicode.GetBytes("Files")));
        Assert.True(Contains(response, Encoding.Unicode.GetBytes("IPC$")));
    }

    [Fact]
    public void EndToEnd_ShareEnumeration_OverIpcPipe_ListsShares()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, Remark = "Daten" });

        var state = new SmbServerState(options);
        var dispatcher = new Smb2Dispatcher(state);
        var conn = new SmbConnection();

        // Login
        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([Smb.Protocol.Enums.SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        byte[] challenge = ReadSecurityBuffer(r1);
        dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(challenge)));

        // TREE_CONNECT \\server\IPC$
        uint treeId = Smb2Header.Read(dispatcher.ProcessMessage(conn,
            TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\server\IPC$"))).TreeId;

        // CREATE \PIPE\srvsvc
        byte[] create = dispatcher.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            4, sessionId, treeId, "srvsvc", desiredAccess: 0x0012019F,
            disposition: (uint)Smb.Protocol.Enums.CreateDisposition.Open, options: 0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        (ulong p, ulong v) = ReadCreateFileId(create);

        // IOCTL FSCTL_PIPE_TRANSCEIVE: Bind
        byte[] bindResp = dispatcher.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            5, sessionId, treeId, p, v, IoctlMessage.FsctlPipeTransceive, BindPdu(1)));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(bindResp).Status);
        Assert.Equal((byte)DcerpcPduType.BindAck, ReadIoctlOutput(bindResp)[2]);

        // IOCTL FSCTL_PIPE_TRANSCEIVE: NetrShareEnum (Opnum 15)
        byte[] enumResp = dispatcher.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            6, sessionId, treeId, p, v, IoctlMessage.FsctlPipeTransceive, RequestPdu(2, 15)));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(enumResp).Status);

        byte[] output = ReadIoctlOutput(enumResp);
        Assert.Equal((byte)DcerpcPduType.Response, output[2]);
        Assert.True(Contains(output, Encoding.Unicode.GetBytes("Files")), "Share 'Files' muss in der Enumeration erscheinen.");
        Assert.True(Contains(output, Encoding.Unicode.GetBytes("IPC$")), "Share 'IPC$' muss in der Enumeration erscheinen.");
    }

    private static byte[] ReadSecurityBuffer(byte[] resp)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(resp.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(resp.AsSpan(body + 6, 2));
        return len == 0 ? [] : resp.AsSpan(off, len).ToArray();
    }

    private static (ulong, ulong) ReadCreateFileId(byte[] resp)
    {
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(resp.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(resp.AsSpan(body + 72, 8)));
    }

    private static byte[] ReadIoctlOutput(byte[] resp)
    {
        const int body = Smb2Header.Size;
        int outCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(body + 36, 4));
        return resp.AsSpan(112, outCount).ToArray(); // OutputOffset = 112
    }
}
