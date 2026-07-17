using System.Buffers.Binary;
using System.Text;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Authorization;
using Smb.Server.Rpc;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

public class RpcShareEnumTests
{
    // --- DCERPC test PDUs (client side) ---

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
        // 16-byte header (ptype=11) + minimal body (server ignores the body).
        var body = new byte[8];
        return TestHelpers.Concat(DcerpcHeader(11, callId), body);
    }

    private static byte[] RequestPdu(uint callId, ushort opnum, byte[]? stub = null)
    {
        var body = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(6, 2), opnum); // opnum at offset 22
        return TestHelpers.Concat(TestHelpers.Concat(DcerpcHeader(0, callId), body), stub ?? []);
    }

    /// <summary>NetrShareGetInfo request stub: null ServerName, the share name, the info level.</summary>
    private static byte[] ShareGetInfoStub(string netName, uint level)
    {
        byte[] chars = Encoding.Unicode.GetBytes(netName + "\0");
        int padded = (chars.Length + 3) / 4 * 4;
        var stub = new byte[4 + 12 + padded + 4];
        // ServerName referent id = 0 (null unique pointer)
        BinaryPrimitives.WriteUInt32LittleEndian(stub.AsSpan(4, 4), (uint)(chars.Length / 2));  // max_count
        BinaryPrimitives.WriteUInt32LittleEndian(stub.AsSpan(8, 4), 0);                          // offset
        BinaryPrimitives.WriteUInt32LittleEndian(stub.AsSpan(12, 4), (uint)(chars.Length / 2)); // actual_count
        chars.CopyTo(stub, 16);
        BinaryPrimitives.WriteUInt32LittleEndian(stub.AsSpan(16 + padded, 4), level);
        return stub;
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
            new ShareEntry("Files", SrvsvcEndpoint.StypeDisktree, "Data"),
            new ShareEntry("IPC$", SrvsvcEndpoint.StypeIpc | SrvsvcEndpoint.StypeSpecial, "Remote IPC"),
        ]);

        byte[] bindAck = endpoint.HandlePdu(BindPdu(1));
        Assert.Equal((byte)DcerpcPduType.BindAck, bindAck[2]);

        byte[] response = endpoint.HandlePdu(RequestPdu(2, 15));
        Assert.Equal((byte)DcerpcPduType.Response, response[2]);

        // NDR stub begins after the 24-byte response header: EntriesRead at offset 24+12.
        int entriesRead = BinaryPrimitives.ReadInt32LittleEndian(response.AsSpan(24 + 12, 4));
        Assert.Equal(2, entriesRead);
        Assert.True(Contains(response, Encoding.Unicode.GetBytes("Files")));
        Assert.True(Contains(response, Encoding.Unicode.GetBytes("IPC$")));
    }

    /// <summary>
    /// NetrShareGetInfo (Opnum 16) — the call the Windows shell makes while resolving a UNC path
    /// for a packaged app. Answering it with a DCERPC FAULT (the old behaviour for every opnum but
    /// 15) made the Windows 11 Notepad report existing files as "not found" while classic Win32
    /// editors on the same share worked (they never consult srvsvc). Measured 2026-07-16.
    /// </summary>
    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    public void SrvsvcEndpoint_NetrShareGetInfo_ReturnsShare(uint level)
    {
        var endpoint = new SrvsvcEndpoint([new ShareEntry("Files", SrvsvcEndpoint.StypeDisktree, "Data")]);
        endpoint.HandlePdu(BindPdu(1));

        byte[] response = endpoint.HandlePdu(RequestPdu(2, 16, ShareGetInfoStub("Files", level)));

        Assert.Equal((byte)DcerpcPduType.Response, response[2]);
        Assert.True(Contains(response, Encoding.Unicode.GetBytes("Files")));
        uint ret = BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(response.Length - 4, 4));
        Assert.Equal(0u, ret); // ERROR_SUCCESS
    }

    [Fact]
    public void SrvsvcEndpoint_NetrShareGetInfo_UnknownShare_IsNetNameNotFound_NotAFault()
    {
        var endpoint = new SrvsvcEndpoint([new ShareEntry("Files", SrvsvcEndpoint.StypeDisktree, "Data")]);
        endpoint.HandlePdu(BindPdu(1));

        byte[] response = endpoint.HandlePdu(RequestPdu(2, 16, ShareGetInfoStub("Nope", 1)));

        Assert.Equal((byte)DcerpcPduType.Response, response[2]); // a RESPONSE, not a fault
        uint ret = BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(response.Length - 4, 4));
        Assert.Equal(2310u, ret); // NERR_NetNameNotFound
    }

    /// <summary>Levels with server-local details answer like Windows answers non-admins.</summary>
    [Fact]
    public void SrvsvcEndpoint_NetrShareGetInfo_Level2_IsAccessDenied_NotAFault()
    {
        var endpoint = new SrvsvcEndpoint([new ShareEntry("Files", SrvsvcEndpoint.StypeDisktree, "Data")]);
        endpoint.HandlePdu(BindPdu(1));

        byte[] response = endpoint.HandlePdu(RequestPdu(2, 16, ShareGetInfoStub("Files", 2)));

        Assert.Equal((byte)DcerpcPduType.Response, response[2]);
        uint ret = BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(response.Length - 4, 4));
        Assert.Equal(5u, ret); // ERROR_ACCESS_DENIED
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
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, Remark = "Data" });

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
        Assert.True(Contains(output, Encoding.Unicode.GetBytes("Files")), "Share 'Files' must appear in the enumeration.");
        Assert.True(Contains(output, Encoding.Unicode.GetBytes("IPC$")), "Share 'IPC$' must appear in the enumeration.");
    }

    /// <summary>
    /// [W6.2b] Share enumeration consults the authorization policy through the now-async path
    /// (CREATE \PIPE\srvsvc → OpenRpcEndpointAsync → GetVisibleSharesAsync → IShareAccessPolicy.IsVisibleAsync).
    /// A <b>synchronous</b> policy must filter exactly as it did before the async conversion (its async default
    /// simply delegates ⇒ behaviour-neutral); an <b>async</b> (I/O-bound) policy must filter too — the new
    /// capability. Both cases: the hidden share must not appear in the NetrShareEnum response.
    /// </summary>
    [Theory]
    [InlineData(false)] // synchronous policy — proves W6.2b is behaviour-neutral for existing policies
    [InlineData(true)]  // async policy — the newly supported I/O-bound case
    public async Task ShareEnumeration_AppliesPolicy_ThroughAsyncPath(bool asyncPolicy)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
            ShareAccessPolicy = asyncPolicy
                ? new AsyncDelegateSharePolicy(
                    authorizeConnect: _ => new ValueTask<ShareAccessResult>(ShareAccessResult.Grant()),
                    isVisible: async ctx => { await Task.Yield(); return ctx.ShareName != "Secret"; })
                : new DelegateSharePolicy(
                    authorize: _ => ShareAccessResult.Grant(),
                    isVisible: ctx => ctx.ShareName != "Secret"),
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, Remark = "Data" });
        options.Shares.Add(new Share { Name = "Secret", Type = ShareType.Disk, Remark = "Confidential" });

        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();

        await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(ReadSecurityBuffer(r1))));

        uint treeId = Smb2Header.Read(await dispatcher.ProcessMessageAsync(conn,
            TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\server\IPC$"))).TreeId;

        // CREATE \PIPE\srvsvc — this is where the (async) policy snapshot is taken.
        byte[] create = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildCreateRequest(
            4, sessionId, treeId, "srvsvc", desiredAccess: 0x0012019F,
            disposition: (uint)CreateDisposition.Open, options: 0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        (ulong p, ulong v) = ReadCreateFileId(create);

        await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildIoctlRequest(
            5, sessionId, treeId, p, v, IoctlMessage.FsctlPipeTransceive, BindPdu(1)));
        byte[] enumResp = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildIoctlRequest(
            6, sessionId, treeId, p, v, IoctlMessage.FsctlPipeTransceive, RequestPdu(2, 15)));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(enumResp).Status);

        byte[] output = ReadIoctlOutput(enumResp);
        Assert.Equal((byte)DcerpcPduType.Response, output[2]);
        Assert.True(Contains(output, Encoding.Unicode.GetBytes("Files")), "A visible share must be enumerated.");
        Assert.True(Contains(output, Encoding.Unicode.GetBytes("IPC$")), "IPC$ must be enumerated.");
        Assert.False(Contains(output, Encoding.Unicode.GetBytes("Secret")), "A policy-filtered share must not be enumerated.");
    }

    /// <summary>
    /// A named-pipe handle must answer QUERY_INFO, not report the handle closed.
    /// <para>
    /// The Windows client opens <c>\PIPE\srvsvc</c> and then asks it for FileStandardInformation <i>before</i>
    /// sending the DCERPC bind. STATUS_FILE_CLOSED there makes the client abandon the RPC and retry the
    /// CREATE/QUERY_INFO pair a few times, so the symptom surfaces not as a failed query but as
    /// RPC_S_CALL_FAILED (1727) out of <c>net view</c>, and as "the remote procedure call failed" in
    /// Explorer — with the server's shares unlistable.
    /// </para>
    /// <para>
    /// A pipe has no backing file, so every field here is synthesized rather than stat'd; the values asserted
    /// are the ones Windows reports for its own pipes.
    /// </para>
    /// </summary>
    [Fact]
    public async Task PipeHandle_QueryStandardInformation_IsAnsweredNotReportedClosed()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());

        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();

        await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(ReadSecurityBuffer(r1))));

        uint treeId = Smb2Header.Read(await dispatcher.ProcessMessageAsync(conn,
            TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\server\IPC$"))).TreeId;

        byte[] create = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildCreateRequest(
            4, sessionId, treeId, "srvsvc", desiredAccess: 0x0012019F,
            disposition: (uint)CreateDisposition.Open, options: 0));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        (ulong p, ulong v) = ReadCreateFileId(create);

        byte[] resp = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildQueryInfoRequest(
            5, sessionId, treeId, p, v,
            infoType: (byte)InfoType.File,
            fileInfoClass: (byte)FileInformationClass.FileStandardInformation,
            outputBufferLength: 4096));

        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);

        // FILE_STANDARD_INFORMATION (MS-FSCC §2.4.41): a pipe is a zero-length, single-link non-directory.
        ReadOnlySpan<byte> info = ReadQueryInfoOutput(resp);
        Assert.Equal(24, info.Length);
        Assert.Equal(4096, BinaryPrimitives.ReadInt64LittleEndian(info[..8]));       // AllocationSize
        Assert.Equal(0, BinaryPrimitives.ReadInt64LittleEndian(info.Slice(8, 8)));   // EndOfFile
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(info.Slice(16, 4)));// NumberOfLinks
        Assert.Equal(0, info[20]);                                                   // DeletePending
        Assert.Equal(0, info[21]);                                                   // Directory
    }

    /// <summary>
    /// The pipe's synthesized answer covers InfoType FILE only. A class it cannot describe must be declined as
    /// STATUS_INVALID_INFO_CLASS — the handle is open and valid, so STATUS_FILE_CLOSED would be a lie about
    /// the handle rather than about the query, and would send the client into the same retry loop.
    /// </summary>
    [Fact]
    public async Task PipeHandle_QueryUnsupportedInfoClass_IsInvalidInfoClass()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());

        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();

        await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(ReadSecurityBuffer(r1))));

        uint treeId = Smb2Header.Read(await dispatcher.ProcessMessageAsync(conn,
            TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\server\IPC$"))).TreeId;

        byte[] create = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildCreateRequest(
            4, sessionId, treeId, "srvsvc", desiredAccess: 0x0012019F,
            disposition: (uint)CreateDisposition.Open, options: 0));
        (ulong p, ulong v) = ReadCreateFileId(create);

        byte[] resp = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildQueryInfoRequest(
            5, sessionId, treeId, p, v,
            infoType: (byte)InfoType.FileSystem,
            fileInfoClass: (byte)FsInformationClass.FileFsSizeInformation,
            outputBufferLength: 4096));

        Assert.Equal(NtStatus.InvalidInfoClass, Smb2Header.Read(resp).Status);
    }

    /// <summary>
    /// The other two commands whose handle lookup demands a backing file (<c>|| open.LocalOpen is null</c> ⇒
    /// STATUS_FILE_CLOSED) — the shape that broke QUERY_INFO on a pipe. Read on its own that lookup looks like
    /// the same bug waiting to happen, but it is unreachable for a pipe: both handlers resolve the tree's file
    /// store first, and an IPC$ tree has none, so both decline with STATUS_NOT_SUPPORTED before the handle is
    /// ever looked up.
    /// <para>
    /// This pins that reasoning rather than the fix that reasoning made unnecessary. If the store lookup is
    /// ever reordered after the handle lookup, these two start telling clients a live pipe handle is closed —
    /// and this case fails instead of a user finding out.
    /// </para>
    /// </summary>
    [Fact]
    public async Task PipeHandle_SetInfoAndQueryDirectory_AreDeclinedBeforeTheHandleLookup()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());

        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();

        await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(ReadSecurityBuffer(r1))));

        uint treeId = Smb2Header.Read(await dispatcher.ProcessMessageAsync(conn,
            TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\server\IPC$"))).TreeId;

        byte[] create = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildCreateRequest(
            4, sessionId, treeId, "srvsvc", desiredAccess: 0x0012019F,
            disposition: (uint)CreateDisposition.Open, options: 0));
        (ulong p, ulong v) = ReadCreateFileId(create);

        // SET_INFO: a pipe has no size to set — declined for the IPC$ tree, not by calling the handle closed.
        byte[] setInfo = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildSetInfoRequest(
            5, sessionId, treeId, p, v,
            infoType: (byte)InfoType.File,
            fileInfoClass: (byte)FileInformationClass.FileEndOfFileInformation,
            buffer: new byte[8]));
        Assert.Equal(NtStatus.NotSupported, Smb2Header.Read(setInfo).Status);

        // QUERY_DIRECTORY: a pipe is not a directory — same guard, same reason.
        byte[] queryDir = await dispatcher.ProcessMessageAsync(conn, TestHelpers.BuildQueryDirectoryRequest(
            6, sessionId, treeId, p, v,
            infoClass: (byte)FileInformationClass.FileBothDirectoryInformation,
            pattern: "*", outputBufferLength: 4096));
        Assert.Equal(NtStatus.NotSupported, Smb2Header.Read(queryDir).Status);
    }

    private static byte[] ReadQueryInfoOutput(byte[] resp)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(resp.AsSpan(body + 2, 2));
        int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(body + 4, 4));
        return resp.AsSpan(off, len).ToArray();
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
