using Smb.Auth;
using Smb.Crypto;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

public class DispatcherEndToEndTests
{
    private static (Smb2Dispatcher dispatcher, SmbServerState state, SmbConnection conn) NewServer(
        bool requireSigning = false, ISpnegoNegotiator? negotiator = null,
        SmbDialect max = SmbDialect.Smb311)
    {
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = negotiator ?? new DevSpnegoNegotiator(),
            RequireMessageSigning = requireSigning,
            AllowAnonymousAccess = true,
            RejectGuestAccess = true,
            MaxDialect = max,
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Data", Type = ShareType.Disk });

        var state = new SmbServerState(options);
        return (new Smb2Dispatcher(state), state, new SmbConnection());
    }

    [Fact]
    public void Negotiate_SelectsSmb311_AndReportsSuccess()
    {
        var (dispatcher, _, conn) = NewServer();
        byte[] request = TestHelpers.BuildNegotiateRequest(
            [SmbDialect.Smb202, SmbDialect.Smb210, SmbDialect.Smb300, SmbDialect.Smb311],
            ciphers: [SmbCipherId.Aes128Gcm], signingAlgs: [SmbSigningAlgorithmId.AesCmac]);

        byte[] response = dispatcher.ProcessMessage(conn, request);

        Smb2Header header = Smb2Header.Read(response);
        Assert.Equal(NtStatus.Success, header.Status);
        Assert.Equal(SmbCommand.Negotiate, header.Command);
        Assert.True(header.Flags.HasFlag(Smb2HeaderFlags.ServerToRedir));
        Assert.Equal(SmbDialect.Smb311, conn.Dialect);

        // Body StructureSize must be 65.
        Assert.Equal(65, System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(64, 2)));
    }

    [Fact]
    public void FullHandshake_Negotiate_SessionSetup_TreeConnect_Echo()
    {
        var (dispatcher, state, conn) = NewServer();

        // 1) NEGOTIATE
        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest(
            [SmbDialect.Smb311], ciphers: [SmbCipherId.Aes128Gcm]));

        // 2) SESSION_SETUP (Dev-Negotiator accepts in a single step)
        byte[] ssResp = dispatcher.ProcessMessage(conn,
            TestHelpers.BuildSessionSetupRequest(1, 0, [0x01, 0x02, 0x03]));
        Smb2Header ssHeader = Smb2Header.Read(ssResp);
        Assert.Equal(NtStatus.Success, ssHeader.Status);
        Assert.NotEqual(0ul, ssHeader.SessionId);
        ulong sessionId = ssHeader.SessionId;
        Assert.True(state.SessionGlobalList[sessionId].State == SessionState.Valid);

        // 3) TREE_CONNECT zu IPC$
        byte[] tcResp = dispatcher.ProcessMessage(conn,
            TestHelpers.BuildTreeConnectRequest(2, sessionId, @"\\server\IPC$"));
        Smb2Header tcHeader = Smb2Header.Read(tcResp);
        Assert.Equal(NtStatus.Success, tcHeader.Status);
        var tcBody = new Smb.Protocol.Wire.SpanReader(tcResp.AsSpan(64));
        Assert.Equal(16, tcBody.ReadUInt16());                 // TREE_CONNECT Response StructureSize
        Assert.Equal((byte)ShareType.Pipe, tcResp[66]);        // ShareType IPC$ = PIPE

        // 4) ECHO
        byte[] echoResp = dispatcher.ProcessMessage(conn, TestHelpers.BuildEchoRequest(3, sessionId));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(echoResp).Status);
        Assert.Equal(4, System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(echoResp.AsSpan(64, 2)));
    }

    [Fact]
    public void Smb1MultiProtocolNegotiate_AnsweredWithWildcardDialect()
    {
        var (dispatcher, _, conn) = NewServer();

        // Minimales SMB1 SMB_COM_NEGOTIATE-Paket (ProtocolId FF 53 4D 42, Command 0x72).
        var smb1 = new byte[40];
        smb1[0] = 0xFF; smb1[1] = 0x53; smb1[2] = 0x4D; smb1[3] = 0x42;
        smb1[4] = 0x72;

        byte[] response = dispatcher.ProcessMessage(conn, smb1);

        Smb2Header header = Smb2Header.Read(response);
        Assert.Equal(SmbCommand.Negotiate, header.Command);
        Assert.Equal(NtStatus.Success, header.Status);
        // DialectRevision (Body-Offset 4) = 0x02FF (Wildcard).
        Assert.Equal((ushort)SmbDialect.Wildcard2FF,
            System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(64 + 4, 2)));
        // The connection must not be considered "fully negotiated" as a result.
        Assert.False(conn.NegotiateDone);
    }

    [Fact]
    public void Smb1MultiProtocolNegotiate_Smb2002WithoutWildcard_CompletesInSingleRound()
    {
        var (dispatcher, _, conn) = NewServer();

        // pysmb-style SMB1 SMB_COM_NEGOTIATE: offers NT LM 0.12 + the concrete SMB 2.002 dialect,
        // but NOT the "SMB 2.???" wildcard. Per MS-SMB2 §3.3.5.3.1 this completes in a single round —
        // the server must answer with dialect 0x0202 AND finalise the connection state.
        byte[] smb1 = BuildSmb1Negotiate("NT LM 0.12", "SMB 2.002");

        byte[] negResp = dispatcher.ProcessMessage(conn, smb1);
        Smb2Header negHeader = Smb2Header.Read(negResp);
        Assert.Equal(SmbCommand.Negotiate, negHeader.Command);
        Assert.Equal(NtStatus.Success, negHeader.Status);
        Assert.Equal((ushort)SmbDialect.Smb202,
            System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(negResp.AsSpan(64 + 4, 2)));
        Assert.True(conn.NegotiateDone);
        Assert.Equal(SmbDialect.Smb202, conn.Dialect);

        // The next message (SESSION_SETUP, MessageId 1) must now be accepted instead of being
        // rejected with STATUS_INVALID_PARAMETER (the pre-fix behaviour that broke pysmb).
        byte[] ssResp = dispatcher.ProcessMessage(conn,
            TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
        Assert.NotEqual(NtStatus.InvalidParameter, Smb2Header.Read(ssResp).Status);
    }

    [Fact]
    public void Smb1MultiProtocolNegotiate_WithWildcard_StaysTwoStage()
    {
        var (dispatcher, _, conn) = NewServer();

        // A client offering both the concrete 2.002 AND the wildcard is prepared for the two-stage
        // upgrade → answer with the wildcard and leave the connection un-negotiated.
        byte[] smb1 = BuildSmb1Negotiate("NT LM 0.12", "SMB 2.002", "SMB 2.???");

        byte[] resp = dispatcher.ProcessMessage(conn, smb1);
        Assert.Equal((ushort)SmbDialect.Wildcard2FF,
            System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(resp.AsSpan(64 + 4, 2)));
        Assert.False(conn.NegotiateDone);
    }

    /// <summary>Builds a minimal SMB1 SMB_COM_NEGOTIATE offering the given dialect strings.</summary>
    private static byte[] BuildSmb1Negotiate(params string[] dialects)
    {
        var body = new List<byte>();
        foreach (string d in dialects)
        {
            body.Add(0x02); // BufferFormat marker
            body.AddRange(System.Text.Encoding.ASCII.GetBytes(d));
            body.Add(0x00); // null terminator
        }

        var msg = new byte[32 + 1 + 2 + body.Count];
        msg[0] = 0xFF; msg[1] = 0x53; msg[2] = 0x4D; msg[3] = 0x42; // \xFFSMB
        msg[4] = 0x72;                                              // SMB_COM_NEGOTIATE
        msg[32] = 0x00;                                             // WordCount
        msg[33] = (byte)(body.Count & 0xFF);                       // ByteCount (LE)
        msg[34] = (byte)((body.Count >> 8) & 0xFF);
        body.CopyTo(msg, 35);
        return msg;
    }

    [Fact]
    public void TreeConnect_UnknownShare_ReturnsBadNetworkName()
    {
        var (dispatcher, _, conn) = NewServer();
        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        Smb2Header ss = Smb2Header.Read(dispatcher.ProcessMessage(conn,
            TestHelpers.BuildSessionSetupRequest(1, 0, [0x01])));

        byte[] resp = dispatcher.ProcessMessage(conn,
            TestHelpers.BuildTreeConnectRequest(2, ss.SessionId, @"\\server\DoesNotExist"));
        Assert.Equal(NtStatus.BadNetworkName, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void UnsupportedCommand_ReturnsNotSupported()
    {
        var (dispatcher, _, conn) = NewServer();
        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));

        // An unknown/reserved command code (all defined SmbCommands are now implemented)
        // hits the dispatcher's default arm → STATUS_NOT_SUPPORTED.
        byte[] req = TestHelpers.Concat(
            TestHelpers.BuildHeader((SmbCommand)0x00FF, 1, sessionId: 0),
            new byte[4]);
        byte[] resp = dispatcher.ProcessMessage(conn, req);
        Assert.Equal(NtStatus.NotSupported, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void SigningRequired_FinalSessionSetupResponse_IsSignedAndVerifiable()
    {
        byte[] sessionKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        var identity = new SecurityIdentity { DomainName = "DOM", UserName = "alice" };
        var negotiator = new DevSpnegoNegotiator(sessionKey, identity);

        var (dispatcher, state, conn) = NewServer(requireSigning: true, negotiator: negotiator);

        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest(
            [SmbDialect.Smb311], signingAlgs: [SmbSigningAlgorithmId.AesCmac]));

        byte[] ssResp = dispatcher.ProcessMessage(conn,
            TestHelpers.BuildSessionSetupRequest(1, 0, [0xAA, 0xBB]));
        Smb2Header ssHeader = Smb2Header.Read(ssResp);
        Assert.Equal(NtStatus.Success, ssHeader.Status);
        Assert.True(ssHeader.Flags.HasFlag(Smb2HeaderFlags.Signed));

        SmbSession session = state.SessionGlobalList[ssHeader.SessionId];
        Assert.True(session.SigningRequired);

        SmbSigningAlgorithmId alg = Smb2Signer.ResolveAlgorithm(conn.Dialect, conn.SigningAlgorithmId);
        bool ok = Smb2Signer.Verify(alg, session.SigningKey, ssResp, ssHeader.MessageId, isServer: true, isCancel: false);
        Assert.True(ok, "The signed SESSION_SETUP response must be verifiable with the SigningKey.");
    }

    [Fact]
    public void SigningRequired_SignedEchoAccepted_UnsignedRejected()
    {
        byte[] sessionKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        var identity = new SecurityIdentity { DomainName = "DOM", UserName = "bob" };
        var negotiator = new DevSpnegoNegotiator(sessionKey, identity);

        var (dispatcher, state, conn) = NewServer(requireSigning: true, negotiator: negotiator);
        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest(
            [SmbDialect.Smb311], signingAlgs: [SmbSigningAlgorithmId.AesCmac]));
        Smb2Header ss = Smb2Header.Read(dispatcher.ProcessMessage(conn,
            TestHelpers.BuildSessionSetupRequest(1, 0, [0x01])));

        SmbSession session = state.SessionGlobalList[ss.SessionId];
        SmbSigningAlgorithmId alg = Smb2Signer.ResolveAlgorithm(conn.Dialect, conn.SigningAlgorithmId);

        // Signed ECHO → accepted.
        byte[] signedEcho = TestHelpers.BuildEchoRequest(2, ss.SessionId, session.SigningKey, alg);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(dispatcher.ProcessMessage(conn, signedEcho)).Status);

        // Unsigned ECHO when signing is required → ACCESS_DENIED.
        byte[] unsignedEcho = TestHelpers.BuildEchoRequest(3, ss.SessionId);
        Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(dispatcher.ProcessMessage(conn, unsignedEcho)).Status);
    }

    [Fact]
    public void GuestAccess_RejectedByDefaultPolicy()
    {
        var guestIdentity = new SecurityIdentity { DomainName = "DOM", UserName = "guest", IsGuest = true };
        var negotiator = new DevSpnegoNegotiator(new byte[16], guestIdentity);
        var (dispatcher, _, conn) = NewServer(negotiator: negotiator);

        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        byte[] resp = dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
        Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(resp).Status);
    }
}
