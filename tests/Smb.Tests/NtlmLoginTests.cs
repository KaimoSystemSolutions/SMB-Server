using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.Protocol.Enums;
using Smb.Server;
using Xunit;

namespace Smb.Tests;

public class NtlmLoginTests
{
    private static (NtlmSpnegoNegotiator neg, InMemoryIdentityBackend backend) Setup()
    {
        var backend = new InMemoryIdentityBackend()
            .AddUser("DOM", "alice", "S3cret!", userSid: "S-1-5-21-1-2-3-1001");
        var neg = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" });
        return (neg, backend);
    }

    private static GssResult RunNtlm(NtlmSpnegoNegotiator neg, NtlmClient client)
    {
        ISpnegoServerContext ctx = neg.CreateServerContext();
        GssResult challenge = ctx.Accept(client.BuildNegotiate());
        Assert.True(challenge.NeedsMoreProcessing);
        Assert.NotNull(challenge.OutToken);
        byte[] authenticate = client.BuildAuthenticate(challenge.OutToken!);
        return ctx.Accept(authenticate);
    }

    [Fact]
    public void CorrectPassword_LogsIn_AndDerivesMatchingSessionKey()
    {
        var (neg, _) = Setup();
        var client = new NtlmClient("DOM", "alice", "S3cret!");

        GssResult result = RunNtlm(neg, client);

        Assert.Equal(NtStatus.Success, result.Status);
        Assert.NotNull(result.Identity);
        Assert.Equal("alice", result.Identity!.UserName);
        // Server hat denselben ExportedSessionKey abgeleitet (RC4-Entschlüsselung) → NTLMv2-Kette korrekt.
        Assert.Equal(client.ExportedSessionKey, result.SessionKey);
    }

    [Fact]
    public void WrongPassword_IsRejected()
    {
        var (neg, _) = Setup();
        var client = new NtlmClient("DOM", "alice", "falsch");

        GssResult result = RunNtlm(neg, client);
        Assert.Equal(NtStatus.LogonFailure, result.Status);
    }

    [Fact]
    public void EmptyDomainFromClient_StillLogsIn_WhenUserRegisteredUnderWorkgroup()
    {
        // User ist unter "WORKGROUP" registriert, der Client meldet sich aber mit leerer Domain an.
        var backend = new InMemoryIdentityBackend().AddUser("WORKGROUP", "demo", "demo123");
        var neg = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "WORKGROUP" });
        var client = new NtlmClient(domain: "", user: "demo", password: "demo123");

        GssResult result = RunNtlm(neg, client);
        Assert.Equal(NtStatus.Success, result.Status);
        Assert.Equal("demo", result.Identity!.UserName);
    }

    [Fact]
    public void UnknownUser_IsRejected()
    {
        var (neg, _) = Setup();
        var client = new NtlmClient("DOM", "mallory", "egal");

        GssResult result = RunNtlm(neg, client);
        Assert.Equal(NtStatus.LogonFailure, result.Status);
    }

    [Fact]
    public void EmptyPassword_ForUserWithRealPassword_IsRejected()
    {
        // 'alice' hat das Passwort "S3cret!"; ein Login mit leerem Passwort muss scheitern.
        var (neg, _) = Setup();
        var client = new NtlmClient("DOM", "alice", "");

        GssResult result = RunNtlm(neg, client);
        Assert.Equal(NtStatus.LogonFailure, result.Status);
    }

    [Fact]
    public void AnonymousNtlm_EmptyNtResponse_IsRejected()
    {
        // Anonyme NTLM-Authentifizierung (leere NT-Response) muss abgelehnt werden.
        var (neg, _) = Setup();
        ISpnegoServerContext ctx = neg.CreateServerContext();
        var client = new NtlmClient("DOM", "alice", "S3cret!");
        GssResult challenge = ctx.Accept(client.BuildNegotiate());

        // AUTHENTICATE mit leerer NtChallengeResponse fälschen.
        byte[] anon = BuildAnonymousAuthenticate();
        GssResult result = ctx.Accept(anon);
        Assert.Equal(NtStatus.LogonFailure, result.Status);
    }

    private static byte[] BuildAnonymousAuthenticate()
    {
        // Minimales AUTHENTICATE_MESSAGE mit allen Längen 0 (anonym).
        var w = new Smb.Protocol.Wire.GrowableWriter(96);
        w.WriteBytes(NtlmConstants.Signature);
        w.WriteUInt32(NtlmConstants.MessageTypeAuthenticate);
        for (int i = 0; i < 6; i++) { w.WriteUInt16(0); w.WriteUInt16(0); w.WriteUInt32(88); } // 6 leere Felder
        w.WriteUInt32(0);            // NegotiateFlags
        w.WriteUInt64(0);            // Version
        w.WriteBytes(new byte[16]);  // MIC
        return w.ToArray();
    }

    [Fact]
    public void FullSessionSetupOverDispatcher_WithRealNtlm_Succeeds()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "bob", "hunter2");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = true,
        };
        options.Shares.Add(Smb.FileSystem.Share.CreateIpc());
        var state = new Smb.Server.State.SmbServerState(options);
        var dispatcher = new Smb.Server.Smb2Dispatcher(state);
        var conn = new Smb.Server.State.SmbConnection();

        // NEGOTIATE
        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest(
            [SmbDialect.Smb311], signingAlgs: [SmbSigningAlgorithmId.AesCmac]));

        var client = new NtlmClient("DOM", "bob", "hunter2");

        // SESSION_SETUP #1 (NTLM NEGOTIATE) → MORE_PROCESSING + CHALLENGE im Security-Buffer
        byte[] r1 = dispatcher.ProcessMessage(conn,
            TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        var h1 = Smb.Protocol.Messages.Smb2Header.Read(r1);
        Assert.Equal(NtStatus.MoreProcessingRequired, h1.Status);
        ulong sessionId = h1.SessionId;
        byte[] challenge = ExtractSecurityBuffer(r1);

        // SESSION_SETUP #2 (NTLM AUTHENTICATE) → SUCCESS
        byte[] r2 = dispatcher.ProcessMessage(conn,
            TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(challenge)));
        var h2 = Smb.Protocol.Messages.Smb2Header.Read(r2);
        Assert.Equal(NtStatus.Success, h2.Status);
        Assert.True(state.SessionGlobalList[sessionId].State == Smb.Server.State.SessionState.Valid);
    }

    // Liest den Security-Buffer aus einer SESSION_SETUP-Response (Offset absolut ab Nachrichtenbeginn).
    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb.Protocol.Messages.Smb2Header.Size;
        int secOffset = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int secLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return secLength == 0 ? [] : response.AsSpan(secOffset, secLength).ToArray();
    }
}
