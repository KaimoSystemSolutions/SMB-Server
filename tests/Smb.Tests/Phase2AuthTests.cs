using Smb.Auth;
using Smb.Auth.Kerberos;
using Smb.Auth.Ntlm;
using Smb.Auth.Oids;
using Smb.Protocol.Enums;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 2 / M2.1 — composable SPNEGO negotiation and the pluggable Kerberos mechanism. Verifies the
/// modular seam: a library user composes <see cref="SpnegoNegotiator"/> from any set of
/// <see cref="IGssMechanismFactory"/> (Kerberos, NTLM, custom), and Kerberos ticket validation is
/// delegated to an injected <see cref="IKerberosTicketValidator"/>.
/// </summary>
public class Phase2AuthTests
{
    private static readonly byte[] FakeApReq = System.Text.Encoding.ASCII.GetBytes("FAKE-AP-REQ");

    private static SecurityIdentity KerberosIdentity => new()
    {
        DomainName = "CORP",
        UserName = "alice",
        UserSid = "S-1-5-21-1-2-3-1001",
        GroupSids = new[] { "S-1-5-21-1-2-3-513" },
    };

    // --- advertising & selection ---

    [Fact]
    public void InitialToken_AdvertisesMechanisms_InServerPreferenceOrder()
    {
        var negotiator = new SpnegoNegotiator(
            new KerberosMechanismFactory(AlwaysValid(KerberosIdentity)),
            new NtlmMechanismFactory(Backend()));

        byte[] init = negotiator.CreateInitialServerToken();
        SpnegoParseResult parsed = SpnegoTokens.Parse(init);

        Assert.Equal(new[] { GssOids.KerberosV5, GssOids.Ntlm }, parsed.MechTypes);
    }

    [Fact]
    public void Kerberos_OptimisticToken_IsValidatedAndSucceeds_InOneLeg()
    {
        byte[] sessionKey = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        var validator = new CountingValidator(_ => KerberosValidationResult.Succeeded(sessionKey, KerberosIdentity));

        var negotiator = new SpnegoNegotiator(
            new KerberosMechanismFactory(validator),
            new NtlmMechanismFactory(Backend()));
        ISpnegoServerContext ctx = negotiator.CreateServerContext();

        byte[] init = SpnegoTokens.CreateNegTokenInit(
            new[] { GssOids.KerberosV5, GssOids.Ntlm }, KerberosGssToken.WrapApReq(FakeApReq));
        GssResult result = ctx.Accept(init);

        Assert.True(result.IsSuccess);
        Assert.Equal(sessionKey, result.SessionKey);
        Assert.Equal("CORP", result.Identity!.DomainName);
        Assert.Equal("S-1-5-21-1-2-3-1001", result.Identity!.UserSid);
        Assert.Equal(1, validator.Calls);
        Assert.Equal(FakeApReq, validator.LastApReq);           // GSS wrapper was stripped before delegation

        // The wrapped success token is a NegTokenResp with accept-completed.
        SpnegoParseResult resp = SpnegoTokens.Parse(result.OutToken!);
        Assert.Equal(SpnegoTokens.NegStateAcceptCompleted, resp.NegState);
    }

    [Fact]
    public void Kerberos_MutualAuth_WrapsApRep_InResponseToken()
    {
        byte[] apRep = System.Text.Encoding.ASCII.GetBytes("FAKE-AP-REP");
        var negotiator = new SpnegoNegotiator(new KerberosMechanismFactory(
            AlwaysValid(KerberosIdentity, sessionKey: new byte[16], apRep: apRep)));
        ISpnegoServerContext ctx = negotiator.CreateServerContext();

        byte[] init = SpnegoTokens.CreateNegTokenInit(
            new[] { GssOids.KerberosV5 }, KerberosGssToken.WrapApReq(FakeApReq));
        GssResult result = ctx.Accept(init);

        Assert.True(result.IsSuccess);
        SpnegoParseResult resp = SpnegoTokens.Parse(result.OutToken!);
        Assert.NotNull(resp.MechToken);                          // responseToken present
        Assert.True(KerberosGssToken.TryReadApReq(resp.MechToken!, out _) == false); // it's an AP-REP, not AP-REQ
    }

    [Fact]
    public void Kerberos_ValidationFailure_IsRejected()
    {
        var negotiator = new SpnegoNegotiator(new KerberosMechanismFactory(
            new CountingValidator(_ => KerberosValidationResult.Failed(NtStatus.LogonFailure))));
        ISpnegoServerContext ctx = negotiator.CreateServerContext();

        byte[] init = SpnegoTokens.CreateNegTokenInit(
            new[] { GssOids.KerberosV5 }, KerberosGssToken.WrapApReq(FakeApReq));
        GssResult result = ctx.Accept(init);

        Assert.False(result.IsSuccess);
        Assert.Equal(NtStatus.LogonFailure, result.Status);
        Assert.Equal(SpnegoTokens.NegStateReject, SpnegoTokens.Parse(result.OutToken!).NegState);
    }

    [Fact]
    public void UnsupportedFirstMech_SelectsFallback_AndRequestsResend()
    {
        // Server offers only NTLM; client leads with Kerberos (unsupported) then NTLM.
        var negotiator = new SpnegoNegotiator(new NtlmMechanismFactory(Backend()));
        ISpnegoServerContext ctx = negotiator.CreateServerContext();

        byte[] init = SpnegoTokens.CreateNegTokenInit(
            new[] { GssOids.KerberosV5, GssOids.Ntlm }, KerberosGssToken.WrapApReq(FakeApReq));
        GssResult result = ctx.Accept(init);

        Assert.True(result.NeedsMoreProcessing);
        SpnegoParseResult resp = SpnegoTokens.Parse(result.OutToken!);
        Assert.Equal(SpnegoTokens.NegStateAcceptIncomplete, resp.NegState);
        Assert.Equal(GssOids.Ntlm, resp.SupportedMech);          // tells the client which mech to resend for
        Assert.Null(resp.MechToken);                             // the optimistic (Kerberos) token was not consumed
    }

    [Fact]
    public void NoMutuallySupportedMech_IsRejected()
    {
        var negotiator = new SpnegoNegotiator(new NtlmMechanismFactory(Backend()));
        ISpnegoServerContext ctx = negotiator.CreateServerContext();

        byte[] init = SpnegoTokens.CreateNegTokenInit(new[] { GssOids.KerberosV5 }, mechToken: null);
        GssResult result = ctx.Accept(init);

        Assert.False(result.IsSuccess);
        Assert.Equal(SpnegoTokens.NegStateReject, SpnegoTokens.Parse(result.OutToken!).NegState);
    }

    [Fact]
    public void NtlmOverSpnego_FullHandshake_Succeeds()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "bob", "secret");
        var negotiator = new SpnegoNegotiator(
            new KerberosMechanismFactory(AlwaysValid(KerberosIdentity)),
            new NtlmMechanismFactory(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }));
        ISpnegoServerContext ctx = negotiator.CreateServerContext();

        var client = new NtlmClient("DOM", "bob", "secret");

        // Round 1: NegTokenInit offering NTLM, optimistic NTLM NEGOTIATE as mechToken.
        byte[] init = SpnegoTokens.CreateNegTokenInit(new[] { GssOids.Ntlm }, client.BuildNegotiate());
        GssResult r1 = ctx.Accept(init);
        Assert.True(r1.NeedsMoreProcessing);
        SpnegoParseResult challenge = SpnegoTokens.Parse(r1.OutToken!);
        Assert.Equal(GssOids.Ntlm, challenge.SupportedMech);

        // Round 2: client answers with the AUTHENTICATE wrapped in a NegTokenResp.
        byte[] authenticate = client.BuildAuthenticate(challenge.MechToken!);
        byte[] respToken = SpnegoTokens.CreateNegTokenResp(
            SpnegoTokens.NegStateAcceptIncomplete, responseToken: authenticate);
        GssResult r2 = ctx.Accept(respToken);

        Assert.True(r2.IsSuccess);
        Assert.Equal(client.ExportedSessionKey, r2.SessionKey);
        Assert.Equal("bob", r2.Identity!.UserName);
    }

    [Fact]
    public void RawNtlmssp_BypassesSpnego_AndStillWorks()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "carol", "pw");
        var negotiator = new SpnegoNegotiator(
            new KerberosMechanismFactory(AlwaysValid(KerberosIdentity)),
            new NtlmMechanismFactory(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }));
        ISpnegoServerContext ctx = negotiator.CreateServerContext();

        var client = new NtlmClient("DOM", "carol", "pw");
        GssResult r1 = ctx.Accept(client.BuildNegotiate());     // raw NTLMSSP, no SPNEGO wrapper
        Assert.True(r1.NeedsMoreProcessing);
        Assert.True(Smb.Auth.Ntlm.NtlmConstants.IsNtlmSsp(r1.OutToken)); // challenge returned unwrapped

        GssResult r2 = ctx.Accept(client.BuildAuthenticate(r1.OutToken));
        Assert.True(r2.IsSuccess);
        Assert.Equal(client.ExportedSessionKey, r2.SessionKey);
    }

    // --- GSS token framing ---

    [Fact]
    public void KerberosGssToken_WrapAndUnwrap_RoundTrips()
    {
        byte[] wrapped = KerberosGssToken.WrapApReq(FakeApReq);
        Assert.True(KerberosGssToken.TryReadApReq(wrapped, out byte[] unwrapped));
        Assert.Equal(FakeApReq, unwrapped);
    }

    [Fact]
    public void KerberosGssToken_RejectsNonKerberosBytes()
    {
        Assert.False(KerberosGssToken.TryReadApReq(new byte[] { 0x01, 0x02, 0x03 }, out _));
        Assert.False(KerberosGssToken.TryReadApReq(FakeApReq, out _)); // bare AP-REQ has no GSS wrapper
    }

    [Fact]
    public void DelegatingValidator_ForwardsToCallback()
    {
        IKerberosTicketValidator v = new DelegatingKerberosTicketValidator(
            apReq => KerberosValidationResult.Succeeded(new byte[16], KerberosIdentity));
        KerberosValidationResult r = v.Validate(FakeApReq);
        Assert.True(r.IsSuccess);
        Assert.Equal("alice", r.Identity!.UserName);
    }

    // --- helpers ---

    private static InMemoryIdentityBackend Backend() => new InMemoryIdentityBackend().AddUser("DOM", "u", "p");

    private static IKerberosTicketValidator AlwaysValid(SecurityIdentity identity, byte[]? sessionKey = null, byte[]? apRep = null)
        => new CountingValidator(_ => KerberosValidationResult.Succeeded(sessionKey ?? new byte[16], identity, apRep));

    /// <summary>Test validator that records how it was called (a span cannot be captured, so copy it out).</summary>
    private sealed class CountingValidator : IKerberosTicketValidator
    {
        private readonly Func<byte[], KerberosValidationResult> _fn;
        public int Calls { get; private set; }
        public byte[] LastApReq { get; private set; } = [];

        public CountingValidator(Func<byte[], KerberosValidationResult> fn) => _fn = fn;

        public KerberosValidationResult Validate(ReadOnlySpan<byte> apReq)
        {
            Calls++;
            LastApReq = apReq.ToArray();
            return _fn(LastApReq);
        }
    }
}
