using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.Auth.Oids;
using Smb.Crypto;
using Smb.Protocol.Enums;
using Xunit;

namespace Smb.Tests;

public class SpnegoTests
{
    [Fact]
    public void NegTokenInit2_RoundTrips_MechTypes()
    {
        byte[] token = SpnegoTokens.CreateNegTokenInit2([GssOids.KerberosV5, GssOids.Ntlm]);

        SpnegoParseResult parsed = SpnegoTokens.Parse(token);
        Assert.False(parsed.IsResponseToken);
        Assert.Equal(new[] { GssOids.KerberosV5, GssOids.Ntlm }, parsed.MechTypes);
    }

    [Fact]
    public void NegTokenResp_RoundTrips_ResponseToken()
    {
        byte[] responseToken = [0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00]; // "NTLMSSP\0"
        byte[] token = SpnegoTokens.CreateNegTokenResp(
            SpnegoTokens.NegStateAcceptIncomplete, GssOids.Ntlm, responseToken);

        SpnegoParseResult parsed = SpnegoTokens.Parse(token);
        Assert.True(parsed.IsResponseToken);
        Assert.Equal(SpnegoTokens.NegStateAcceptIncomplete, parsed.NegState);
        Assert.Equal(responseToken, parsed.MechToken);
    }

    [Fact]
    public void NegTokenInit2_BeginsWithApplicationTag()
    {
        byte[] token = SpnegoTokens.CreateNegTokenInit2([GssOids.Ntlm]);
        // [APPLICATION 0] constructed = 0x60.
        Assert.Equal(0x60, token[0]);
    }

    [Fact]
    public void Parse_CapturesMechListBytes_MatchingEncodeMechList()
    {
        // The mechListMIC is computed over exactly these bytes, so the parser must surface the on-wire
        // MechTypeList SEQUENCE verbatim — byte-identical to what EncodeMechList produces.
        IReadOnlyList<string> mechs = [GssOids.KerberosV5, GssOids.Ntlm];
        byte[] init = SpnegoTokens.CreateNegTokenInit(mechs, mechToken: [1, 2, 3]);

        SpnegoParseResult parsed = SpnegoTokens.Parse(init);

        Assert.NotNull(parsed.MechListBytes);
        Assert.Equal(SpnegoTokens.EncodeMechList(mechs), parsed.MechListBytes);
        Assert.Equal(0x30, parsed.MechListBytes![0]); // SEQUENCE tag (not the [0] wrapper)
    }

    // ---- B2: SPNEGO mechListMIC enforcement (RFC 4178 §5, downgrade protection) ----------------------

    [Fact]
    public void MechListMic_ValidMic_IsAccepted()
    {
        // Client and server agree on the mechList [NTLM]; the client's MIC over it verifies.
        GssResult result = RunNtlmSpnego(
            enforce: true, onWireMechs: [GssOids.Ntlm], clientSignedMechs: [GssOids.Ntlm]);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void MechListMic_StrippedMechanism_IsRejected()
    {
        // Downgrade (O8): the client really offered [Kerberos, NTLM] and signed that list, but a MITM
        // stripped Kerberos so the server sees only [NTLM]. Verifying the MIC over the received list fails.
        GssResult result = RunNtlmSpnego(
            enforce: true,
            onWireMechs: [GssOids.Ntlm],
            clientSignedMechs: [GssOids.KerberosV5, GssOids.Ntlm]);

        Assert.False(result.IsSuccess);
        Assert.Equal(NtStatus.AccessDenied, result.Status);
    }

    [Fact]
    public void MechListMic_Missing_IsRejected_WhenEnforced()
    {
        // A MITM that also strips the MIC must not slip through when enforcement is on.
        GssResult result = RunNtlmSpnego(
            enforce: true, onWireMechs: [GssOids.Ntlm], clientSignedMechs: null);

        Assert.False(result.IsSuccess);
        Assert.Equal(NtStatus.AccessDenied, result.Status);
    }

    [Fact]
    public void MechListMic_Missing_IsAccepted_WhenNotEnforced()
    {
        // Default (compatibility) mode: no mechListMIC still authenticates — behavior unchanged.
        GssResult result = RunNtlmSpnego(
            enforce: false, onWireMechs: [GssOids.Ntlm], clientSignedMechs: null);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void MechListMic_TamperedMic_IsRejected()
    {
        // A bit-flipped MIC over the correct list is rejected (constant-time compare fails).
        GssResult result = RunNtlmSpnego(
            enforce: true, onWireMechs: [GssOids.Ntlm], clientSignedMechs: [GssOids.Ntlm],
            corruptMic: true);

        Assert.False(result.IsSuccess);
        Assert.Equal(NtStatus.AccessDenied, result.Status);
    }

    /// <summary>
    /// Drives a full NTLM-over-SPNEGO handshake through the negotiator. <paramref name="onWireMechs"/> is
    /// the MechTypeList the server actually receives (what a MITM would have left); when
    /// <paramref name="clientSignedMechs"/> is non-null the client attaches a mechListMIC computed over
    /// <em>that</em> (possibly different) list, simulating a strip when the two differ.
    /// </summary>
    private static GssResult RunNtlmSpnego(bool enforce, IReadOnlyList<string> onWireMechs,
        IReadOnlyList<string>? clientSignedMechs, bool corruptMic = false)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var negotiator = new SpnegoNegotiator(new NtlmMechanismFactory(backend,
            new NtlmServerOptions { NetbiosDomainName = "DOM" }))
        {
            RequireMechListMic = enforce,
        };
        ISpnegoServerContext ctx = negotiator.CreateServerContext();
        var client = new NtlmClient("DOM", "alice", "pw");

        // Leg 1: client NegTokenInit (mechTypes as seen on the wire + optimistic NTLM NEGOTIATE token).
        byte[] init = SpnegoTokens.CreateNegTokenInit(onWireMechs, client.BuildNegotiate());
        GssResult r1 = ctx.Accept(init);
        Assert.True(r1.NeedsMoreProcessing);

        // Extract the wrapped NTLM CHALLENGE and build the AUTHENTICATE.
        byte[] challenge = SpnegoTokens.Parse(r1.OutToken!).MechToken!;
        byte[] authenticate = client.BuildAuthenticate(challenge);

        // Leg 2: client NegTokenResp with the AUTHENTICATE and (optionally) a mechListMIC.
        byte[]? mic = null;
        if (clientSignedMechs is not null)
        {
            byte[] signed = SpnegoTokens.EncodeMechList(clientSignedMechs);
            mic = NtlmCryptography.NtlmMechListMic(client.ExportedSessionKey, client: true, signed);
            if (corruptMic) mic[8] ^= 0xFF;
        }
        byte[] resp = SpnegoTokens.CreateNegTokenResp(
            SpnegoTokens.NegStateAcceptCompleted, responseToken: authenticate, mechListMic: mic);
        return ctx.Accept(resp);
    }
}
