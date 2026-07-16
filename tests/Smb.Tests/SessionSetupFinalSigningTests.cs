using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.Crypto;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// §3.3.5.5.3: on 3.1.1 the final <c>STATUS_SUCCESS</c> SESSION_SETUP response MUST be signed with the
/// freshly derived <c>Session.SigningKey</c> — <b>regardless of whether either side requires signing</b>.
/// That signature is what binds the preauth-integrity hash to the derived key; the Windows client
/// verifies it even on a session that will never sign another frame, and when it is missing it drops
/// the connection right after a successful authentication (observed: server logs 4624, no TREE_CONNECT
/// follows, <c>net use</c> reports error 1208).
/// <para>
/// This was the sixth instance of the F1 failure family (signing decided away from the choke points):
/// the response was only signed when <see cref="SmbSession.SigningRequired"/> was true, which is false
/// with <see cref="SmbServerOptions.RequireMessageSigning"/> off against a default Windows client
/// (it sends <c>SigningEnabled</c>, not <c>SigningRequired</c>). <c>SignIfRequestWasSigned</c> cannot
/// rescue this path — the final NTLM SESSION_SETUP request itself is unsigned.
/// </para>
/// </summary>
public class SessionSetupFinalSigningTests
{
    private static readonly SmbSigningAlgorithmId Alg = SmbSigningAlgorithmId.AesCmac;

    /// <summary>The bug: signing off ⇒ the final response went out unsigned on 3.1.1.</summary>
    [Fact]
    public void FinalResponse_Smb311_WithoutSigningRequirement_IsSigned()
    {
        var (response, session, finalMid) = RunNtlmHandshake(SmbDialect.Smb311, requireSigning: false);

        Smb2Header header = Smb2Header.Read(response);
        Assert.Equal(NtStatus.Success, header.Status);
        Assert.False(session.SigningRequired); // the premise: nothing *requires* signing here
        Assert.True(header.Flags.HasFlag(Smb2HeaderFlags.Signed),
            "the final 3.1.1 SESSION_SETUP response carries no SMB2_FLAGS_SIGNED — the Windows client " +
            "cannot verify the preauth-integrity binding and drops the connection (net use error 1208).");
        Assert.True(Smb2Signer.Verify(Alg, session.SigningKey, response, finalMid, isServer: true, isCancel: false),
            "the final SESSION_SETUP response is flagged signed but does not verify against Session.SigningKey.");
    }

    /// <summary>Pin: with signing required the final response was and stays signed.</summary>
    [Fact]
    public void FinalResponse_Smb311_WithSigningRequirement_IsSigned()
    {
        var (response, session, finalMid) = RunNtlmHandshake(SmbDialect.Smb311, requireSigning: true);

        Smb2Header header = Smb2Header.Read(response);
        Assert.Equal(NtStatus.Success, header.Status);
        Assert.True(session.SigningRequired);
        Assert.True(header.Flags.HasFlag(Smb2HeaderFlags.Signed));
        Assert.True(Smb2Signer.Verify(Alg, session.SigningKey, response, finalMid, isServer: true, isCancel: false));
    }

    /// <summary>
    /// The mandatory final-response signature is the 3.1.1 preauth-integrity rule, not a blanket one:
    /// a 2.1 session without a signing requirement keeps its unsigned final response (§3.3.5.5.3 makes
    /// the unconditional signature dialect-specific; signing an unrequested 2.x response would change
    /// long-standing wire behaviour for no spec reason).
    /// </summary>
    [Fact]
    public void FinalResponse_Smb21_WithoutSigningRequirement_StaysUnsigned()
    {
        var (response, session, _) = RunNtlmHandshake(SmbDialect.Smb210, requireSigning: false);

        Smb2Header header = Smb2Header.Read(response);
        Assert.Equal(NtStatus.Success, header.Status);
        Assert.False(session.SigningRequired);
        Assert.False(header.Flags.HasFlag(Smb2HeaderFlags.Signed),
            "a 2.1 final SESSION_SETUP response must stay unsigned when signing is not required.");
    }

    /// <summary>
    /// Runs NEGOTIATE + the two-leg NTLM SESSION_SETUP and returns the final (SUCCESS) response bytes,
    /// the established session, and the final request's MessageId (the signature covers it).
    /// </summary>
    private static (byte[] Response, SmbSession Session, ulong FinalMessageId) RunNtlmHandshake(
        SmbDialect dialect, bool requireSigning)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = requireSigning,
        };

        var state = new SmbServerState(options);
        var dispatcher = new Smb2Dispatcher(state);
        var connection = new SmbConnection();

        bool is311 = dialect == SmbDialect.Smb311;
        dispatcher.ProcessMessage(connection, TestHelpers.BuildNegotiateRequest(
            [dialect], SmbSecurityMode.SigningEnabled, signingAlgs: is311 ? [Alg] : null));

        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = dispatcher.ProcessMessage(connection, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        Smb2Header h1 = Smb2Header.Read(r1);
        Assert.Equal(NtStatus.MoreProcessingRequired, h1.Status);

        const ulong finalMid = 2;
        byte[] r2 = dispatcher.ProcessMessage(connection, TestHelpers.BuildSessionSetupRequest(
            finalMid, h1.SessionId, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));

        return (r2, state.SessionGlobalList[h1.SessionId], finalMid);
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }
}
