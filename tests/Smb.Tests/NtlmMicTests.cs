using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.Protocol.Enums;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 2 / M2.3 — audit item O1: NTLM MIC verification. The MIC binds NEGOTIATE ‖ CHALLENGE ‖
/// AUTHENTICATE under the session key, so tampering with negotiate flags (a downgrade attempt) is
/// detected. Drives <see cref="NtlmServerMechanism"/> directly with <see cref="NtlmClient"/>.
/// </summary>
public class NtlmMicTests
{
    private const int MicOffset = 72;      // AUTHENTICATE_MESSAGE MIC field
    private const int FlagsOffset = 60;    // AUTHENTICATE_MESSAGE NegotiateFlags field

    [Fact]
    public void ValidMic_IsAccepted()
    {
        var (mech, client, challenge) = Handshake();
        byte[] auth = client.BuildAuthenticate(challenge, withMic: true);

        GssResult result = mech.Accept(auth);

        Assert.True(result.IsSuccess);
        Assert.Equal(client.ExportedSessionKey, result.SessionKey);
    }

    [Fact]
    public void TamperedMic_IsRejected()
    {
        var (mech, client, challenge) = Handshake();
        byte[] auth = client.BuildAuthenticate(challenge, withMic: true);
        auth[MicOffset] ^= 0xFF;           // corrupt the MIC

        GssResult result = mech.Accept(auth);

        Assert.False(result.IsSuccess);
        Assert.Equal(NtStatus.LogonFailure, result.Status);
    }

    [Fact]
    public void TamperedNegotiateFlags_AreDetectedByMic()
    {
        var (mech, client, challenge) = Handshake();
        byte[] auth = client.BuildAuthenticate(challenge, withMic: true);
        auth[FlagsOffset] ^= 0x01;         // flip a negotiate flag (downgrade) → MIC no longer matches

        GssResult result = mech.Accept(auth);

        Assert.False(result.IsSuccess);
        Assert.Equal(NtStatus.LogonFailure, result.Status);
    }

    [Fact]
    public void MissingMic_IsAccepted_WhenNotStrict()
    {
        // Default (compatibility) mode: a client that provides no MIC still authenticates.
        var (mech, client, challenge) = Handshake();
        byte[] auth = client.BuildAuthenticate(challenge, withMic: false);

        GssResult result = mech.Accept(auth);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void MissingMic_IsRejected_InStrictMode()
    {
        var (mech, client, challenge) = Handshake(new NtlmServerOptions
        {
            NetbiosDomainName = "DOM",
            RequireMessageIntegrity = true,
        });
        byte[] auth = client.BuildAuthenticate(challenge, withMic: false);

        GssResult result = mech.Accept(auth);

        Assert.False(result.IsSuccess);
        Assert.Equal(NtStatus.LogonFailure, result.Status);
    }

    [Fact]
    public void ValidMic_IsAccepted_InStrictMode()
    {
        var (mech, client, challenge) = Handshake(new NtlmServerOptions
        {
            NetbiosDomainName = "DOM",
            RequireMessageIntegrity = true,
        });
        byte[] auth = client.BuildAuthenticate(challenge, withMic: true);

        Assert.True(mech.Accept(auth).IsSuccess);
    }

    private static (NtlmServerMechanism mech, NtlmClient client, byte[] challenge) Handshake(
        NtlmServerOptions? options = null)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var mech = new NtlmServerMechanism(backend, options ?? new NtlmServerOptions { NetbiosDomainName = "DOM" });
        var client = new NtlmClient("DOM", "alice", "pw");

        GssResult negotiate = mech.Accept(client.BuildNegotiate());
        Assert.True(negotiate.NeedsMoreProcessing);
        return (mech, client, negotiate.OutToken!);
    }
}
