using System.Buffers.Binary;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.Protocol.Enums;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// [REVIEW-2026-07] Robustness of NTLM AUTHENTICATE_MESSAGE parsing: a client-controlled field
/// offset/length that points outside the message must be rejected on the defined "malformed token"
/// path (FormatException → LogonFailure/INVALID_PARAMETER), not by throwing an unhandled
/// <see cref="ArgumentOutOfRangeException"/> out of <see cref="NtlmAuthenticateMessage.Parse"/>.
/// </summary>
public class NtlmParsingRobustnessTests
{
    // AUTHENTICATE_MESSAGE layout (built by NtlmClient): Signature(8)+Type(4), then six 8-byte
    // fields (len2,maxlen2,off4). The NtChallengeResponse field is the second one; its 4-byte
    // BufferOffset sits at 8+4+8 + 4 = 24.
    private const int NtChallengeResponseOffsetPos = 24;

    [Fact]
    public void Parse_FieldOffsetBeyondMessage_ThrowsFormatException()
    {
        byte[] auth = BuildValidAuthenticate(out _);

        // Point the NtChallengeResponse buffer offset far past the end of the message.
        BinaryPrimitives.WriteUInt32LittleEndian(auth.AsSpan(NtChallengeResponseOffsetPos), 0xFFFFFFF0);

        Assert.Throws<FormatException>(() => NtlmAuthenticateMessage.Parse(auth));
    }

    [Fact]
    public void ServerMechanism_MalformedAuthenticate_FailsCleanly_WithoutThrowing()
    {
        (byte[] auth, NtlmServerMechanism mech) = BuildValidAuthenticateWithMechanism();
        BinaryPrimitives.WriteUInt32LittleEndian(auth.AsSpan(NtChallengeResponseOffsetPos), 0xFFFFFFF0);

        // Must map to a status, never propagate an exception out of the mechanism.
        GssResult result = mech.Accept(auth);

        Assert.False(result.IsSuccess);
        Assert.Equal(NtStatus.InvalidParameter, result.Status);
    }

    [Fact]
    public void ServerMechanism_TruncatedAuthenticate_FailsCleanly()
    {
        (byte[] auth, NtlmServerMechanism mech) = BuildValidAuthenticateWithMechanism();
        byte[] truncated = auth[..40]; // cut off inside the fixed header/fields

        GssResult result = mech.Accept(truncated);

        Assert.False(result.IsSuccess);
    }

    private static byte[] BuildValidAuthenticate(out NtlmClient client)
    {
        client = new NtlmClient("DOM", "alice", "pw");
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var mech = new NtlmServerMechanism(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" });
        GssResult negotiate = mech.Accept(client.BuildNegotiate());
        return client.BuildAuthenticate(negotiate.OutToken!);
    }

    private static (byte[] auth, NtlmServerMechanism mech) BuildValidAuthenticateWithMechanism()
    {
        var client = new NtlmClient("DOM", "alice", "pw");
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var mech = new NtlmServerMechanism(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" });
        GssResult negotiate = mech.Accept(client.BuildNegotiate());
        byte[] auth = client.BuildAuthenticate(negotiate.OutToken!);
        return (auth, mech);
    }
}
