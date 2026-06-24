using Smb.Auth.Oids;
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
}
