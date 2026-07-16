using Smb.Auth;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

public class NegotiateProcessorTests
{
    private static SmbServerOptions DefaultOptions() => new()
    {
        ServerGuid = new byte[16],
        SpnegoNegotiator = new DevSpnegoNegotiator(),
    };

    [Fact]
    public void SelectDialect_PicksHighestCommon()
    {
        var options = DefaultOptions();
        SmbDialect chosen = NegotiateProcessor.SelectDialect(
            [SmbDialect.Smb202, SmbDialect.Smb210, SmbDialect.Smb300, SmbDialect.Smb311], options);
        Assert.Equal(SmbDialect.Smb311, chosen);
    }

    [Fact]
    public void SelectDialect_RespectsMaxDialectCap()
    {
        var options = DefaultOptions();
        options.MaxDialect = SmbDialect.Smb210;
        SmbDialect chosen = NegotiateProcessor.SelectDialect(
            [SmbDialect.Smb202, SmbDialect.Smb210, SmbDialect.Smb311], options);
        Assert.Equal(SmbDialect.Smb210, chosen);
    }

    [Fact]
    public void SelectDialect_IgnoresWildcard()
    {
        var options = DefaultOptions();
        SmbDialect chosen = NegotiateProcessor.SelectDialect([SmbDialect.Wildcard2FF], options);
        Assert.Equal(SmbDialect.None, chosen);
    }

    [Fact]
    public void BuildResponse_311_NegotiatesCipherBySeverPreference()
    {
        var options = DefaultOptions();
        // Server prefers AES-128-GCM; client offers CCM and GCM.
        var connection = new SmbConnection();
        var request = NegotiateRequest.Parse(
            TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311],
                ciphers: [SmbCipherId.Aes128Ccm, SmbCipherId.Aes128Gcm],
                signingAlgs: [SmbSigningAlgorithmId.AesCmac, SmbSigningAlgorithmId.AesGmac]),
            Smb2Header.Size);

        NegotiateResponse response = NegotiateProcessor.BuildResponse(connection, request, options, []);

        Assert.Equal(SmbDialect.Smb311, connection.Dialect);
        Assert.Equal(SmbCipherId.Aes128Gcm, connection.CipherId);
        Assert.Equal(SmbSigningAlgorithmId.AesGmac, connection.SigningAlgorithmId);

        // Response contains exactly one selected cipher/signing context each.
        EncryptionContext enc = response.NegotiateContexts.OfType<EncryptionContext>().Single();
        Assert.Equal(SmbCipherId.Aes128Gcm, Assert.Single(enc.Ciphers));
        SigningContext sign = response.NegotiateContexts.OfType<SigningContext>().Single();
        Assert.Equal(SmbSigningAlgorithmId.AesGmac, Assert.Single(sign.Algorithms));
    }

    [Fact]
    public void BuildResponse_SetsSigningRequired_WhenPolicyRequires()
    {
        var options = DefaultOptions();
        options.RequireMessageSigning = true;
        var connection = new SmbConnection();
        var request = NegotiateRequest.Parse(
            TestHelpers.BuildNegotiateRequest([SmbDialect.Smb300]), Smb2Header.Size);

        NegotiateResponse response = NegotiateProcessor.BuildResponse(connection, request, options, []);

        Assert.True(response.SecurityMode.HasFlag(SmbSecurityMode.SigningRequired));
        Assert.True(connection.ShouldSign);
    }

    [Fact]
    public void BuildResponse_311_AlwaysIncludesPreauthContext()
    {
        var options = DefaultOptions();
        var connection = new SmbConnection();
        var request = NegotiateRequest.Parse(
            TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]), Smb2Header.Size);

        NegotiateResponse response = NegotiateProcessor.BuildResponse(connection, request, options, []);
        Assert.Single(response.NegotiateContexts.OfType<PreauthIntegrityContext>());
    }
}
