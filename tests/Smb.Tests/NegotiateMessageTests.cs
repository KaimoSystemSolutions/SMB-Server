using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;
using Xunit;

namespace Smb.Tests;

public class NegotiateMessageTests
{
    [Fact]
    public void Request_ParsesDialectsAndContexts()
    {
        byte[] message = TestHelpers.BuildNegotiateRequest(
            [SmbDialect.Smb202, SmbDialect.Smb210, SmbDialect.Smb300, SmbDialect.Smb311],
            ciphers: [SmbCipherId.Aes128Gcm, SmbCipherId.Aes256Gcm],
            signingAlgs: [SmbSigningAlgorithmId.AesGmac, SmbSigningAlgorithmId.AesCmac]);

        NegotiateRequest req = NegotiateRequest.Parse(message, Smb2Header.Size);

        Assert.Equal(4, req.Dialects.Count);
        Assert.Contains(SmbDialect.Smb311, req.Dialects);
        Assert.True(req.OffersSmb311);

        var preauth = Assert.IsType<PreauthIntegrityContext>(req.NegotiateContexts[0]);
        Assert.Contains(PreauthHashAlgorithm.Sha512, preauth.HashAlgorithms);

        EncryptionContext enc = req.NegotiateContexts.OfType<EncryptionContext>().Single();
        Assert.Equal(new[] { SmbCipherId.Aes128Gcm, SmbCipherId.Aes256Gcm }, enc.Ciphers);

        SigningContext sign = req.NegotiateContexts.OfType<SigningContext>().Single();
        Assert.Equal(SmbSigningAlgorithmId.AesGmac, sign.Algorithms[0]);
    }

    [Fact]
    public void Request_WithoutContexts_ParsesPlainDialects()
    {
        byte[] message = TestHelpers.BuildNegotiateRequest([SmbDialect.Smb202, SmbDialect.Smb210]);
        NegotiateRequest req = NegotiateRequest.Parse(message, Smb2Header.Size);
        Assert.Equal(2, req.Dialects.Count);
        Assert.Empty(req.NegotiateContexts);
        Assert.False(req.OffersSmb311);
    }

    [Fact]
    public void Response_StructureSizeIs65_AndContextsAre8ByteAligned()
    {
        var response = new NegotiateResponse
        {
            SecurityMode = SmbSecurityMode.SigningEnabled | SmbSecurityMode.SigningRequired,
            DialectRevision = SmbDialect.Smb311,
            ServerGuid = new byte[16],
            Capabilities = Smb2Capabilities.LargeMtu,
            SecurityBuffer = new byte[] { 1, 2, 3, 4, 5 }, // ungerade Länge → erzwingt Context-Padding
            NegotiateContexts =
            [
                new PreauthIntegrityContext { HashAlgorithms = [PreauthHashAlgorithm.Sha512], Salt = new byte[32] },
                new EncryptionContext { Ciphers = [SmbCipherId.Aes128Gcm] },
            ],
        };

        byte[] body = response.ToBody();
        var r = new SpanReader(body);
        Assert.Equal(65, r.ReadUInt16());                       // StructureSize
        r.Seek(6);
        Assert.Equal(2, r.ReadUInt16());                        // NegotiateContextCount

        // NegotiateContextOffset steht bei Body-Offset 60 (absolut ab Nachrichtenbeginn).
        r.Seek(60);
        uint ctxOffsetAbs = r.ReadUInt32();
        Assert.True(ctxOffsetAbs % 8 == 0, "Context-Liste muss 8-Byte-aligned beginnen.");

        // Vom (absoluten) Offset zurück in den Body rechnen und Contexts lesen.
        int ctxOffsetInBody = (int)ctxOffsetAbs - Smb2Header.Size;
        NegotiateContext first = NegotiateContext.Read(body.AsSpan(ctxOffsetInBody), out int consumed);
        Assert.IsType<PreauthIntegrityContext>(first);

        int secondStart = Align8(ctxOffsetInBody + consumed + Smb2Header.Size) - Smb2Header.Size;
        NegotiateContext second = NegotiateContext.Read(body.AsSpan(secondStart), out _);
        var enc = Assert.IsType<EncryptionContext>(second);
        Assert.Equal(SmbCipherId.Aes128Gcm, enc.Ciphers[0]);
    }

    [Fact]
    public void Context_RoundTrips()
    {
        var ctx = new SigningContext
        {
            Algorithms = [SmbSigningAlgorithmId.AesGmac, SmbSigningAlgorithmId.HmacSha256],
        };
        var w = new GrowableWriter();
        ctx.Write(w);

        NegotiateContext parsed = NegotiateContext.Read(w.ToArray(), out int consumed);
        Assert.Equal(w.Position, consumed);
        var sign = Assert.IsType<SigningContext>(parsed);
        Assert.Equal(ctx.Algorithms, sign.Algorithms);
    }

    private static int Align8(int v) => (v + 7) & ~7;
}
