using System.Security.Cryptography;
using Smb.Crypto;
using Smb.Protocol.Enums;
using Xunit;

namespace Smb.Tests;

public class SigningAndKdfTests
{
    [Fact]
    public void Kdf_IsDeterministic_AndRespectsLength()
    {
        byte[] kdk = RandomNumberGenerator.GetBytes(16);
        byte[] label = "SMBSigningKey\0"u8.ToArray();
        byte[] context = RandomNumberGenerator.GetBytes(64);

        byte[] a = Sp800108CounterKdf.DeriveKey(kdk, label, context, 16);
        byte[] b = Sp800108CounterKdf.DeriveKey(kdk, label, context, 16);
        byte[] c32 = Sp800108CounterKdf.DeriveKey(kdk, label, context, 32);

        Assert.Equal(16, a.Length);
        Assert.Equal(32, c32.Length);
        Assert.Equal(a, b); // deterministisch
        // Hinweis: Die Output-Länge L fließt als [L]₄ in den PRF-Input ein (SP800-108 §5.1),
        // daher unterscheidet sich der 32-Byte-Output bewusst von zwei verketteten 16-Byte-Outputs.
        byte[] a2 = Sp800108CounterKdf.DeriveKey(kdk, label, context, 16);
        Assert.Equal(a, a2);
    }

    [Fact]
    public void Smb3KeyDerivation_311Aes128_ProducesDistinct16ByteKeys()
    {
        byte[] sessionKey = RandomNumberGenerator.GetBytes(16);
        byte[] preauth = RandomNumberGenerator.GetBytes(64);

        Smb3SessionKeys keys = Smb3KeyDerivation.Derive(
            SmbDialect.Smb311, SmbCipherId.Aes128Gcm, sessionKey, sessionKey, preauth);

        Assert.Equal(16, keys.SigningKey.Length);
        Assert.Equal(16, keys.EncryptionKey.Length);
        Assert.Equal(16, keys.DecryptionKey.Length);
        Assert.Equal(16, keys.ApplicationKey.Length);

        // Server-Encrypt (S2C) und -Decrypt (C2S) müssen verschieden sein (Context §8.3, §23).
        Assert.NotEqual(keys.EncryptionKey, keys.DecryptionKey);
        Assert.NotEqual(keys.SigningKey, keys.EncryptionKey);
    }

    [Fact]
    public void Smb3KeyDerivation_311Aes256_DerivesFrom16ByteSessionKey_NotFullKey()
    {
        // [AUDIT-2026-06] KDK für ALLE Keys ist die 16-Byte-SessionKey — auch für AES-256-Cipher-Keys
        // (nur die Output-Länge L wird 256, §3.1.4.2). Beweis: ein ANDERER "voller" GSS-Key darf die
        // abgeleiteten Keys NICHT verändern. Früher wurde fälschlich der volle Key als KDK genutzt →
        // dieser Test würde dann fehlschlagen. Siehe docs/SECURITY_AUDIT.md (Finding M3).
        byte[] sessionKey16 = RandomNumberGenerator.GetBytes(16);
        byte[] preauth = RandomNumberGenerator.GetBytes(64);
        byte[] fullKeyA = RandomNumberGenerator.GetBytes(32);
        byte[] fullKeyB = RandomNumberGenerator.GetBytes(32);

        Smb3SessionKeys a = Smb3KeyDerivation.Derive(SmbDialect.Smb311, SmbCipherId.Aes256Gcm, sessionKey16, fullKeyA, preauth);
        Smb3SessionKeys b = Smb3KeyDerivation.Derive(SmbDialect.Smb311, SmbCipherId.Aes256Gcm, sessionKey16, fullKeyB, preauth);

        Assert.Equal(16, a.SigningKey.Length);    // Signing bleibt AES-128.
        Assert.Equal(32, a.EncryptionKey.Length); // AES-256 → 32-Byte-Output ...
        Assert.Equal(32, a.DecryptionKey.Length);
        Assert.Equal(a.EncryptionKey, b.EncryptionKey); // ... aber unabhängig vom vollen GSS-Key.
        Assert.Equal(a.DecryptionKey, b.DecryptionKey);
    }

    [Fact]
    public void Smb30_DecryptionKeyLabel_HasSpaceBeforeNul()
    {
        // Der "ServerIn "-Context (Leerzeichen vor NUL) muss eine andere DecryptionKey liefern,
        // als wenn fälschlich "ServerIn\0" (ohne Leerzeichen) verwendet würde (Context §23).
        byte[] sessionKey = RandomNumberGenerator.GetBytes(16);
        Smb3SessionKeys keys = Smb3KeyDerivation.Derive(
            SmbDialect.Smb300, SmbCipherId.Aes128Ccm, sessionKey, sessionKey, []);

        byte[] wrongLabel = "SMB2AESCCM\0"u8.ToArray();
        byte[] wrongContext = "ServerIn\0"u8.ToArray(); // ohne Leerzeichen!
        byte[] wrong = Sp800108CounterKdf.DeriveKey(sessionKey, wrongLabel, wrongContext, 16);

        Assert.NotEqual(wrong, keys.DecryptionKey);
    }

    [Theory]
    [InlineData(SmbSigningAlgorithmId.HmacSha256)]
    [InlineData(SmbSigningAlgorithmId.AesCmac)]
    [InlineData(SmbSigningAlgorithmId.AesGmac)]
    public void Signer_SignThenVerify_Succeeds(SmbSigningAlgorithmId alg)
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] message = RandomNumberGenerator.GetBytes(128); // ≥64 (Header) + Body
        ulong messageId = 7;

        Smb2Signer.SignInPlace(alg, key, message, messageId, isServer: true, isCancel: false);
        Assert.True(Smb2Signer.Verify(alg, key, message, messageId, isServer: true, isCancel: false));
    }

    [Theory]
    [InlineData(SmbSigningAlgorithmId.HmacSha256)]
    [InlineData(SmbSigningAlgorithmId.AesCmac)]
    [InlineData(SmbSigningAlgorithmId.AesGmac)]
    public void Signer_DetectsTampering(SmbSigningAlgorithmId alg)
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] message = RandomNumberGenerator.GetBytes(96);
        Smb2Signer.SignInPlace(alg, key, message, 1, isServer: true, isCancel: false);

        message[80] ^= 0xFF; // Body-Byte verfälschen
        Assert.False(Smb2Signer.Verify(alg, key, message, 1, isServer: true, isCancel: false));
    }

    [Fact]
    public void Gmac_ServerAndClientNonces_Differ()
    {
        // Dieselbe Nachricht, aber isServer-Flag unterschiedlich → Signaturen müssen differieren
        // (Nonce-LSB unterscheidet Server von Client, Context §10).
        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] message = RandomNumberGenerator.GetBytes(64);

        byte[] serverSig = Smb2Signer.ComputeSignature(SmbSigningAlgorithmId.AesGmac, key, message, 5, isServer: true, isCancel: false);
        byte[] clientSig = Smb2Signer.ComputeSignature(SmbSigningAlgorithmId.AesGmac, key, message, 5, isServer: false, isCancel: false);
        Assert.NotEqual(serverSig, clientSig);
    }

    [Fact]
    public void ResolveAlgorithm_PerDialect()
    {
        Assert.Equal(SmbSigningAlgorithmId.HmacSha256, Smb2Signer.ResolveAlgorithm(SmbDialect.Smb202, SmbSigningAlgorithmId.AesGmac));
        Assert.Equal(SmbSigningAlgorithmId.HmacSha256, Smb2Signer.ResolveAlgorithm(SmbDialect.Smb210, SmbSigningAlgorithmId.AesGmac));
        Assert.Equal(SmbSigningAlgorithmId.AesCmac, Smb2Signer.ResolveAlgorithm(SmbDialect.Smb300, SmbSigningAlgorithmId.AesGmac));
        Assert.Equal(SmbSigningAlgorithmId.AesGmac, Smb2Signer.ResolveAlgorithm(SmbDialect.Smb311, SmbSigningAlgorithmId.AesGmac));
    }
}
