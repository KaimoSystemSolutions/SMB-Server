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
        Assert.Equal(a, b); // deterministic
        // Note: the output length L flows as [L]₄ into the PRF input (SP800-108 §5.1),
        // so the 32-byte output intentionally differs from two concatenated 16-byte outputs.
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

        // Server-encrypt (S2C) and server-decrypt (C2S) must differ (Context §8.3, §23).
        Assert.NotEqual(keys.EncryptionKey, keys.DecryptionKey);
        Assert.NotEqual(keys.SigningKey, keys.EncryptionKey);
    }

    [Fact]
    public void Smb3KeyDerivation_311Aes256_DerivesFrom16ByteSessionKey_NotFullKey()
    {
        // [AUDIT-2026-06] KDK for ALL keys is the 16-byte SessionKey — even for AES-256 cipher keys
        // (only the output length L becomes 256, §3.1.4.2). Proof: a DIFFERENT "full" GSS key must
        // NOT change the derived keys. Previously the full key was incorrectly used as the KDK →
        // this test would then fail. See docs/SECURITY_AUDIT.md (Finding M3).
        byte[] sessionKey16 = RandomNumberGenerator.GetBytes(16);
        byte[] preauth = RandomNumberGenerator.GetBytes(64);
        byte[] fullKeyA = RandomNumberGenerator.GetBytes(32);
        byte[] fullKeyB = RandomNumberGenerator.GetBytes(32);

        Smb3SessionKeys a = Smb3KeyDerivation.Derive(SmbDialect.Smb311, SmbCipherId.Aes256Gcm, sessionKey16, fullKeyA, preauth);
        Smb3SessionKeys b = Smb3KeyDerivation.Derive(SmbDialect.Smb311, SmbCipherId.Aes256Gcm, sessionKey16, fullKeyB, preauth);

        Assert.Equal(16, a.SigningKey.Length);    // Signing stays AES-128.
        Assert.Equal(32, a.EncryptionKey.Length); // AES-256 → 32-byte output ...
        Assert.Equal(32, a.DecryptionKey.Length);
        Assert.Equal(a.EncryptionKey, b.EncryptionKey); // ... but independent of the full GSS key.
        Assert.Equal(a.DecryptionKey, b.DecryptionKey);
    }

    [Fact]
    public void Smb30_DecryptionKeyLabel_HasSpaceBeforeNul()
    {
        // The "ServerIn " context (space before NUL) must produce a different DecryptionKey
        // than if "ServerIn\0" (without space) were incorrectly used (Context §23).
        byte[] sessionKey = RandomNumberGenerator.GetBytes(16);
        Smb3SessionKeys keys = Smb3KeyDerivation.Derive(
            SmbDialect.Smb300, SmbCipherId.Aes128Ccm, sessionKey, sessionKey, []);

        byte[] wrongLabel = "SMB2AESCCM\0"u8.ToArray();
        byte[] wrongContext = "ServerIn\0"u8.ToArray(); // without space!
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
        byte[] message = RandomNumberGenerator.GetBytes(128); // ≥64 (header) + body
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

        message[80] ^= 0xFF; // corrupt body byte
        Assert.False(Smb2Signer.Verify(alg, key, message, 1, isServer: true, isCancel: false));
    }

    [Fact]
    public void Gmac_ServerAndClientNonces_Differ()
    {
        // Same message but different isServer flag → signatures must differ
        // (nonce LSB distinguishes server from client, Context §10).
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
