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

    // ---- Authoritative KATs against the .NET framework's CAVP-validated SP800-108 KDF ----
    // System.Security.Cryptography.SP800108HmacCounterKdf implements the exact same construction
    // (PRF(KI, [i]₄ ‖ Label ‖ 0x00 ‖ Context ‖ [L]₄), counter+L 32-bit big-endian). Matching it
    // validates our KDF against an independent, certified oracle — no hand-transcribed test vectors.
    // This closes Finding M3's "no known-answer vector" gap for the KDF math and the SMB label/context
    // wiring; the remaining M3 item is a live Windows capture of the end-to-end handshake.

    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(48)] // > 32 bytes → exercises the multi-iteration counter loop (i = 1, 2)
    public void Kdf_MatchesFrameworkSp800108_KnownAnswer(int outputBytes)
    {
        byte[] kdk = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] label = "SMBSigningKey\0"u8.ToArray();
        byte[] context = Convert.FromHexString("aabbccddeeff00112233445566778899");

        byte[] mine = Sp800108CounterKdf.DeriveKey(kdk, label, context, outputBytes);
        byte[] oracle = SP800108HmacCounterKdf.DeriveBytes(kdk, HashAlgorithmName.SHA256, label, context, outputBytes);

        Assert.Equal(oracle, mine);
    }

    [Fact]
    public void Smb3KeyDerivation_311_MatchesFrameworkOracle_ForEachKey()
    {
        byte[] sessionKey = RandomNumberGenerator.GetBytes(16);
        byte[] preauth = RandomNumberGenerator.GetBytes(64);

        Smb3SessionKeys keys = Smb3KeyDerivation.Derive(
            SmbDialect.Smb311, SmbCipherId.Aes128Gcm, sessionKey, sessionKey, preauth);

        // Exact SMB 3.1.1 labels (MS-SMB2 §3.1.4.2), each carrying its terminating NUL as impacket/Windows do.
        Assert.Equal(Oracle(sessionKey, "SMBSigningKey\0", preauth, 16), keys.SigningKey);
        Assert.Equal(Oracle(sessionKey, "SMBAppKey\0", preauth, 16), keys.ApplicationKey);
        Assert.Equal(Oracle(sessionKey, "SMBS2CCipherKey\0", preauth, 16), keys.EncryptionKey); // server encrypts (S2C)
        Assert.Equal(Oracle(sessionKey, "SMBC2SCipherKey\0", preauth, 16), keys.DecryptionKey); // server decrypts (C2S)
    }

    [Fact]
    public void Smb3KeyDerivation_311Aes256_CipherKeys_MatchFrameworkOracle_At32Bytes()
    {
        byte[] sessionKey = RandomNumberGenerator.GetBytes(16);
        byte[] preauth = RandomNumberGenerator.GetBytes(64);

        Smb3SessionKeys keys = Smb3KeyDerivation.Derive(
            SmbDialect.Smb311, SmbCipherId.Aes256Gcm, sessionKey, RandomNumberGenerator.GetBytes(32), preauth);

        // KDK is the 16-byte session key; only the output length L becomes 256 bits (Finding M3).
        Assert.Equal(Oracle(sessionKey, "SMBS2CCipherKey\0", preauth, 32), keys.EncryptionKey);
        Assert.Equal(Oracle(sessionKey, "SMBC2SCipherKey\0", preauth, 32), keys.DecryptionKey);
        Assert.Equal(Oracle(sessionKey, "SMBSigningKey\0", preauth, 16), keys.SigningKey); // signing stays 16 bytes
    }

    private static byte[] Oracle(byte[] kdk, string label, byte[] context, int bytes)
        => SP800108HmacCounterKdf.DeriveBytes(
            kdk, HashAlgorithmName.SHA256, System.Text.Encoding.ASCII.GetBytes(label), context, bytes);

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
