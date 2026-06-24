using System.Security.Cryptography;
using Smb.Crypto;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Xunit;

namespace Smb.Tests;

public class TransformAndPreauthTests
{
    [Theory]
    [InlineData(SmbCipherId.Aes128Gcm, 16)]
    [InlineData(SmbCipherId.Aes256Gcm, 32)]
    [InlineData(SmbCipherId.Aes128Ccm, 16)]
    [InlineData(SmbCipherId.Aes256Ccm, 32)]
    public void Transform_EncryptDecrypt_RoundTrips(SmbCipherId cipher, int keyLen)
    {
        byte[] key = RandomNumberGenerator.GetBytes(keyLen);
        byte[] plaintext = RandomNumberGenerator.GetBytes(200);
        ulong sessionId = 0xDEADBEEF;
        byte[] nonce = RandomNumberGenerator.GetBytes(Smb2Transform.NonceLength(cipher));

        byte[] frame = Smb2Transform.Encrypt(cipher, key, sessionId, nonce, plaintext);

        // Frame beginnt mit Transform-ProtocolId und ist um den Header länger.
        Assert.True(SmbProtocolIds.IsTransform(frame));
        Assert.Equal(TransformHeader.Size + plaintext.Length, frame.Length);

        byte[] decrypted = Smb2Transform.Decrypt(cipher, key, frame);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Transform_TamperedCiphertext_FailsAuthentication()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] plaintext = RandomNumberGenerator.GetBytes(64);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] frame = Smb2Transform.Encrypt(SmbCipherId.Aes128Gcm, key, 1, nonce, plaintext);

        frame[^1] ^= 0xFF; // letztes Ciphertext-Byte verfälschen
        // AesGcm wirft AuthenticationTagMismatchException (abgeleitet von CryptographicException).
        Assert.ThrowsAny<CryptographicException>(() => Smb2Transform.Decrypt(SmbCipherId.Aes128Gcm, key, frame));
    }

    [Fact]
    public void TransformHeader_RoundTrips()
    {
        var header = new TransformHeader
        {
            Nonce = RandomNumberGenerator.GetBytes(16),
            Signature = RandomNumberGenerator.GetBytes(16),
            OriginalMessageSize = 123,
            SessionId = 0x1122334455667788,
        };
        var buf = new byte[TransformHeader.Size];
        header.Write(buf);

        TransformHeader parsed = TransformHeader.Read(buf);
        Assert.Equal(123u, parsed.OriginalMessageSize);
        Assert.Equal(0x1122334455667788ul, parsed.SessionId);
        Assert.Equal(header.Nonce, parsed.Nonce);
    }

    [Fact]
    public void PreauthHash_MatchesIndependentSha512Chain()
    {
        var msg1 = RandomNumberGenerator.GetBytes(50);
        var msg2 = RandomNumberGenerator.GetBytes(70);

        var hash = new PreauthIntegrityHash();
        hash.Append(msg1);
        hash.Append(msg2);

        // Unabhängige Referenzberechnung: H=0; H=SHA512(H‖m1); H=SHA512(H‖m2).
        byte[] h = new byte[64];
        h = SHA512.HashData(Concat(h, msg1));
        h = SHA512.HashData(Concat(h, msg2));

        Assert.Equal(h, hash.Value);
    }

    [Fact]
    public void PreauthHash_Clone_IsIndependent()
    {
        var hash = new PreauthIntegrityHash();
        hash.Append(new byte[] { 1, 2, 3 });

        PreauthIntegrityHash clone = hash.Clone();
        clone.Append(new byte[] { 4, 5, 6 });

        Assert.NotEqual(hash.Value, clone.Value); // Clone-Änderung darf Original nicht beeinflussen.
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0);
        b.CopyTo(r, a.Length);
        return r;
    }
}
