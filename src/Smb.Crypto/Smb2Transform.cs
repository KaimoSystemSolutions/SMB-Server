using System.Security.Cryptography;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;

namespace Smb.Crypto;

/// <summary>
/// Encryption/decryption of complete SMB2 messages via TRANSFORM_HEADER
/// (Context §11, MS-SMB2 §3.1.4.3). AEAD = AES-CCM/GCM (128/256). The server encrypts outgoing
/// data with the EncryptionKey (S→C) and decrypts incoming data with the DecryptionKey (C→S).
/// Encrypted messages are <b>not</b> additionally signed (Context §23).
/// </summary>
public static class Smb2Transform
{
    /// <summary>Nonce length per cipher: GCM 12, CCM 11 bytes (the rest of the 16-byte field stays 0).</summary>
    public static int NonceLength(SmbCipherId cipher) => cipher switch
    {
        SmbCipherId.Aes128Gcm or SmbCipherId.Aes256Gcm => 12,
        SmbCipherId.Aes128Ccm or SmbCipherId.Aes256Ccm => 11,
        _ => throw new ArgumentOutOfRangeException(nameof(cipher)),
    };

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> (a complete SMB2 message) into a transform frame.
    /// <paramref name="nonce"/> must be unique per session/key (GCM/CCM security depends on it!) and
    /// have the correct length for the cipher.
    /// </summary>
    public static byte[] Encrypt(
        SmbCipherId cipher,
        ReadOnlySpan<byte> encryptionKey,
        ulong sessionId,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext)
    {
        int expectedNonce = NonceLength(cipher);
        if (nonce.Length != expectedNonce)
            throw new ArgumentException($"Nonce for {cipher} must be {expectedNonce} bytes.", nameof(nonce));

        var frame = new byte[TransformHeader.Size + plaintext.Length];

        var header = new TransformHeader
        {
            OriginalMessageSize = (uint)plaintext.Length,
            Flags = TransformHeader.FlagEncrypted,
            SessionId = sessionId,
        };
        nonce.CopyTo(header.Nonce); // remaining bytes stay 0
        header.Write(frame);

        Span<byte> aad = frame.AsSpan(TransformHeader.AadOffset, TransformHeader.AadLength);
        Span<byte> ciphertext = frame.AsSpan(TransformHeader.Size, plaintext.Length);
        Span<byte> tag = frame.AsSpan(SignatureFieldOffset, 16);

        EncryptAead(cipher, encryptionKey, nonce, plaintext, ciphertext, tag, aad);
        return frame;
    }

    /// <summary>
    /// Decrypts a transform frame and returns the embedded plaintext SMB2 message.
    /// </summary>
    /// <exception cref="CryptographicException">If the auth tag does not match.</exception>
    public static byte[] Decrypt(
        SmbCipherId cipher,
        ReadOnlySpan<byte> decryptionKey,
        ReadOnlySpan<byte> frame)
    {
        if (frame.Length < TransformHeader.Size)
            throw new ArgumentException("Frame too short for TRANSFORM_HEADER.", nameof(frame));
        if (!SmbProtocolIds.IsTransform(frame))
            throw new ArgumentException("Not a transform frame (ProtocolId ≠ FD 53 4D 42).", nameof(frame));

        var header = TransformHeader.Read(frame);
        int nonceLen = NonceLength(cipher);
        ReadOnlySpan<byte> nonce = header.Nonce.AsSpan(0, nonceLen);

        ReadOnlySpan<byte> aad = frame.Slice(TransformHeader.AadOffset, TransformHeader.AadLength);
        ReadOnlySpan<byte> ciphertext = frame[TransformHeader.Size..];
        ReadOnlySpan<byte> tag = header.Signature;

        var plaintext = new byte[ciphertext.Length];
        DecryptAead(cipher, decryptionKey, nonce, ciphertext, tag, plaintext, aad);

        if (header.OriginalMessageSize != plaintext.Length)
            throw new CryptographicException("OriginalMessageSize does not match the plaintext length.");
        return plaintext;
    }

    private const int SignatureFieldOffset = 4; // after ProtocolId(4)

    private static void EncryptAead(
        SmbCipherId cipher,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> aad)
    {
        switch (cipher)
        {
            case SmbCipherId.Aes128Gcm:
            case SmbCipherId.Aes256Gcm:
                using (var gcm = new AesGcm(key.ToArray(), 16))
                    gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
                break;
            case SmbCipherId.Aes128Ccm:
            case SmbCipherId.Aes256Ccm:
                using (var ccm = new AesCcm(key.ToArray()))
                    ccm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(cipher));
        }
    }

    private static void DecryptAead(
        SmbCipherId cipher,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> aad)
    {
        switch (cipher)
        {
            case SmbCipherId.Aes128Gcm:
            case SmbCipherId.Aes256Gcm:
                using (var gcm = new AesGcm(key.ToArray(), 16))
                    gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                break;
            case SmbCipherId.Aes128Ccm:
            case SmbCipherId.Aes256Ccm:
                using (var ccm = new AesCcm(key.ToArray()))
                    ccm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(cipher));
        }
    }
}
