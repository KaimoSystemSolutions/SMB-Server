using System.Buffers.Binary;
using System.Security.Cryptography;
using Smb.Protocol.Enums;

namespace Smb.Crypto;

/// <summary>
/// SMB2/3 message signing (Context §10, MS-SMB2 §3.1.4.1). Algorithm depends on the dialect:
/// <list type="bullet">
///   <item>2.0.2 / 2.1: HMAC-SHA256 (first 16 bytes), key = full GSS session key.</item>
///   <item>3.0 / 3.0.2: AES-128-CMAC, key = derived SigningKey.</item>
///   <item>3.1.1: AES-CMAC, AES-GMAC or HMAC-SHA256 depending on the negotiated algorithm.</item>
/// </list>
/// The 16-byte signature field (header offset 48) is zeroed before the computation and then
/// overwritten with the result.
/// </summary>
public static class Smb2Signer
{
    /// <summary>Offset of the signature field in the SMB2 header.</summary>
    public const int SignatureOffset = 48;

    /// <summary>Length of the signature field.</summary>
    public const int SignatureLength = 16;

    /// <summary>
    /// Determines the effective signing algorithm from the dialect and (3.1.1) the negotiated algorithm.
    /// </summary>
    public static SmbSigningAlgorithmId ResolveAlgorithm(SmbDialect dialect, SmbSigningAlgorithmId negotiated)
        => dialect switch
        {
            SmbDialect.Smb202 or SmbDialect.Smb210 => SmbSigningAlgorithmId.HmacSha256,
            SmbDialect.Smb300 or SmbDialect.Smb302 => SmbSigningAlgorithmId.AesCmac,
            SmbDialect.Smb311 => negotiated,
            _ => throw new ArgumentOutOfRangeException(nameof(dialect), dialect, "No signing for this dialect."),
        };

    /// <summary>
    /// Computes the 16-byte signature over the <b>entire</b> message. The signature field in
    /// <paramref name="message"/> must be zeroed beforehand (see <see cref="SignInPlace"/>).
    /// </summary>
    public static byte[] ComputeSignature(
        SmbSigningAlgorithmId algorithm,
        ReadOnlySpan<byte> signingKey,
        ReadOnlySpan<byte> message,
        ulong messageId,
        bool isServer,
        bool isCancel)
    {
        return algorithm switch
        {
            SmbSigningAlgorithmId.HmacSha256 => HmacSha256First16(signingKey, message),
            SmbSigningAlgorithmId.AesCmac => AesCmac.Compute(signingKey, message),
            SmbSigningAlgorithmId.AesGmac => AesGmac(signingKey, message, messageId, isServer, isCancel),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        };
    }

    /// <summary>
    /// Signs the message in place: zeroes the signature field, computes the signature and writes it
    /// back. Sets NO flags — the caller sets <c>SMB2_FLAGS_SIGNED</c>.
    /// </summary>
    public static void SignInPlace(
        SmbSigningAlgorithmId algorithm,
        ReadOnlySpan<byte> signingKey,
        Span<byte> message,
        ulong messageId,
        bool isServer,
        bool isCancel)
    {
        message.Slice(SignatureOffset, SignatureLength).Clear();
        byte[] sig = ComputeSignature(algorithm, signingKey, message, messageId, isServer, isCancel);
        sig.AsSpan(0, SignatureLength).CopyTo(message.Slice(SignatureOffset, SignatureLength));
    }

    /// <summary>
    /// Verifies the signature of an incoming message with a constant-time comparison. Leaves
    /// <paramref name="message"/> unchanged (the signature field is zeroed on a copy).
    /// </summary>
    public static bool Verify(
        SmbSigningAlgorithmId algorithm,
        ReadOnlySpan<byte> signingKey,
        ReadOnlySpan<byte> message,
        ulong messageId,
        bool isServer,
        bool isCancel)
    {
        if (message.Length < SignatureOffset + SignatureLength) return false;

        // Extract the signature that was sent, then zero the field for recomputation (on a copy).
        Span<byte> received = stackalloc byte[SignatureLength];
        message.Slice(SignatureOffset, SignatureLength).CopyTo(received);

        byte[] copy = message.ToArray();
        copy.AsSpan(SignatureOffset, SignatureLength).Clear();

        byte[] expected = ComputeSignature(algorithm, signingKey, copy, messageId, isServer, isCancel);
        return CryptographicOperations.FixedTimeEquals(received, expected.AsSpan(0, SignatureLength));
    }

    private static byte[] HmacSha256First16(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        Span<byte> full = stackalloc byte[32];
        using var hmac = new HMACSHA256(key.ToArray());
        hmac.TryComputeHash(message, full, out _);
        return full[..SignatureLength].ToArray();
    }

    /// <summary>
    /// AES-GMAC (RFC 4543) = AES-GCM tag over empty plaintext with the message as AAD.
    /// 12-byte nonce = MessageId(8, LE) ‖ flags DWORD(4, LE), with LSB=1 (server) and
    /// bit 1 = 1 for CANCEL (Context §10).
    /// </summary>
    private static byte[] AesGmac(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> message,
        ulong messageId,
        bool isServer,
        bool isCancel)
    {
        Span<byte> nonce = stackalloc byte[12];
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[..8], messageId);
        uint flags = 0;
        if (isServer) flags |= 0x1;
        if (isCancel) flags |= 0x2;
        BinaryPrimitives.WriteUInt32LittleEndian(nonce[8..], flags);

        var tag = new byte[SignatureLength];
        using var gcm = new AesGcm(key.ToArray(), SignatureLength);
        gcm.Encrypt(nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, message);
        return tag;
    }
}
