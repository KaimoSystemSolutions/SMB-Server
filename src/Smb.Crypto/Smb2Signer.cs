using System.Buffers.Binary;
using System.Security.Cryptography;
using Smb.Protocol.Enums;

namespace Smb.Crypto;

/// <summary>
/// SMB2/3-Nachrichtensignierung (Context §10, MS-SMB2 §3.1.4.1). Algorithmus je nach Dialekt:
/// <list type="bullet">
///   <item>2.0.2 / 2.1: HMAC-SHA256 (erste 16 Byte), Key = voller GSS-Session-Key.</item>
///   <item>3.0 / 3.0.2: AES-128-CMAC, Key = abgeleiteter SigningKey.</item>
///   <item>3.1.1: AES-CMAC, AES-GMAC oder HMAC-SHA256 je nach ausgehandeltem Algorithmus.</item>
/// </list>
/// Das 16-Byte-Signaturfeld (Header-Offset 48) wird vor der Berechnung auf 0 gesetzt und
/// danach mit dem Ergebnis überschrieben.
/// </summary>
public static class Smb2Signer
{
    /// <summary>Offset des Signaturfelds im SMB2-Header.</summary>
    public const int SignatureOffset = 48;

    /// <summary>Länge des Signaturfelds.</summary>
    public const int SignatureLength = 16;

    /// <summary>
    /// Bestimmt den effektiven Signing-Algorithmus aus Dialekt und (3.1.1) ausgehandeltem Algorithmus.
    /// </summary>
    public static SmbSigningAlgorithmId ResolveAlgorithm(SmbDialect dialect, SmbSigningAlgorithmId negotiated)
        => dialect switch
        {
            SmbDialect.Smb202 or SmbDialect.Smb210 => SmbSigningAlgorithmId.HmacSha256,
            SmbDialect.Smb300 or SmbDialect.Smb302 => SmbSigningAlgorithmId.AesCmac,
            SmbDialect.Smb311 => negotiated,
            _ => throw new ArgumentOutOfRangeException(nameof(dialect), dialect, "Kein Signing für diesen Dialekt."),
        };

    /// <summary>
    /// Berechnet die 16-Byte-Signatur über die <b>gesamte</b> Nachricht. Das Signaturfeld
    /// in <paramref name="message"/> muss zuvor genullt sein (siehe <see cref="SignInPlace"/>).
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
    /// Signiert die Nachricht in-place: nullt das Signaturfeld, berechnet die Signatur und
    /// schreibt sie zurück. Setzt KEINE Flags — der Aufrufer setzt <c>SMB2_FLAGS_SIGNED</c>.
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
    /// Prüft die Signatur einer eingehenden Nachricht konstanzeit-vergleichend. Lässt
    /// <paramref name="message"/> unverändert (Signaturfeld wird auf einer Kopie genullt).
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

        // Mitgesendete Signatur extrahieren, danach Feld für die Neuberechnung nullen (auf Kopie).
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
    /// AES-GMAC (RFC 4543) = AES-GCM-Tag über leeren Klartext mit der Nachricht als AAD.
    /// 12-Byte-Nonce = MessageId(8, LE) ‖ Flags-DWORD(4, LE), mit LSB=1 (Server) und
    /// Bit 1 = 1 für CANCEL (Context §10).
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
