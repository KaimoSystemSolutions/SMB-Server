using System.Text;
using Smb.Protocol.Enums;

namespace Smb.Crypto;

/// <summary>Result of the SMB 3.x key derivation (Context §8.3).</summary>
public sealed class Smb3SessionKeys
{
    /// <summary>Signing key (always 16 bytes — AES-CMAC/GMAC or HMAC key).</summary>
    public required byte[] SigningKey { get; init; }

    /// <summary>Server→client encryption (the server <b>encrypts</b> outgoing data with this).</summary>
    public required byte[] EncryptionKey { get; init; }

    /// <summary>Client→server decryption (the server <b>decrypts</b> incoming data with this).</summary>
    public required byte[] DecryptionKey { get; init; }

    /// <summary>Application key (e.g. for RPC over SMB).</summary>
    public required byte[] ApplicationKey { get; init; }
}

/// <summary>
/// SMB 3.x key derivation from the GSS session key (Context §8.3, MS-SMB2 §3.1.4.2),
/// server-side. <b>Important:</b> the encrypt/decrypt roles are mirrored relative to the client —
/// the server encrypts with <c>SMBS2CCipherKey/ServerOut</c> and decrypts with
/// <c>SMBC2SCipherKey/ServerIn </c> (note the trailing space before the NUL!).
/// </summary>
public static class Smb3KeyDerivation
{
    // 3.0 / 3.0.2 — NUL-terminated ASCII labels & contexts (exact byte lengths per Context §8.3).
    private static readonly byte[] Label30Signing = Ascii("SMB2AESCMAC");   // 12 incl. NUL
    private static readonly byte[] Context30Signing = Ascii("SmbSign");     // 8
    private static readonly byte[] Label30App = Ascii("SMB2APP");           // 8
    private static readonly byte[] Context30App = Ascii("SmbRpc");          // 7
    private static readonly byte[] Label30Cipher = Ascii("SMB2AESCCM");     // 11
    private static readonly byte[] Context30ServerOut = Ascii("ServerOut"); // 10
    private static readonly byte[] Context30ServerIn = Ascii("ServerIn ");  // 10 — trailing space before NUL!

    // 3.1.1 — labels; the context here is always the session's preauth integrity hash.
    private static readonly byte[] Label311Signing = Ascii("SMBSigningKey"); // 14
    private static readonly byte[] Label311App = Ascii("SMBAppKey");         // 10
    private static readonly byte[] Label311S2C = Ascii("SMBS2CCipherKey");   // 16
    private static readonly byte[] Label311C2S = Ascii("SMBC2SCipherKey");   // 16

    /// <summary>
    /// Derives all session keys.
    /// </summary>
    /// <param name="dialect">Negotiated dialect (must be 3.x).</param>
    /// <param name="cipherId">Negotiated cipher (for the key length of the cipher keys).</param>
    /// <param name="sessionKey">The first 16 bytes of the GSS session key (KDK for signing/app/AES-128).</param>
    /// <param name="fullSessionKey">Full GSS session key (KDK for AES-256 cipher keys).</param>
    /// <param name="preauthHash">The session's preauth integrity hash (3.1.1 only; otherwise ignored).</param>
    public static Smb3SessionKeys Derive(
        SmbDialect dialect,
        SmbCipherId cipherId,
        ReadOnlySpan<byte> sessionKey,
        ReadOnlySpan<byte> fullSessionKey,
        ReadOnlySpan<byte> preauthHash)
    {
        if (!dialect.IsSmb3OrLater())
            throw new ArgumentException("Key derivation only exists for SMB 3.x.", nameof(dialect));

        bool is311 = dialect == SmbDialect.Smb311;
        bool aes256 = cipherId is SmbCipherId.Aes256Ccm or SmbCipherId.Aes256Gcm;
        int cipherKeyLen = aes256 ? 32 : 16;

        // [AUDIT-2026-06] The KDK for ALL derived keys is the SessionKey truncated to 16 bytes —
        // including the AES-256 cipher keys (only the output length L becomes 256, not the KDK length).
        // MS-SMB2 §3.3.5.5.3 sets Session.SessionKey = first 16 bytes of the GSS key; §3.1.4.2 uses
        // exactly that as K1. Previously the full GSS key was wrongly used as the KDK — equivalent for
        // NTLM (16-byte key), but it would have made Kerberos+AES-256 incompatible.
        // ⚠️ Re-verify against a real Windows interop capture before adding Kerberos support.
        // See docs/SECURITY_AUDIT.md (Finding M3). The fullSessionKey parameter is kept in the
        // signature for possible future use, but is deliberately no longer used as the KDK.
        _ = fullSessionKey;
        ReadOnlySpan<byte> cipherKdk = sessionKey;

        byte[] signingKey, encKey, decKey, appKey;

        if (is311)
        {
            signingKey = Sp800108CounterKdf.DeriveKey(sessionKey, Label311Signing, preauthHash, 16);
            appKey = Sp800108CounterKdf.DeriveKey(sessionKey, Label311App, preauthHash, 16);
            encKey = Sp800108CounterKdf.DeriveKey(cipherKdk, Label311S2C, preauthHash, cipherKeyLen);
            decKey = Sp800108CounterKdf.DeriveKey(cipherKdk, Label311C2S, preauthHash, cipherKeyLen);
        }
        else
        {
            // 3.0 / 3.0.2: fixed ASCII contexts, always AES-128 → 16-byte keys.
            signingKey = Sp800108CounterKdf.DeriveKey(sessionKey, Label30Signing, Context30Signing, 16);
            appKey = Sp800108CounterKdf.DeriveKey(sessionKey, Label30App, Context30App, 16);
            encKey = Sp800108CounterKdf.DeriveKey(sessionKey, Label30Cipher, Context30ServerOut, 16);
            decKey = Sp800108CounterKdf.DeriveKey(sessionKey, Label30Cipher, Context30ServerIn, 16);
        }

        return new Smb3SessionKeys
        {
            SigningKey = signingKey,
            EncryptionKey = encKey,
            DecryptionKey = decKey,
            ApplicationKey = appKey,
        };
    }

    /// <summary>ASCII bytes with an appended NUL terminator (Context §8.3 / §23).</summary>
    private static byte[] Ascii(string s)
    {
        var bytes = new byte[s.Length + 1];
        Encoding.ASCII.GetBytes(s, bytes);
        bytes[^1] = 0x00;
        return bytes;
    }
}
