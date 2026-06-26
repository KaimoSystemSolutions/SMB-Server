using System.Text;
using Smb.Protocol.Enums;

namespace Smb.Crypto;

/// <summary>Ergebnis der SMB-3.x-Schlüsselableitung (Context §8.3).</summary>
public sealed class Smb3SessionKeys
{
    /// <summary>Signing-Key (immer 16 Byte — AES-CMAC/GMAC bzw. HMAC-Key).</summary>
    public required byte[] SigningKey { get; init; }

    /// <summary>Server→Client-Verschlüsselung (Server <b>verschlüsselt</b> hiermit ausgehend).</summary>
    public required byte[] EncryptionKey { get; init; }

    /// <summary>Client→Server-Entschlüsselung (Server <b>entschlüsselt</b> hiermit eingehend).</summary>
    public required byte[] DecryptionKey { get; init; }

    /// <summary>Application-Key (z.B. für RPC over SMB).</summary>
    public required byte[] ApplicationKey { get; init; }
}

/// <summary>
/// SMB-3.x-Schlüsselableitung aus dem GSS-Session-Key (Context §8.3, MS-SMB2 §3.1.4.2),
/// server-seitig. <b>Wichtig:</b> Encrypt/Decrypt-Rollen sind gegenüber dem Client
/// gespiegelt — der Server verschlüsselt mit <c>SMBS2CCipherKey/ServerOut</c> und
/// entschlüsselt mit <c>SMBC2SCipherKey/ServerIn </c> (Leerzeichen vor NUL!).
/// </summary>
public static class Smb3KeyDerivation
{
    // 3.0 / 3.0.2 — NUL-terminierte ASCII-Labels & -Contexts (exakte Byte-Längen laut Context §8.3).
    private static readonly byte[] Label30Signing = Ascii("SMB2AESCMAC");   // 12 inkl. NUL
    private static readonly byte[] Context30Signing = Ascii("SmbSign");     // 8
    private static readonly byte[] Label30App = Ascii("SMB2APP");           // 8
    private static readonly byte[] Context30App = Ascii("SmbRpc");          // 7
    private static readonly byte[] Label30Cipher = Ascii("SMB2AESCCM");     // 11
    private static readonly byte[] Context30ServerOut = Ascii("ServerOut"); // 10
    private static readonly byte[] Context30ServerIn = Ascii("ServerIn ");  // 10 — Leerzeichen vor NUL!

    // 3.1.1 — Labels; Context ist hier immer der Preauth-Integrity-Hash der Session.
    private static readonly byte[] Label311Signing = Ascii("SMBSigningKey"); // 14
    private static readonly byte[] Label311App = Ascii("SMBAppKey");         // 10
    private static readonly byte[] Label311S2C = Ascii("SMBS2CCipherKey");   // 16
    private static readonly byte[] Label311C2S = Ascii("SMBC2SCipherKey");   // 16

    /// <summary>
    /// Leitet alle Session-Keys ab.
    /// </summary>
    /// <param name="dialect">Ausgehandelter Dialekt (muss 3.x sein).</param>
    /// <param name="cipherId">Ausgehandelter Cipher (für Schlüssellänge der Cipher-Keys).</param>
    /// <param name="sessionKey">Die ersten 16 Byte des GSS-Session-Keys (KDK für Signing/App/AES-128).</param>
    /// <param name="fullSessionKey">Voller GSS-Session-Key (KDK für AES-256-Cipher-Keys).</param>
    /// <param name="preauthHash">Preauth-Integrity-Hash der Session (nur 3.1.1; sonst ignoriert).</param>
    public static Smb3SessionKeys Derive(
        SmbDialect dialect,
        SmbCipherId cipherId,
        ReadOnlySpan<byte> sessionKey,
        ReadOnlySpan<byte> fullSessionKey,
        ReadOnlySpan<byte> preauthHash)
    {
        if (!dialect.IsSmb3OrLater())
            throw new ArgumentException("Schlüsselableitung gibt es nur für SMB 3.x.", nameof(dialect));

        bool is311 = dialect == SmbDialect.Smb311;
        bool aes256 = cipherId is SmbCipherId.Aes256Ccm or SmbCipherId.Aes256Gcm;
        int cipherKeyLen = aes256 ? 32 : 16;

        // [AUDIT-2026-06] KDK für ALLE abgeleiteten Keys ist die auf 16 Byte gekürzte SessionKey —
        // auch für AES-256-Cipher-Keys (nur die Output-Länge L wird 256, nicht die KDK-Länge).
        // MS-SMB2 §3.3.5.5.3 setzt Session.SessionKey = erste 16 Byte des GSS-Keys; §3.1.4.2 nutzt
        // genau diese als K1. Früher wurde fälschlich der volle GSS-Key als KDK genommen — bei NTLM
        // (16-Byte-Key) wirkungsgleich, hätte aber Kerberos+AES-256 inkompatibel gemacht.
        // ⚠️ Vor Kerberos-Support gegen eine echte Windows-Interop-Aufzeichnung gegenprüfen.
        // Siehe docs/SECURITY_AUDIT.md (Finding M3). Der Parameter fullSessionKey bleibt für eine
        // etwaige künftige Nutzung in der Signatur, wird aber bewusst nicht mehr als KDK verwendet.
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
            // 3.0 / 3.0.2: feste ASCII-Contexts, immer AES-128 → 16-Byte-Keys.
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

    /// <summary>ASCII-Bytes mit angehängtem NUL-Terminator (Context §8.3 / §23).</summary>
    private static byte[] Ascii(string s)
    {
        var bytes = new byte[s.Length + 1];
        Encoding.ASCII.GetBytes(s, bytes);
        bytes[^1] = 0x00;
        return bytes;
    }
}
