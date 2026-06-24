using System.Security.Cryptography;
using System.Text;

namespace Smb.Crypto;

/// <summary>
/// NTLMv2-Kernberechnungen (Context §9.3, MS-NLMP §3.3.2). Nur NTLMv2/v2 — NTLMv1/LM
/// werden bewusst nicht unterstützt (Context §20). HMAC-MD5 wird ausschließlich für diese
/// NTLM-internen Berechnungen genutzt.
/// </summary>
public static class NtlmCryptography
{
    /// <summary>NT-Hash = <c>MD4(UTF16LE(password))</c> (MS-NLMP §3.3.1, NTOWFv1-Basis).</summary>
    public static byte[] NtHash(string password)
        => Md4.Compute(Encoding.Unicode.GetBytes(password));

    /// <summary>
    /// NTOWFv2 = <c>HMAC_MD5( NTHash, UTF16LE( Uppercase(user) ‖ domain ) )</c>
    /// (Context §9.3, MS-NLMP §3.3.2). User wird groß-, Domain nicht verändert.
    /// </summary>
    public static byte[] NtowfV2(byte[] ntHash, string user, string domain)
    {
        byte[] data = Encoding.Unicode.GetBytes(user.ToUpperInvariant() + domain);
        using var hmac = new HMACMD5(ntHash);
        return hmac.ComputeHash(data);
    }

    /// <summary>NTOWFv2 direkt aus dem Passwort.</summary>
    public static byte[] NtowfV2FromPassword(string password, string user, string domain)
        => NtowfV2(NtHash(password), user, domain);

    /// <summary>
    /// NTProofStr = <c>HMAC_MD5( NTOWFv2, ServerChallenge ‖ temp )</c> (Context §9.3).
    /// <paramref name="temp"/> ist der NTLMv2_RESPONSE-Anteil ab Responseversion (ohne die
    /// vorangestellten 16 Byte NTProofStr).
    /// </summary>
    public static byte[] NtProofString(byte[] ntowfV2, ReadOnlySpan<byte> serverChallenge, ReadOnlySpan<byte> temp)
    {
        var data = new byte[serverChallenge.Length + temp.Length];
        serverChallenge.CopyTo(data);
        temp.CopyTo(data.AsSpan(serverChallenge.Length));
        using var hmac = new HMACMD5(ntowfV2);
        return hmac.ComputeHash(data);
    }

    /// <summary>SessionBaseKey = <c>HMAC_MD5( NTOWFv2, NTProofStr )</c> (Context §9.3).</summary>
    public static byte[] SessionBaseKey(byte[] ntowfV2, ReadOnlySpan<byte> ntProofStr)
    {
        using var hmac = new HMACMD5(ntowfV2);
        return hmac.ComputeHash(ntProofStr.ToArray());
    }

    /// <summary>
    /// ExportedSessionKey ableiten (MS-NLMP §3.4.5.1/§3.4.5.2): Bei NTLMv2 ist
    /// <c>KeyExchangeKey = SessionBaseKey</c>. Ist <c>NEGOTIATE_KEY_EXCH</c> gesetzt, gilt
    /// <c>ExportedSessionKey = RC4(KeyExchangeKey, EncryptedRandomSessionKey)</c>, sonst
    /// <c>= KeyExchangeKey</c>. Dieser Schlüssel ist der GSS-Session-Key für §8.3.
    /// </summary>
    public static byte[] ExportedSessionKey(byte[] sessionBaseKey, bool keyExchange,
        ReadOnlySpan<byte> encryptedRandomSessionKey)
    {
        if (!keyExchange || encryptedRandomSessionKey.IsEmpty)
            return sessionBaseKey;
        return Rc4.Transform(sessionBaseKey, encryptedRandomSessionKey);
    }

    /// <summary>
    /// MIC = <c>HMAC_MD5( ExportedSessionKey, NegotiateMsg ‖ ChallengeMsg ‖ AuthenticateMsg )</c>,
    /// wobei im AuthenticateMsg das 16-Byte-MIC-Feld auf 0 steht (MS-NLMP §3.1.5.1.2, Context §9.3).
    /// </summary>
    public static byte[] ComputeMic(byte[] exportedSessionKey,
        ReadOnlySpan<byte> negotiate, ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> authenticateWithZeroMic)
    {
        var data = new byte[negotiate.Length + challenge.Length + authenticateWithZeroMic.Length];
        negotiate.CopyTo(data);
        challenge.CopyTo(data.AsSpan(negotiate.Length));
        authenticateWithZeroMic.CopyTo(data.AsSpan(negotiate.Length + challenge.Length));
        using var hmac = new HMACMD5(exportedSessionKey);
        return hmac.ComputeHash(data);
    }
}
