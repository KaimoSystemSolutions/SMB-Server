using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Smb.Crypto;

/// <summary>
/// NTLMv2 core computations (Context §9.3, MS-NLMP §3.3.2). NTLMv2 only — NTLMv1/LM are
/// deliberately not supported (Context §20). HMAC-MD5 is used exclusively for these
/// NTLM-internal computations.
/// </summary>
public static class NtlmCryptography
{
    /// <summary>NT hash = <c>MD4(UTF16LE(password))</c> (MS-NLMP §3.3.1, NTOWFv1 basis).</summary>
    public static byte[] NtHash(string password)
        => Md4.Compute(Encoding.Unicode.GetBytes(password));

    /// <summary>
    /// NTOWFv2 = <c>HMAC_MD5( NTHash, UTF16LE( Uppercase(user) ‖ domain ) )</c>
    /// (Context §9.3, MS-NLMP §3.3.2). The user is upper-cased, the domain is left unchanged.
    /// </summary>
    public static byte[] NtowfV2(byte[] ntHash, string user, string domain)
    {
        byte[] data = Encoding.Unicode.GetBytes(user.ToUpperInvariant() + domain);
        using var hmac = new HMACMD5(ntHash);
        return hmac.ComputeHash(data);
    }

    /// <summary>NTOWFv2 directly from the password.</summary>
    public static byte[] NtowfV2FromPassword(string password, string user, string domain)
        => NtowfV2(NtHash(password), user, domain);

    /// <summary>
    /// NTProofStr = <c>HMAC_MD5( NTOWFv2, ServerChallenge ‖ temp )</c> (Context §9.3).
    /// <paramref name="temp"/> is the NTLMv2_RESPONSE part from the response version onward (without
    /// the leading 16 bytes of NTProofStr).
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
    /// Derive the ExportedSessionKey (MS-NLMP §3.4.5.1/§3.4.5.2): for NTLMv2,
    /// <c>KeyExchangeKey = SessionBaseKey</c>. If <c>NEGOTIATE_KEY_EXCH</c> is set, then
    /// <c>ExportedSessionKey = RC4(KeyExchangeKey, EncryptedRandomSessionKey)</c>, otherwise
    /// <c>= KeyExchangeKey</c>. This key is the GSS session key for §8.3.
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
    /// where the 16-byte MIC field in AuthenticateMsg is zeroed (MS-NLMP §3.1.5.1.2, Context §9.3).
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

    // MS-NLMP §3.4.5.2 / §3.4.5.3 key-derivation magic constants (the terminating NUL is part of the
    // MD5 input). "client" = client-to-server keys; "server" = server-to-client keys.
    private static readonly byte[] ClientSignMagic =
        Encoding.ASCII.GetBytes("session key to client-to-server signing key magic constant\0");
    private static readonly byte[] ServerSignMagic =
        Encoding.ASCII.GetBytes("session key to server-to-client signing key magic constant\0");
    private static readonly byte[] ClientSealMagic =
        Encoding.ASCII.GetBytes("session key to client-to-server sealing key magic constant\0");
    private static readonly byte[] ServerSealMagic =
        Encoding.ASCII.GetBytes("session key to server-to-client sealing key magic constant\0");

    /// <summary>SIGNKEY (MS-NLMP §3.4.5.2): <c>MD5( ExportedSessionKey ‖ magic )</c>, extended session
    /// security. <paramref name="client"/> selects the client-to-server (true) or server-to-client key.</summary>
    public static byte[] NtlmSignKey(byte[] exportedSessionKey, bool client)
        => Md5Concat(exportedSessionKey, client ? ClientSignMagic : ServerSignMagic);

    /// <summary>SEALKEY (MS-NLMP §3.4.5.3): <c>MD5( ExportedSessionKey ‖ magic )</c> for extended session
    /// security with <c>NEGOTIATE_128</c> (the full 16-byte key feeds the MD5). This NTLM stack always
    /// negotiates 128-bit + key exchange, so no key-length truncation applies.</summary>
    public static byte[] NtlmSealKey(byte[] exportedSessionKey, bool client)
        => Md5Concat(exportedSessionKey, client ? ClientSealMagic : ServerSealMagic);

    private static byte[] Md5Concat(byte[] a, byte[] b)
    {
        var buf = new byte[a.Length + b.Length];
        a.CopyTo(buf, 0);
        b.CopyTo(buf, a.Length);
        return MD5.HashData(buf);
    }

    /// <summary>
    /// NTLMSSP GSS_getMIC signature for the <b>first</b> message on the context (SeqNum 0), as used for
    /// the SPNEGO <c>mechListMIC</c> (RFC 4178 §5). Connection-oriented, extended session security with
    /// key exchange (MS-NLMP §3.4.4.1): the 16-byte signature is
    /// <c>Version(1) ‖ RC4(SealKey, HMAC_MD5(SignKey, LE32(0) ‖ message)[0..8]) ‖ LE32(0)</c>.
    /// <para>Only SeqNum 0 is supported: RC4 is a stateful stream cipher, so a fresh handle is valid
    /// only for the first signed message — which is exactly the mechListMIC case.</para>
    /// </summary>
    public static byte[] NtlmMechListMic(byte[] exportedSessionKey, bool client, ReadOnlySpan<byte> message)
    {
        byte[] signKey = NtlmSignKey(exportedSessionKey, client);
        byte[] sealKey = NtlmSealKey(exportedSessionKey, client);

        var data = new byte[4 + message.Length];       // LE32(SeqNum=0) ‖ message
        message.CopyTo(data.AsSpan(4));
        byte[] hmac;
        using (var h = new HMACMD5(signKey)) hmac = h.ComputeHash(data);

        byte[] sealed8 = Rc4.Transform(sealKey, hmac.AsSpan(0, 8)); // fresh handle → valid for SeqNum 0

        var sig = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(sig.AsSpan(0), 1);   // Version
        sealed8.CopyTo(sig, 4);                                        // sealed checksum
        BinaryPrimitives.WriteUInt32LittleEndian(sig.AsSpan(12), 0);  // SeqNum
        return sig;
    }
}
