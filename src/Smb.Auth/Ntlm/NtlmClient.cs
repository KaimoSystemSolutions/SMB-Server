using System.Security.Cryptography;
using System.Text;
using Smb.Crypto;
using Smb.Protocol.Wire;

namespace Smb.Auth.Ntlm;

/// <summary>
/// Client-seitige NTLMv2-Berechnung (MS-NLMP §3.1.5). Baut NEGOTIATE/AUTHENTICATE und
/// verarbeitet die CHALLENGE. Wird vom Beispiel-Client und von Integrationstests genutzt,
/// um sich mit echten Credentials anzumelden. Sendet rohe NTLMSSP-Tokens (ohne SPNEGO-Wrapper).
/// </summary>
public sealed class NtlmClient
{
    private readonly string _domain;
    private readonly string _user;
    private readonly string _password;

    /// <summary>Nach <see cref="BuildAuthenticate"/> verfügbar: der GSS-Session-Key (für SMB-Signing/Keys).</summary>
    public byte[] ExportedSessionKey { get; private set; } = [];

    public NtlmClient(string domain, string user, string password)
    {
        _domain = domain;
        _user = user;
        _password = password;
    }

    /// <summary>Baut das NEGOTIATE_MESSAGE (Type 1, rohes NTLMSSP).</summary>
    public byte[] BuildNegotiate()
    {
        var flags = NtlmNegotiateFlags.NegotiateUnicode | NtlmNegotiateFlags.NegotiateNtlm
                  | NtlmNegotiateFlags.RequestTarget | NtlmNegotiateFlags.NegotiateExtendedSessionSecurity
                  | NtlmNegotiateFlags.NegotiateAlwaysSign | NtlmNegotiateFlags.NegotiateKeyExchange
                  | NtlmNegotiateFlags.Negotiate128 | NtlmNegotiateFlags.Negotiate56;

        var w = new GrowableWriter(40);
        w.WriteBytes(NtlmConstants.Signature);
        w.WriteUInt32(NtlmConstants.MessageTypeNegotiate);
        w.WriteUInt32((uint)flags);
        w.WriteUInt64(0); // DomainNameFields (leer)
        w.WriteUInt64(0); // WorkstationFields (leer)
        return w.ToArray();
    }

    /// <summary>
    /// Verarbeitet die CHALLENGE und baut das AUTHENTICATE_MESSAGE (Type 3) mit NTLMv2-Response.
    /// Setzt nebenbei <see cref="ExportedSessionKey"/>.
    /// </summary>
    public byte[] BuildAuthenticate(ReadOnlySpan<byte> challengeToken)
    {
        (byte[] serverChallenge, byte[] targetInfo) = ParseChallenge(challengeToken);

        byte[] ntHash = NtlmCryptography.NtHash(_password);
        byte[] ntowfV2 = NtlmCryptography.NtowfV2(ntHash, _user, _domain);

        // NTLMv2_CLIENT_CHALLENGE ("temp"): RespType‖HiRespType‖Reserved‖Timestamp‖ClientChallenge‖Reserved‖TargetInfo‖Reserved
        long timestamp = ExtractTimestamp(targetInfo) ?? DateTime.UtcNow.ToFileTimeUtc();
        byte[] clientChallenge = RandomNumberGenerator.GetBytes(8);

        var temp = new GrowableWriter(64 + targetInfo.Length);
        temp.WriteByte(0x01); // RespType
        temp.WriteByte(0x01); // HiRespType
        temp.WriteUInt16(0);  // Reserved1
        temp.WriteUInt32(0);  // Reserved2
        temp.WriteUInt64((ulong)timestamp);
        temp.WriteBytes(clientChallenge);
        temp.WriteUInt32(0);  // Reserved3
        temp.WriteBytes(targetInfo);
        temp.WriteUInt32(0);  // Reserved (Ende)
        byte[] tempBytes = temp.ToArray();

        byte[] ntProof = NtlmCryptography.NtProofString(ntowfV2, serverChallenge, tempBytes);

        // NtChallengeResponse = NTProofStr ‖ temp
        var ntResponse = new byte[ntProof.Length + tempBytes.Length];
        ntProof.CopyTo(ntResponse, 0);
        tempBytes.CopyTo(ntResponse, ntProof.Length);

        // Schlüssel: KeyExchangeKey = SessionBaseKey; ExportedSessionKey = zufällig, RC4-verschlüsselt.
        byte[] sessionBaseKey = NtlmCryptography.SessionBaseKey(ntowfV2, ntProof);
        ExportedSessionKey = RandomNumberGenerator.GetBytes(16);
        byte[] encryptedSessionKey = Rc4.Transform(sessionBaseKey, ExportedSessionKey);

        return BuildAuthenticateMessage(ntResponse, encryptedSessionKey);
    }

    private byte[] BuildAuthenticateMessage(byte[] ntResponse, byte[] encryptedSessionKey)
    {
        byte[] domain = Encoding.Unicode.GetBytes(_domain);
        byte[] user = Encoding.Unicode.GetBytes(_user);
        byte[] workstation = Encoding.Unicode.GetBytes("CLIENT");
        byte[] lmResponse = new byte[24]; // NTLMv2: LM-Response wird genullt

        var flags = NtlmNegotiateFlags.NegotiateUnicode | NtlmNegotiateFlags.NegotiateNtlm
                  | NtlmNegotiateFlags.NegotiateExtendedSessionSecurity | NtlmNegotiateFlags.NegotiateKeyExchange
                  | NtlmNegotiateFlags.NegotiateAlwaysSign | NtlmNegotiateFlags.RequestTarget
                  | NtlmNegotiateFlags.NegotiateTargetInfo | NtlmNegotiateFlags.Negotiate128
                  | NtlmNegotiateFlags.Negotiate56;

        const int payloadStart = 88; // nach MIC(16) bei Offset 72
        int off = payloadStart;
        int lmOff = off; off += lmResponse.Length;
        int ntOff = off; off += ntResponse.Length;
        int domOff = off; off += domain.Length;
        int userOff = off; off += user.Length;
        int wsOff = off; off += workstation.Length;
        int keyOff = off; off += encryptedSessionKey.Length;

        var w = new GrowableWriter(off);
        w.WriteBytes(NtlmConstants.Signature);
        w.WriteUInt32(NtlmConstants.MessageTypeAuthenticate);
        WriteField(w, lmResponse.Length, lmOff);
        WriteField(w, ntResponse.Length, ntOff);
        WriteField(w, domain.Length, domOff);
        WriteField(w, user.Length, userOff);
        WriteField(w, workstation.Length, wsOff);
        WriteField(w, encryptedSessionKey.Length, keyOff);
        w.WriteUInt32((uint)flags);
        w.WriteUInt64(0);            // Version
        w.WriteBytes(new byte[16]);  // MIC = 0 (MIC-Prüfung wird serverseitig übersprungen)

        w.WriteBytes(lmResponse);
        w.WriteBytes(ntResponse);
        w.WriteBytes(domain);
        w.WriteBytes(user);
        w.WriteBytes(workstation);
        w.WriteBytes(encryptedSessionKey);
        return w.ToArray();
    }

    private static void WriteField(GrowableWriter w, int length, int offset)
    {
        w.WriteUInt16((ushort)length);
        w.WriteUInt16((ushort)length);
        w.WriteUInt32((uint)offset);
    }

    private static (byte[] serverChallenge, byte[] targetInfo) ParseChallenge(ReadOnlySpan<byte> data)
    {
        if (!NtlmConstants.IsNtlmSsp(data)) throw new FormatException("Kein NTLMSSP-Token.");
        var r = new SpanReader(data);
        r.Skip(8);                 // Signature
        r.ReadUInt32();            // MessageType
        r.Skip(8);                 // TargetNameFields
        r.ReadUInt32();            // NegotiateFlags
        byte[] serverChallenge = r.ReadByteArray(8);
        r.Skip(8);                 // Reserved
        int tiLen = r.ReadUInt16();
        r.Skip(2);                 // TargetInfoMaxLen
        int tiOff = (int)r.ReadUInt32();
        byte[] targetInfo = tiLen == 0 ? [] : data.Slice(tiOff, tiLen).ToArray();
        return (serverChallenge, targetInfo);
    }

    private static long? ExtractTimestamp(byte[] targetInfo)
    {
        foreach (NtlmAvPair pair in NtlmAvPairs.Decode(targetInfo))
            if (pair.Id == NtlmAvId.Timestamp && pair.Value.Length == 8)
                return BitConverter.ToInt64(pair.Value);
        return null;
    }
}
