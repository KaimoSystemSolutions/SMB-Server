using System.Security.Cryptography;
using System.Text;
using Smb.Crypto;
using Smb.Protocol.Wire;

namespace Smb.Auth.Ntlm;

/// <summary>
/// Client-side NTLMv2 computation (MS-NLMP §3.1.5). Builds NEGOTIATE/AUTHENTICATE and processes
/// the CHALLENGE. Used by the sample client and by integration tests to log in with real
/// credentials. Sends raw NTLMSSP tokens (without an SPNEGO wrapper).
/// </summary>
public sealed class NtlmClient
{
    private readonly string _domain;
    private readonly string _user;
    private readonly string _password;

    /// <summary>Available after <see cref="BuildAuthenticate"/>: the GSS session key (for SMB signing/keys).</summary>
    public byte[] ExportedSessionKey { get; private set; } = [];

    // Raw NEGOTIATE/CHALLENGE kept so an optional MIC can be computed over all three messages.
    private byte[] _negotiate = [];
    private byte[] _challenge = [];

    public NtlmClient(string domain, string user, string password)
    {
        _domain = domain;
        _user = user;
        _password = password;
    }

    /// <summary>Builds the NEGOTIATE_MESSAGE (Type 1, raw NTLMSSP).</summary>
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
        w.WriteUInt64(0); // DomainNameFields (empty)
        w.WriteUInt64(0); // WorkstationFields (empty)
        _negotiate = w.ToArray();
        return _negotiate;
    }

    /// <summary>
    /// Processes the CHALLENGE and builds the AUTHENTICATE_MESSAGE (Type 3) with an NTLMv2 response.
    /// Sets <see cref="ExportedSessionKey"/> as a side effect.
    /// </summary>
    public byte[] BuildAuthenticate(ReadOnlySpan<byte> challengeToken, bool withMic = false)
    {
        _challenge = challengeToken.ToArray();
        (byte[] serverChallenge, byte[] targetInfo) = ParseChallenge(challengeToken);

        // When adding a MIC, announce it in MsvAvFlags (bit 0x2); the flag is part of the TargetInfo
        // that feeds the NTProofStr, so it must be set before computing the response.
        if (withMic) targetInfo = AddMsvAvFlags(targetInfo, 0x00000002);

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

        // Keys: KeyExchangeKey = SessionBaseKey; ExportedSessionKey = random, RC4-encrypted.
        byte[] sessionBaseKey = NtlmCryptography.SessionBaseKey(ntowfV2, ntProof);
        ExportedSessionKey = RandomNumberGenerator.GetBytes(16);
        byte[] encryptedSessionKey = Rc4.Transform(sessionBaseKey, ExportedSessionKey);

        byte[] message = BuildAuthenticateMessage(ntResponse, encryptedSessionKey);

        if (withMic)
        {
            // The message currently has a zeroed MIC field (offset 72); compute the MIC over
            // NEGOTIATE ‖ CHALLENGE ‖ this message and patch it in place.
            byte[] mic = NtlmCryptography.ComputeMic(ExportedSessionKey, _negotiate, _challenge, message);
            mic.CopyTo(message, 72);
        }
        return message;
    }

    /// <summary>Adds/replaces the <c>MsvAvFlags</c> AV pair in a TargetInfo blob (re-encoded with EOL).</summary>
    private static byte[] AddMsvAvFlags(byte[] targetInfo, uint flags)
    {
        List<NtlmAvPair> pairs = NtlmAvPairs.Decode(targetInfo);
        pairs.RemoveAll(p => p.Id == NtlmAvId.Flags);
        pairs.Add(new NtlmAvPair(NtlmAvId.Flags, BitConverter.GetBytes(flags)));
        return NtlmAvPairs.Encode(pairs);
    }

    private byte[] BuildAuthenticateMessage(byte[] ntResponse, byte[] encryptedSessionKey)
    {
        byte[] domain = Encoding.Unicode.GetBytes(_domain);
        byte[] user = Encoding.Unicode.GetBytes(_user);
        byte[] workstation = Encoding.Unicode.GetBytes("CLIENT");
        byte[] lmResponse = new byte[24]; // NTLMv2: the LM response is zeroed

        var flags = NtlmNegotiateFlags.NegotiateUnicode | NtlmNegotiateFlags.NegotiateNtlm
                  | NtlmNegotiateFlags.NegotiateExtendedSessionSecurity | NtlmNegotiateFlags.NegotiateKeyExchange
                  | NtlmNegotiateFlags.NegotiateAlwaysSign | NtlmNegotiateFlags.RequestTarget
                  | NtlmNegotiateFlags.NegotiateTargetInfo | NtlmNegotiateFlags.Negotiate128
                  | NtlmNegotiateFlags.Negotiate56;

        const int payloadStart = 88; // after MIC(16) at offset 72
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
        w.WriteBytes(new byte[16]);  // MIC = 0 (MIC verification is skipped on the server)

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
        if (!NtlmConstants.IsNtlmSsp(data)) throw new FormatException("Not an NTLMSSP token.");
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
