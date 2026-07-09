using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Auth.Ntlm;

/// <summary>An AV pair (TargetInfo entry, MS-NLMP §2.2.2.1).</summary>
public readonly record struct NtlmAvPair(NtlmAvId Id, byte[] Value);

/// <summary>Encoding/decoding of the TargetInfo AV-pair list (ends with MsvAvEOL).</summary>
public static class NtlmAvPairs
{
    public static byte[] Encode(IEnumerable<NtlmAvPair> pairs)
    {
        var w = new GrowableWriter(128);
        foreach (NtlmAvPair p in pairs)
        {
            w.WriteUInt16((ushort)p.Id);
            w.WriteUInt16((ushort)p.Value.Length);
            w.WriteBytes(p.Value);
        }
        w.WriteUInt16((ushort)NtlmAvId.EOL);
        w.WriteUInt16(0);
        return w.ToArray();
    }

    public static List<NtlmAvPair> Decode(ReadOnlySpan<byte> data)
    {
        var list = new List<NtlmAvPair>();
        var r = new SpanReader(data);
        while (r.Remaining >= 4)
        {
            var id = (NtlmAvId)r.ReadUInt16();
            int len = r.ReadUInt16();
            if (id == NtlmAvId.EOL) break;
            if (len > r.Remaining) break; // defensive against malformed TargetInfo
            list.Add(new NtlmAvPair(id, r.ReadByteArray(len)));
        }
        return list;
    }
}

/// <summary>NTLM CHALLENGE_MESSAGE (Type 2, MS-NLMP §2.2.1.2) — Server→Client.</summary>
public sealed class NtlmChallengeMessage
{
    public required byte[] ServerChallenge { get; init; } // 8 bytes
    public required string TargetName { get; init; }
    public required NtlmNegotiateFlags Flags { get; init; }
    public required byte[] TargetInfo { get; init; }      // encoded AV-pair list

    public byte[] ToArray()
    {
        byte[] targetNameBytes = Encoding.Unicode.GetBytes(TargetName);

        // Fixed part: Signature(8)+Type(4)+TargetNameFields(8)+Flags(4)+ServerChallenge(8)
        //             +Reserved(8)+TargetInfoFields(8)+Version(8) = 56 bytes.
        const int fixedLen = 56;
        int targetNameOffset = fixedLen;
        int targetInfoOffset = targetNameOffset + targetNameBytes.Length;

        var w = new GrowableWriter(fixedLen + targetNameBytes.Length + TargetInfo.Length);
        w.WriteBytes(NtlmConstants.Signature);
        w.WriteUInt32(NtlmConstants.MessageTypeChallenge);

        // TargetNameFields (len, maxlen, offset)
        w.WriteUInt16((ushort)targetNameBytes.Length);
        w.WriteUInt16((ushort)targetNameBytes.Length);
        w.WriteUInt32((uint)targetNameOffset);

        w.WriteUInt32((uint)Flags);
        w.WriteBytes(ServerChallenge);   // 8
        w.WriteUInt64(0);                // Reserved 8

        // TargetInfoFields
        w.WriteUInt16((ushort)TargetInfo.Length);
        w.WriteUInt16((ushort)TargetInfo.Length);
        w.WriteUInt32((uint)targetInfoOffset);

        w.WriteUInt64(0);                // Version (8) – we set 0

        w.WriteBytes(targetNameBytes);
        w.WriteBytes(TargetInfo);
        return w.ToArray();
    }
}

/// <summary>NTLM NEGOTIATE_MESSAGE (Type 1) — only the flags are needed.</summary>
public sealed class NtlmNegotiateMessage
{
    public NtlmNegotiateFlags Flags { get; init; }

    public static NtlmNegotiateMessage Parse(ReadOnlySpan<byte> data)
    {
        if (!NtlmConstants.IsNtlmSsp(data)) throw new FormatException("Not an NTLMSSP token.");
        var r = new SpanReader(data);
        r.Skip(8); // Signature
        uint type = r.ReadUInt32();
        if (type != NtlmConstants.MessageTypeNegotiate) throw new FormatException("Not a NEGOTIATE_MESSAGE.");
        var flags = (NtlmNegotiateFlags)r.ReadUInt32();
        return new NtlmNegotiateMessage { Flags = flags };
    }
}

/// <summary>NTLM AUTHENTICATE_MESSAGE (Type 3, MS-NLMP §2.2.1.3) — Client→Server.</summary>
public sealed class NtlmAuthenticateMessage
{
    public byte[] LmChallengeResponse { get; init; } = [];
    public byte[] NtChallengeResponse { get; init; } = [];
    public string DomainName { get; init; } = string.Empty;
    public string UserName { get; init; } = string.Empty;
    public string Workstation { get; init; } = string.Empty;
    public byte[] EncryptedRandomSessionKey { get; init; } = [];
    public NtlmNegotiateFlags Flags { get; init; }
    public byte[] Mic { get; init; } = new byte[16];

    /// <summary>NTProofStr (first 16 bytes of the NtChallengeResponse).</summary>
    public ReadOnlySpan<byte> NtProofString => NtChallengeResponse.AsSpan(0, 16);

    /// <summary>The "temp" part (NTLMv2_CLIENT_CHALLENGE) after the NTProofStr.</summary>
    public ReadOnlySpan<byte> ClientChallengeBlob => NtChallengeResponse.AsSpan(16);

    public static NtlmAuthenticateMessage Parse(ReadOnlySpan<byte> data)
    {
        if (!NtlmConstants.IsNtlmSsp(data)) throw new FormatException("Not an NTLMSSP token.");
        var r = new SpanReader(data);
        r.Skip(8);
        uint type = r.ReadUInt32();
        if (type != NtlmConstants.MessageTypeAuthenticate) throw new FormatException("Not an AUTHENTICATE_MESSAGE.");

        (int lmLen, int lmOff) = ReadField(ref r);
        (int ntLen, int ntOff) = ReadField(ref r);
        (int domLen, int domOff) = ReadField(ref r);
        (int userLen, int userOff) = ReadField(ref r);
        (int wsLen, int wsOff) = ReadField(ref r);
        (int keyLen, int keyOff) = ReadField(ref r);
        var flags = (NtlmNegotiateFlags)r.ReadUInt32();

        // Version (8) follows, then optionally the MIC (16). We read the MIC at its fixed
        // position (offset 64..79), provided the payload does not start earlier.
        byte[] mic = new byte[16];
        int firstPayload = Min(lmOff, ntOff, domOff, userOff, wsOff, keyOff);
        if (firstPayload >= 88 && data.Length >= 88)
            mic = data.Slice(72, 16).ToArray(); // after Signature(8)+Type(4)+6×Fields(48)+Flags(4)+Version(8)=72

        return new NtlmAuthenticateMessage
        {
            LmChallengeResponse = Slice(data, lmOff, lmLen),
            NtChallengeResponse = Slice(data, ntOff, ntLen),
            DomainName = Unicode(data, domOff, domLen),
            UserName = Unicode(data, userOff, userLen),
            Workstation = Unicode(data, wsOff, wsLen),
            EncryptedRandomSessionKey = Slice(data, keyOff, keyLen),
            Flags = flags,
            Mic = mic,
        };
    }

    private static (int len, int off) ReadField(ref SpanReader r)
    {
        int len = r.ReadUInt16();
        r.Skip(2); // MaxLen
        int off = (int)r.ReadUInt32();
        return (len, off);
    }

    private static byte[] Slice(ReadOnlySpan<byte> data, int off, int len)
    {
        if (len == 0) return [];
        EnsureInBounds(data.Length, off, len);
        return data.Slice(off, len).ToArray();
    }

    private static string Unicode(ReadOnlySpan<byte> data, int off, int len)
    {
        if (len == 0) return string.Empty;
        EnsureInBounds(data.Length, off, len);
        return Encoding.Unicode.GetString(data.Slice(off, len));
    }

    /// <summary>
    /// [REVIEW-2026-07] Validates that a payload field (len/off from the AUTHENTICATE header) lies fully
    /// within the message before slicing. The offset is a client-controlled 32-bit value and the length a
    /// 16-bit one; an out-of-range pair would make <see cref="ReadOnlySpan{T}.Slice(int,int)"/> throw an
    /// <see cref="ArgumentOutOfRangeException"/> that escapes NTLM parsing. Throwing a
    /// <see cref="FormatException"/> instead keeps it on the defined "malformed token → LogonFailure/
    /// INVALID_PARAMETER" path (<see cref="NtlmServerMechanism.HandleAuthenticate"/>) rather than relying
    /// on the dispatcher's catch-all. <c>off &gt; dataLength - len</c> is overflow-safe (len ≥ 0).
    /// </summary>
    private static void EnsureInBounds(int dataLength, int off, int len)
    {
        if (off < 0 || len < 0 || off > dataLength - len)
            throw new FormatException("NTLM AUTHENTICATE field references data outside the message.");
    }

    private static int Min(params int[] values)
    {
        int m = int.MaxValue;
        foreach (int v in values) if (v > 0 && v < m) m = v;
        return m;
    }
}
