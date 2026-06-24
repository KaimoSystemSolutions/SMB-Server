using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Auth.Ntlm;

/// <summary>Ein AV-Pair (TargetInfo-Eintrag, MS-NLMP §2.2.2.1).</summary>
public readonly record struct NtlmAvPair(NtlmAvId Id, byte[] Value);

/// <summary>Kodierung/Dekodierung der TargetInfo-AV-Pair-Liste (endet mit MsvAvEOL).</summary>
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
            if (len > r.Remaining) break; // defensiv gegen fehlformatierte TargetInfo
            list.Add(new NtlmAvPair(id, r.ReadByteArray(len)));
        }
        return list;
    }
}

/// <summary>NTLM CHALLENGE_MESSAGE (Type 2, MS-NLMP §2.2.1.2) — Server→Client.</summary>
public sealed class NtlmChallengeMessage
{
    public required byte[] ServerChallenge { get; init; } // 8 Byte
    public required string TargetName { get; init; }
    public required NtlmNegotiateFlags Flags { get; init; }
    public required byte[] TargetInfo { get; init; }      // kodierte AV-Pair-Liste

    public byte[] ToArray()
    {
        byte[] targetNameBytes = Encoding.Unicode.GetBytes(TargetName);

        // Fester Teil: Signature(8)+Type(4)+TargetNameFields(8)+Flags(4)+ServerChallenge(8)
        //              +Reserved(8)+TargetInfoFields(8)+Version(8) = 56 Byte.
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

        w.WriteUInt64(0);                // Version (8) – wir setzen 0

        w.WriteBytes(targetNameBytes);
        w.WriteBytes(TargetInfo);
        return w.ToArray();
    }
}

/// <summary>NTLM NEGOTIATE_MESSAGE (Type 1) — nur die Flags werden gebraucht.</summary>
public sealed class NtlmNegotiateMessage
{
    public NtlmNegotiateFlags Flags { get; init; }

    public static NtlmNegotiateMessage Parse(ReadOnlySpan<byte> data)
    {
        if (!NtlmConstants.IsNtlmSsp(data)) throw new FormatException("Kein NTLMSSP-Token.");
        var r = new SpanReader(data);
        r.Skip(8); // Signature
        uint type = r.ReadUInt32();
        if (type != NtlmConstants.MessageTypeNegotiate) throw new FormatException("Kein NEGOTIATE_MESSAGE.");
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

    /// <summary>NTProofStr (erste 16 Byte der NtChallengeResponse).</summary>
    public ReadOnlySpan<byte> NtProofString => NtChallengeResponse.AsSpan(0, 16);

    /// <summary>Der "temp"-Teil (NTLMv2_CLIENT_CHALLENGE) hinter dem NTProofStr.</summary>
    public ReadOnlySpan<byte> ClientChallengeBlob => NtChallengeResponse.AsSpan(16);

    public static NtlmAuthenticateMessage Parse(ReadOnlySpan<byte> data)
    {
        if (!NtlmConstants.IsNtlmSsp(data)) throw new FormatException("Kein NTLMSSP-Token.");
        var r = new SpanReader(data);
        r.Skip(8);
        uint type = r.ReadUInt32();
        if (type != NtlmConstants.MessageTypeAuthenticate) throw new FormatException("Kein AUTHENTICATE_MESSAGE.");

        (int lmLen, int lmOff) = ReadField(ref r);
        (int ntLen, int ntOff) = ReadField(ref r);
        (int domLen, int domOff) = ReadField(ref r);
        (int userLen, int userOff) = ReadField(ref r);
        (int wsLen, int wsOff) = ReadField(ref r);
        (int keyLen, int keyOff) = ReadField(ref r);
        var flags = (NtlmNegotiateFlags)r.ReadUInt32();

        // Version (8) folgt, danach optional MIC (16). Wir lesen das MIC anhand seiner festen
        // Position (Offset 64..79), sofern die Payload nicht früher beginnt.
        byte[] mic = new byte[16];
        int firstPayload = Min(lmOff, ntOff, domOff, userOff, wsOff, keyOff);
        if (firstPayload >= 88 && data.Length >= 88)
            mic = data.Slice(72, 16).ToArray(); // nach Signature(8)+Type(4)+6×Fields(48)+Flags(4)+Version(8)=72

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
        => len == 0 ? [] : data.Slice(off, len).ToArray();

    private static string Unicode(ReadOnlySpan<byte> data, int off, int len)
        => len == 0 ? string.Empty : Encoding.Unicode.GetString(data.Slice(off, len));

    private static int Min(params int[] values)
    {
        int m = int.MaxValue;
        foreach (int v in values) if (v > 0 && v < m) m = v;
        return m;
    }
}
