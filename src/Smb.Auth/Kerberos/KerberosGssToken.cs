using System.Formats.Asn1;
using Smb.Auth.Oids;

namespace Smb.Auth.Kerberos;

/// <summary>
/// GSS-API mechanism-token framing for Kerberos (RFC 1964 / RFC 4121 §4.1, RFC 2743 §3.1). A Kerberos
/// SPNEGO <c>mechToken</c> is the initial GSS-API context token:
/// <code>
/// [APPLICATION 0] IMPLICIT SEQUENCE {
///     thisMech  OBJECT IDENTIFIER,        -- krb5 (or the MS legacy OID)
///     TOK_ID    2 bytes,                  -- 01 00 = AP-REQ, 02 00 = AP-REP
///     innerToken … (raw KRB_AP_REQ / KRB_AP_REP DER)
/// }
/// </code>
/// The inner token after TOK_ID is <b>not</b> a nested DER value of the SEQUENCE, so the tail is handled
/// with a small manual TLV reader/writer rather than <see cref="AsnReader"/>/<see cref="AsnWriter"/>.
/// </summary>
public static class KerberosGssToken
{
    /// <summary>TOK_ID for KRB_AP_REQ (RFC 4121 §4.1).</summary>
    public static ReadOnlySpan<byte> TokIdApReq => [0x01, 0x00];

    /// <summary>TOK_ID for KRB_AP_REP.</summary>
    public static ReadOnlySpan<byte> TokIdApRep => [0x02, 0x00];

    private const byte Application0 = 0x60; // [APPLICATION 0], constructed

    /// <summary>
    /// Strips the GSS-API wrapper from a Kerberos mech token and returns the inner KRB_AP_REQ. Returns
    /// <c>false</c> (without throwing) when the bytes are not a Kerberos GSS token — callers may then fall
    /// back to treating the input as a bare AP-REQ.
    /// </summary>
    public static bool TryReadApReq(ReadOnlySpan<byte> gssToken, out byte[] apReq)
    {
        apReq = [];
        if (gssToken.Length < 2 || gssToken[0] != Application0) return false;

        int pos = 1;
        if (!TryReadLength(gssToken, ref pos, out int bodyLen)) return false;
        if (pos + bodyLen > gssToken.Length) return false;
        ReadOnlySpan<byte> body = gssToken.Slice(pos, bodyLen);

        // thisMech OID.
        if (body.Length < 2 || body[0] != 0x06) return false;
        int p = 1;
        if (!TryReadLength(body, ref p, out int oidLen)) return false;
        if (p + oidLen > body.Length) return false;

        if (!IsKerberosOid(body.Slice(0, p + oidLen))) return false;
        p += oidLen;

        // TOK_ID (2 bytes) — we accept AP-REQ; other tok-ids are rejected as "not an AP-REQ".
        if (p + 2 > body.Length) return false;
        if (!body.Slice(p, 2).SequenceEqual(TokIdApReq)) return false;
        p += 2;

        apReq = body[p..].ToArray();
        return true;
    }

    /// <summary>
    /// Wraps a raw KRB_AP_REP into the GSS-API mech token the client expects for mutual authentication
    /// (krb5 OID + <see cref="TokIdApRep"/> + AP-REP).
    /// </summary>
    public static byte[] WrapApRep(ReadOnlySpan<byte> apRep) => Wrap(TokIdApRep, apRep);

    /// <summary>Wraps a raw KRB_AP_REQ into a GSS-API mech token (mainly for tests / client-side use).</summary>
    public static byte[] WrapApReq(ReadOnlySpan<byte> apReq) => Wrap(TokIdApReq, apReq);

    private static byte[] Wrap(ReadOnlySpan<byte> tokId, ReadOnlySpan<byte> inner)
    {
        byte[] oidTlv = EncodeOidTlv(GssOids.KerberosV5);
        int bodyLen = oidTlv.Length + tokId.Length + inner.Length;
        byte[] lenBytes = EncodeLength(bodyLen);

        var token = new byte[1 + lenBytes.Length + bodyLen];
        int i = 0;
        token[i++] = Application0;
        lenBytes.CopyTo(token, i); i += lenBytes.Length;
        oidTlv.CopyTo(token, i); i += oidTlv.Length;
        tokId.CopyTo(token.AsSpan(i)); i += tokId.Length;
        inner.CopyTo(token.AsSpan(i));
        return token;
    }

    private static bool IsKerberosOid(ReadOnlySpan<byte> oidTlv)
    {
        try
        {
            var reader = new AsnReader(oidTlv.ToArray(), AsnEncodingRules.DER);
            string oid = reader.ReadObjectIdentifier();
            return oid is GssOids.KerberosV5 or GssOids.KerberosLegacy;
        }
        catch (AsnContentException) { return false; }
    }

    private static byte[] EncodeOidTlv(string oid)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteObjectIdentifier(oid);
        return w.Encode();
    }

    // --- BER/DER definite length helpers ---

    private static bool TryReadLength(ReadOnlySpan<byte> data, ref int pos, out int length)
    {
        length = 0;
        if (pos >= data.Length) return false;
        byte first = data[pos++];
        if ((first & 0x80) == 0) { length = first; return true; }  // short form

        int count = first & 0x7F;
        if (count == 0 || count > 4 || pos + count > data.Length) return false; // no indefinite/oversized
        int value = 0;
        for (int i = 0; i < count; i++) value = (value << 8) | data[pos++];
        if (value < 0) return false;
        length = value;
        return true;
    }

    private static byte[] EncodeLength(int length)
    {
        if (length < 0x80) return [(byte)length];
        var bytes = new List<byte>(4);
        int v = length;
        while (v > 0) { bytes.Insert(0, (byte)(v & 0xFF)); v >>= 8; }
        var result = new byte[1 + bytes.Count];
        result[0] = (byte)(0x80 | bytes.Count);
        bytes.CopyTo(result, 1);
        return result;
    }
}
