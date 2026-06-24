using System.Formats.Asn1;

namespace Smb.Auth.Oids;

/// <summary>Geparster Inhalt eines eingehenden SPNEGO-Tokens (NegTokenInit oder NegTokenResp).</summary>
public sealed class SpnegoParseResult
{
    /// <summary>Angebotene Mechanismus-OIDs (nur bei NegTokenInit gefüllt).</summary>
    public IReadOnlyList<string> MechTypes { get; init; } = [];

    /// <summary>Das eingebettete Mech-Token (z.B. NTLMSSP-Blob), falls vorhanden.</summary>
    public byte[]? MechToken { get; init; }

    /// <summary>negState bei NegTokenResp (0=accept-completed, 1=accept-incomplete, 2=reject, 3=request-mic).</summary>
    public int? NegState { get; init; }

    /// <summary>True, wenn das Token ein NegTokenResp (Folge-Token) war; sonst NegTokenInit.</summary>
    public bool IsResponseToken { get; init; }
}

/// <summary>
/// Kodierung/Dekodierung von SPNEGO-Tokens (RFC 4178, MS-SPNG) per ASN.1-DER. Genutzt vom
/// Negotiator (Context §9). Deckt den für SMB nötigen Satz ab: server-seitiges NegTokenInit2
/// (NEGOTIATE-Response) und Parsen der Client-Tokens (NegTokenInit / NegTokenResp).
/// </summary>
public static class SpnegoTokens
{
    // SPNEGO negState "accept-incomplete" (mehr Schritte nötig).
    public const int NegStateAcceptCompleted = 0;
    public const int NegStateAcceptIncomplete = 1;
    public const int NegStateReject = 2;

    // Default-Hint, den auch Windows verwendet.
    private const string DefaultHintName = "not_defined_in_RFC4178@please_ignore";

    private static readonly Asn1Tag ContextTag0 = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag ContextTag1 = new(TagClass.ContextSpecific, 1);
    private static readonly Asn1Tag ContextTag2 = new(TagClass.ContextSpecific, 2);
    private static readonly Asn1Tag ContextTag3 = new(TagClass.ContextSpecific, 3);
    private static readonly Asn1Tag ApplicationTag0 = new(TagClass.Application, 0, isConstructed: true);

    /// <summary>
    /// Baut das server-initiale NegTokenInit2 (Context §9.2). Struktur:
    /// <c>[APPLICATION 0] { SPNEGO-OID, [0] NegTokenInit2 { mechTypes [0], negHints [3] } }</c>.
    /// </summary>
    public static byte[] CreateNegTokenInit2(IReadOnlyList<string> mechTypes, string? hintName = DefaultHintName)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence(ApplicationTag0))
        {
            writer.WriteObjectIdentifier(GssOids.Spnego);

            using (writer.PushSequence(ContextTag0)) // innerContextToken [0] NegTokenInit2
            using (writer.PushSequence())            // NegTokenInit2 ::= SEQUENCE
            {
                // mechTypes [0] MechTypeList
                using (writer.PushSequence(ContextTag0))
                using (writer.PushSequence())
                {
                    foreach (string oid in mechTypes)
                        writer.WriteObjectIdentifier(oid);
                }

                // negHints [3] NegHints { hintName [0] GeneralString }
                if (hintName is not null)
                {
                    using (writer.PushSequence(ContextTag3))
                    using (writer.PushSequence())
                    using (writer.PushSequence(ContextTag0))
                    {
                        // GeneralString (Universal 27) — die BCL-AsnWriter-API kann diesen
                        // String-Typ nicht direkt schreiben; daher die TLV von Hand kodieren
                        // und als fertigen Wert einsetzen.
                        writer.WriteEncodedValue(EncodeGeneralString(hintName));
                    }
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// Baut ein NegTokenResp (Server→Client-Folge-Token), z.B. mit <c>responseToken</c>
    /// (= NTLM CHALLENGE_MESSAGE) und negState <c>accept-incomplete</c>.
    /// </summary>
    public static byte[] CreateNegTokenResp(int negState, string? supportedMech = null,
        byte[]? responseToken = null, byte[]? mechListMic = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence(ContextTag1)) // NegotiationToken CHOICE negTokenResp [1]
        using (writer.PushSequence())            // NegTokenResp ::= SEQUENCE
        {
            using (writer.PushSequence(ContextTag0))
                writer.WriteEnumeratedValue((NegStateValue)negState);

            if (supportedMech is not null)
                using (writer.PushSequence(ContextTag1))
                    writer.WriteObjectIdentifier(supportedMech);

            if (responseToken is not null)
                using (writer.PushSequence(ContextTag2))
                    writer.WriteOctetString(responseToken);

            if (mechListMic is not null)
                using (writer.PushSequence(ContextTag3))
                    writer.WriteOctetString(mechListMic);
        }

        return writer.Encode();
    }

    private enum NegStateValue { }

    /// <summary>Kodiert eine ASCII-Zeichenkette als DER-GeneralString-TLV (Tag 0x1B).</summary>
    private static byte[] EncodeGeneralString(string value)
    {
        byte[] content = System.Text.Encoding.ASCII.GetBytes(value);
        if (content.Length < 0x80)
        {
            var tlv = new byte[2 + content.Length];
            tlv[0] = 0x1B;                  // [UNIVERSAL 27] GeneralString, primitiv
            tlv[1] = (byte)content.Length;  // kurze Längenform
            content.CopyTo(tlv, 2);
            return tlv;
        }

        // Lange Längenform (für lange Hints — in der Praxis nicht nötig).
        var lenBytes = new List<byte>();
        int len = content.Length;
        while (len > 0) { lenBytes.Insert(0, (byte)(len & 0xFF)); len >>= 8; }
        var result = new byte[2 + lenBytes.Count + content.Length];
        result[0] = 0x1B;
        result[1] = (byte)(0x80 | lenBytes.Count);
        lenBytes.CopyTo(result, 2);
        content.CopyTo(result, 2 + lenBytes.Count);
        return result;
    }

    /// <summary>
    /// Parst ein eingehendes SPNEGO-Token: NegTokenInit (GSSAPI-App-Tag) oder NegTokenResp.
    /// Liefert die Mech-OIDs und/oder das eingebettete Mech-Token.
    /// </summary>
    public static SpnegoParseResult Parse(ReadOnlySpan<byte> token)
    {
        var reader = new AsnReader(token.ToArray(), AsnEncodingRules.DER);
        Asn1Tag tag = reader.PeekTag();

        if (tag.TagClass == TagClass.Application && tag.TagValue == 0)
            return ParseNegTokenInit(reader);

        if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 1)
            return ParseNegTokenResp(reader);

        throw new FormatException($"Unerwartetes SPNEGO-Top-Level-Tag {tag.TagClass}/{tag.TagValue}.");
    }

    private static SpnegoParseResult ParseNegTokenInit(AsnReader reader)
    {
        AsnReader app = reader.ReadSequence(ApplicationTag0);
        string oid = app.ReadObjectIdentifier();
        if (oid != GssOids.Spnego)
            throw new FormatException($"Erwartete SPNEGO-OID, fand {oid}.");

        AsnReader inner = app.ReadSequence(ContextTag0);
        AsnReader negInit = inner.ReadSequence();

        var mechTypes = new List<string>();
        byte[]? mechToken = null;

        while (negInit.HasData)
        {
            Asn1Tag fieldTag = negInit.PeekTag();
            if (fieldTag.TagClass != TagClass.ContextSpecific)
            {
                negInit.ReadEncodedValue();
                continue;
            }

            switch (fieldTag.TagValue)
            {
                case 0: // mechTypes [0] MechTypeList
                    AsnReader list = negInit.ReadSequence(ContextTag0).ReadSequence();
                    while (list.HasData) mechTypes.Add(list.ReadObjectIdentifier());
                    break;
                case 2: // mechToken [2] OCTET STRING
                    mechToken = negInit.ReadSequence(ContextTag2).ReadOctetString();
                    break;
                default:
                    negInit.ReadEncodedValue();
                    break;
            }
        }

        return new SpnegoParseResult { MechTypes = mechTypes, MechToken = mechToken, IsResponseToken = false };
    }

    private static SpnegoParseResult ParseNegTokenResp(AsnReader reader)
    {
        AsnReader resp = reader.ReadSequence(ContextTag1).ReadSequence();
        int? negState = null;
        byte[]? responseToken = null;

        while (resp.HasData)
        {
            Asn1Tag fieldTag = resp.PeekTag();
            if (fieldTag.TagClass != TagClass.ContextSpecific)
            {
                resp.ReadEncodedValue();
                continue;
            }

            switch (fieldTag.TagValue)
            {
                case 0: // negState [0] ENUMERATED
                    negState = (int)resp.ReadSequence(ContextTag0).ReadEnumeratedValue<NegStateValue>();
                    break;
                case 2: // responseToken [2] OCTET STRING
                    responseToken = resp.ReadSequence(ContextTag2).ReadOctetString();
                    break;
                default:
                    resp.ReadEncodedValue();
                    break;
            }
        }

        return new SpnegoParseResult { MechToken = responseToken, NegState = negState, IsResponseToken = true };
    }
}
