using System.Formats.Asn1;

namespace Smb.Auth.Oids;

/// <summary>Parsed content of an incoming SPNEGO token (NegTokenInit or NegTokenResp).</summary>
public sealed class SpnegoParseResult
{
    /// <summary>Offered mechanism OIDs (only populated for NegTokenInit).</summary>
    public IReadOnlyList<string> MechTypes { get; init; } = [];

    /// <summary>The embedded mech token (e.g. NTLMSSP blob), if present.</summary>
    public byte[]? MechToken { get; init; }

    /// <summary>The mechanism the server selected (<c>supportedMech</c> [1] of a NegTokenResp), if present.</summary>
    public string? SupportedMech { get; init; }

    /// <summary>negState for NegTokenResp (0=accept-completed, 1=accept-incomplete, 2=reject, 3=request-mic).</summary>
    public int? NegState { get; init; }

    /// <summary>
    /// The SPNEGO <c>mechListMIC</c> ([3] of a NegTokenResp), if present. This is the client's
    /// GSS_getMIC over the <c>MechTypeList</c> it sent; verifying it detects a mechanism-list downgrade
    /// (RFC 4178 §5). Currently surfaced for diagnostics/future enforcement only — see
    /// docs/SECURITY_AUDIT.md finding O8.
    /// </summary>
    public byte[]? MechListMic { get; init; }

    /// <summary>True if the token was a NegTokenResp (follow-up token); otherwise NegTokenInit.</summary>
    public bool IsResponseToken { get; init; }
}

/// <summary>
/// Encoding/decoding of SPNEGO tokens (RFC 4178, MS-SPNG) via ASN.1 DER. Used by the negotiator
/// (Context §9). Covers the set needed for SMB: server-side NegTokenInit2 (NEGOTIATE response) and
/// parsing of the client tokens (NegTokenInit / NegTokenResp).
/// </summary>
public static class SpnegoTokens
{
    // SPNEGO negState "accept-incomplete" (more steps needed).
    public const int NegStateAcceptCompleted = 0;
    public const int NegStateAcceptIncomplete = 1;
    public const int NegStateReject = 2;

    // Default hint, the same one Windows uses.
    private const string DefaultHintName = "not_defined_in_RFC4178@please_ignore";

    private static readonly Asn1Tag ContextTag0 = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag ContextTag1 = new(TagClass.ContextSpecific, 1);
    private static readonly Asn1Tag ContextTag2 = new(TagClass.ContextSpecific, 2);
    private static readonly Asn1Tag ContextTag3 = new(TagClass.ContextSpecific, 3);
    private static readonly Asn1Tag ApplicationTag0 = new(TagClass.Application, 0, isConstructed: true);

    /// <summary>
    /// Builds the server-initial NegTokenInit2 (Context §9.2). Structure:
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
                        // GeneralString (Universal 27) — the BCL AsnWriter API cannot write this
                        // string type directly; therefore encode the TLV by hand and insert it as a
                        // ready-made value.
                        writer.WriteEncodedValue(EncodeGeneralString(hintName));
                    }
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// Builds a client-style NegTokenInit (Context §9.2): <c>[APPLICATION 0] { SPNEGO-OID,
    /// [0] NegTokenInit { mechTypes [0], mechToken [2] } }</c>. This is the initial token a client sends
    /// (offered mechanisms in preference order plus an optimistic mech token). Symmetric to
    /// <see cref="CreateNegTokenInit2"/> (the server-initial token); useful for client-side and tests.
    /// </summary>
    public static byte[] CreateNegTokenInit(IReadOnlyList<string> mechTypes, byte[]? mechToken = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence(ApplicationTag0))
        {
            writer.WriteObjectIdentifier(GssOids.Spnego);

            using (writer.PushSequence(ContextTag0)) // innerContextToken [0] NegTokenInit
            using (writer.PushSequence())            // NegTokenInit ::= SEQUENCE
            {
                using (writer.PushSequence(ContextTag0)) // mechTypes [0] MechTypeList
                using (writer.PushSequence())
                {
                    foreach (string oid in mechTypes)
                        writer.WriteObjectIdentifier(oid);
                }

                if (mechToken is not null)
                    using (writer.PushSequence(ContextTag2)) // mechToken [2] OCTET STRING
                        writer.WriteOctetString(mechToken);
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// Builds a NegTokenResp (server→client follow-up token), e.g. with <c>responseToken</c>
    /// (= NTLM CHALLENGE_MESSAGE) and negState <c>accept-incomplete</c>.
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

    /// <summary>Encodes an ASCII string as a DER GeneralString TLV (tag 0x1B).</summary>
    private static byte[] EncodeGeneralString(string value)
    {
        byte[] content = System.Text.Encoding.ASCII.GetBytes(value);
        if (content.Length < 0x80)
        {
            var tlv = new byte[2 + content.Length];
            tlv[0] = 0x1B;                  // [UNIVERSAL 27] GeneralString, primitive
            tlv[1] = (byte)content.Length;  // short length form
            content.CopyTo(tlv, 2);
            return tlv;
        }

        // Long length form (for long hints — not needed in practice).
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
    /// Parses an incoming SPNEGO token: NegTokenInit (GSSAPI app tag) or NegTokenResp.
    /// Returns the mech OIDs and/or the embedded mech token.
    /// </summary>
    public static SpnegoParseResult Parse(ReadOnlySpan<byte> token)
    {
        var reader = new AsnReader(token.ToArray(), AsnEncodingRules.DER);
        Asn1Tag tag = reader.PeekTag();

        if (tag.TagClass == TagClass.Application && tag.TagValue == 0)
            return ParseNegTokenInit(reader);

        if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 1)
            return ParseNegTokenResp(reader);

        throw new FormatException($"Unexpected SPNEGO top-level tag {tag.TagClass}/{tag.TagValue}.");
    }

    private static SpnegoParseResult ParseNegTokenInit(AsnReader reader)
    {
        AsnReader app = reader.ReadSequence(ApplicationTag0);
        string oid = app.ReadObjectIdentifier();
        if (oid != GssOids.Spnego)
            throw new FormatException($"Expected SPNEGO OID, found {oid}.");

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
        string? supportedMech = null;
        byte[]? responseToken = null;
        byte[]? mechListMic = null;

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
                case 1: // supportedMech [1] OBJECT IDENTIFIER
                    supportedMech = resp.ReadSequence(ContextTag1).ReadObjectIdentifier();
                    break;
                case 2: // responseToken [2] OCTET STRING
                    responseToken = resp.ReadSequence(ContextTag2).ReadOctetString();
                    break;
                case 3: // mechListMIC [3] OCTET STRING — surfaced for O8 (downgrade detection), not yet enforced
                    mechListMic = resp.ReadSequence(ContextTag3).ReadOctetString();
                    break;
                default:
                    resp.ReadEncodedValue();
                    break;
            }
        }

        return new SpnegoParseResult
        {
            MechToken = responseToken,
            SupportedMech = supportedMech,
            NegState = negState,
            MechListMic = mechListMic,
            IsResponseToken = true,
        };
    }
}
