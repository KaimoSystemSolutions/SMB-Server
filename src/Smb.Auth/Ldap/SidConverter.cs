using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Smb.Auth.Ldap;

/// <summary>
/// Converts Windows security identifiers (SIDs) between their binary form (MS-DTYP §2.4.2.2, as stored
/// in the AD <c>objectSid</c> attribute) and the canonical string form <c>S-R-A-S0-S1-…</c>. Also
/// produces the byte-escaped form (<c>\HH\HH…</c>) required to match a binary SID in an LDAP search
/// filter. Pure and dependency-free — shared by the LDAP backend and (later) the ACL layer.
/// <para>
/// Binary layout: <c>Revision(1) · SubAuthorityCount(1) · IdentifierAuthority(6, big-endian) ·
/// SubAuthority[count](4 each, little-endian)</c>.
/// </para>
/// </summary>
public static class SidConverter
{
    private const byte SidRevision = 1;
    private const int MaxSubAuthorities = 15; // MS-DTYP: at most 15

    /// <summary>Parses a binary SID into its string form. Returns false on malformed input (never throws).</summary>
    public static bool TryToString(ReadOnlySpan<byte> binary, out string sid)
    {
        sid = string.Empty;
        if (binary.Length < 8) return false;

        byte revision = binary[0];
        int subCount = binary[1];
        if (subCount > MaxSubAuthorities) return false;
        if (binary.Length < 8 + 4 * subCount) return false;

        // IdentifierAuthority: 6 bytes big-endian.
        ulong authority = 0;
        for (int i = 2; i < 8; i++) authority = (authority << 8) | binary[i];

        var sb = new StringBuilder(16 + subCount * 11);
        sb.Append("S-").Append(revision).Append('-');
        if (authority <= uint.MaxValue)
            sb.Append(authority.ToString(CultureInfo.InvariantCulture));
        else
            sb.Append("0x").Append(authority.ToString("X12", CultureInfo.InvariantCulture));

        for (int i = 0; i < subCount; i++)
        {
            uint sub = BinaryPrimitives.ReadUInt32LittleEndian(binary.Slice(8 + 4 * i, 4));
            sb.Append('-').Append(sub.ToString(CultureInfo.InvariantCulture));
        }

        sid = sb.ToString();
        return true;
    }

    /// <summary>Parses a string SID (<c>S-1-5-…</c>) into its binary form. Returns false on malformed input.</summary>
    public static bool TryToBinary(string? sid, out byte[] binary)
    {
        binary = [];
        if (string.IsNullOrEmpty(sid)) return false;

        string[] parts = sid.Split('-');
        // "S", revision, authority, then 0..15 sub-authorities.
        if (parts.Length < 3 || !parts[0].Equals("S", StringComparison.OrdinalIgnoreCase)) return false;
        if (!byte.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out byte revision))
            return false;

        if (!TryParseAuthority(parts[2], out ulong authority)) return false;

        int subCount = parts.Length - 3;
        if (subCount > MaxSubAuthorities) return false;

        var subs = new uint[subCount];
        for (int i = 0; i < subCount; i++)
            if (!uint.TryParse(parts[3 + i], NumberStyles.Integer, CultureInfo.InvariantCulture, out subs[i]))
                return false;

        var result = new byte[8 + 4 * subCount];
        result[0] = revision;
        result[1] = (byte)subCount;
        for (int i = 0; i < 6; i++)                       // authority: big-endian into bytes 2..7
            result[7 - i] = (byte)((authority >> (8 * i)) & 0xFF);
        for (int i = 0; i < subCount; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8 + 4 * i, 4), subs[i]);

        binary = result;
        return true;
    }

    /// <summary>
    /// Escapes a binary SID as an LDAP filter assertion value (RFC 4515): each byte becomes <c>\HH</c>.
    /// Use in a filter such as <c>(objectSid=\01\05\00\00…)</c> for SID → account reverse lookups.
    /// </summary>
    public static string ToLdapFilterValue(ReadOnlySpan<byte> binary)
    {
        var sb = new StringBuilder(binary.Length * 3);
        foreach (byte b in binary)
            sb.Append('\\').Append(b.ToString("x2", CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    private static bool TryParseAuthority(string text, out ulong authority)
    {
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out authority);
        return ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out authority);
    }
}
