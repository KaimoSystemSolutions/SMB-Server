using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Security;

/// <summary>
/// A Windows security identifier (SID, MS-DTYP §2.4.2). Immutable value type with binary
/// (<c>objectSid</c> / security-descriptor) and canonical string (<c>S-R-A-S0-S1-…</c>) forms.
/// Binary layout: <c>Revision(1) · SubAuthorityCount(1) · IdentifierAuthority(6, big-endian) ·
/// SubAuthority[count](4 each, little-endian)</c>.
/// </summary>
public sealed class Sid : IEquatable<Sid>
{
    /// <summary>Maximum number of sub-authorities (MS-DTYP §2.4.2.1).</summary>
    public const int MaxSubAuthorities = 15;

    private const ulong MaxAuthority = 0xFFFF_FFFF_FFFF; // 48-bit

    private readonly uint[] _subAuthorities;

    /// <summary>Creates a revision-1 SID (the only revision in use).</summary>
    public static Sid Create(ulong identifierAuthority, params uint[] subAuthorities)
        => new(1, identifierAuthority, subAuthorities);

    public Sid(byte revision, ulong identifierAuthority, params uint[] subAuthorities)
    {
        ArgumentNullException.ThrowIfNull(subAuthorities);
        if (subAuthorities.Length > MaxSubAuthorities)
            throw new ArgumentException($"A SID has at most {MaxSubAuthorities} sub-authorities.", nameof(subAuthorities));
        if (identifierAuthority > MaxAuthority)
            throw new ArgumentOutOfRangeException(nameof(identifierAuthority), "IdentifierAuthority is a 48-bit value.");

        Revision = revision;
        IdentifierAuthority = identifierAuthority;
        _subAuthorities = (uint[])subAuthorities.Clone();
    }

    public byte Revision { get; }

    /// <summary>48-bit identifier authority (5 = NT authority for most SIDs).</summary>
    public ulong IdentifierAuthority { get; }

    public IReadOnlyList<uint> SubAuthorities => _subAuthorities;

    /// <summary>Size of the binary encoding in bytes.</summary>
    public int BinaryLength => 8 + 4 * _subAuthorities.Length;

    /// <summary>Parses a binary SID from the start of <paramref name="data"/>.</summary>
    public static Sid Parse(ReadOnlySpan<byte> data) => Parse(data, out _);

    /// <summary>Parses a binary SID and reports how many bytes it consumed (for chained structures).</summary>
    public static Sid Parse(ReadOnlySpan<byte> data, out int consumed)
    {
        if (data.Length < 8)
            throw new SmbWireFormatException($"SID too short: {data.Length} bytes.");

        byte revision = data[0];
        int subCount = data[1];
        if (subCount > MaxSubAuthorities)
            throw new SmbWireFormatException($"SID SubAuthorityCount {subCount} > {MaxSubAuthorities}.");

        int length = 8 + 4 * subCount;
        if (data.Length < length)
            throw new SmbWireFormatException($"SID needs {length} bytes, has {data.Length}.");

        ulong authority = 0;
        for (int i = 2; i < 8; i++) authority = (authority << 8) | data[i];

        var subs = new uint[subCount];
        for (int i = 0; i < subCount; i++)
            subs[i] = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8 + 4 * i, 4));

        consumed = length;
        return new Sid(revision, authority, subs);
    }

    /// <summary>Writes the binary SID via <paramref name="w"/>.</summary>
    public void Write(ref SpanWriter w)
    {
        w.WriteByte(Revision);
        w.WriteByte((byte)_subAuthorities.Length);
        for (int i = 5; i >= 0; i--)                       // 6-byte authority, big-endian
            w.WriteByte((byte)((IdentifierAuthority >> (8 * i)) & 0xFF));
        foreach (uint sub in _subAuthorities)
            w.WriteUInt32(sub);
    }

    /// <summary>Returns the binary SID as a new array.</summary>
    public byte[] ToBytes()
    {
        var bytes = new byte[BinaryLength];
        var w = new SpanWriter(bytes);
        Write(ref w);
        return bytes;
    }

    public override string ToString()
    {
        var sb = new StringBuilder(16 + _subAuthorities.Length * 11);
        sb.Append("S-").Append(Revision).Append('-');
        if (IdentifierAuthority <= uint.MaxValue)
            sb.Append(IdentifierAuthority.ToString(CultureInfo.InvariantCulture));
        else
            sb.Append("0x").Append(IdentifierAuthority.ToString("X12", CultureInfo.InvariantCulture));
        foreach (uint sub in _subAuthorities)
            sb.Append('-').Append(sub.ToString(CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    /// <summary>Parses a string SID (<c>S-1-5-…</c>). Throws <see cref="FormatException"/> on malformed input.</summary>
    public static Sid FromString(string sid)
        => TryParse(sid, out Sid? parsed) ? parsed : throw new FormatException($"Invalid SID string '{sid}'.");

    public static bool TryParse(string? sid, out Sid result)
    {
        result = null!;
        if (string.IsNullOrEmpty(sid)) return false;

        string[] parts = sid.Split('-');
        if (parts.Length < 3 || !parts[0].Equals("S", StringComparison.OrdinalIgnoreCase)) return false;
        if (!byte.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out byte revision)) return false;
        if (!TryParseAuthority(parts[2], out ulong authority)) return false;

        int subCount = parts.Length - 3;
        if (subCount > MaxSubAuthorities) return false;
        var subs = new uint[subCount];
        for (int i = 0; i < subCount; i++)
            if (!uint.TryParse(parts[3 + i], NumberStyles.Integer, CultureInfo.InvariantCulture, out subs[i]))
                return false;

        result = new Sid(revision, authority, subs);
        return true;
    }

    private static bool TryParseAuthority(string text, out ulong authority)
        => text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? ulong.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out authority)
            : ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out authority);

    public bool Equals(Sid? other)
        => other is not null
           && Revision == other.Revision
           && IdentifierAuthority == other.IdentifierAuthority
           && _subAuthorities.AsSpan().SequenceEqual(other._subAuthorities);

    public override bool Equals(object? obj) => Equals(obj as Sid);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Revision);
        hash.Add(IdentifierAuthority);
        foreach (uint sub in _subAuthorities) hash.Add(sub);
        return hash.ToHashCode();
    }

    public static bool operator ==(Sid? left, Sid? right) => left is null ? right is null : left.Equals(right);
    public static bool operator !=(Sid? left, Sid? right) => !(left == right);
}
