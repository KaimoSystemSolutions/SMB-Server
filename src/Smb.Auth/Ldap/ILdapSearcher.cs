using System.Text;

namespace Smb.Auth.Ldap;

/// <summary>LDAP search scope (RFC 4511 §4.5.1.2).</summary>
public enum LdapSearchScope
{
    /// <summary>The base object only.</summary>
    Base,
    /// <summary>Immediate children of the base object.</summary>
    OneLevel,
    /// <summary>The base object and its whole subtree.</summary>
    Subtree,
}

/// <summary>
/// A single directory entry returned by an <see cref="ILdapSearcher"/>. LDAP attributes are
/// multi-valued and may be binary (e.g. <c>objectSid</c>) or textual (e.g. <c>sAMAccountName</c>), so
/// values are held as raw bytes; the accessors decode UTF-8 on demand. Attribute-name lookups are
/// case-insensitive, matching LDAP semantics.
/// </summary>
public sealed class LdapEntry
{
    private readonly IReadOnlyDictionary<string, IReadOnlyList<byte[]>> _attributes;

    public LdapEntry(string distinguishedName, IReadOnlyDictionary<string, IReadOnlyList<byte[]>> attributes)
    {
        DistinguishedName = distinguishedName;
        _attributes = new Dictionary<string, IReadOnlyList<byte[]>>(attributes, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>The entry's distinguished name (e.g. <c>CN=Alice,OU=Users,DC=corp,DC=com</c>).</summary>
    public string DistinguishedName { get; }

    /// <summary>First raw value of an attribute, or <c>null</c> if absent/empty.</summary>
    public byte[]? GetBytes(string attribute)
        => _attributes.TryGetValue(attribute, out IReadOnlyList<byte[]>? v) && v.Count > 0 ? v[0] : null;

    /// <summary>All raw values of an attribute (empty if absent).</summary>
    public IReadOnlyList<byte[]> GetByteValues(string attribute)
        => _attributes.TryGetValue(attribute, out IReadOnlyList<byte[]>? v) ? v : [];

    /// <summary>First value of an attribute decoded as UTF-8, or <c>null</c> if absent/empty.</summary>
    public string? GetString(string attribute)
    {
        byte[]? v = GetBytes(attribute);
        return v is null ? null : Encoding.UTF8.GetString(v);
    }

    /// <summary>All values of an attribute decoded as UTF-8 (empty if absent).</summary>
    public IReadOnlyList<string> GetStrings(string attribute)
    {
        IReadOnlyList<byte[]> values = GetByteValues(attribute);
        if (values.Count == 0) return [];
        var result = new string[values.Count];
        for (int i = 0; i < values.Count; i++) result[i] = Encoding.UTF8.GetString(values[i]);
        return result;
    }
}

/// <summary>
/// <b>LDAP transport seam (M2.2).</b> The minimal directory-query surface the
/// <see cref="LdapIdentityBackend"/> depends on. Keeping it this small means the identity-resolution
/// logic is dependency-free and unit-testable against a fake directory, while the real network binding
/// (LDAP/LDAPS to a domain controller, connection reuse, credentials) lives in a separate, opt-in
/// implementation — e.g. one wrapping <c>System.DirectoryServices.Protocols</c>. A library user may
/// also implement this against any other directory source.
/// </summary>
public interface ILdapSearcher
{
    /// <summary>
    /// Runs a search and returns the matching entries. Implementations should surface connection/bind
    /// failures as exceptions; the backend treats <i>no matches</i> as "unknown user".
    /// </summary>
    IReadOnlyList<LdapEntry> Search(string baseDn, string filter, LdapSearchScope scope, IReadOnlyList<string> attributes);
}
