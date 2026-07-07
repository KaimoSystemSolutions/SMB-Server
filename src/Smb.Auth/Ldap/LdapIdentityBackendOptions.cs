namespace Smb.Auth.Ldap;

/// <summary>
/// Configuration for <see cref="LdapIdentityBackend"/> (M2.2). Covers the search base, the attribute
/// and filter names used to locate users and their groups, and the identity cache TTL. Defaults target
/// Active Directory; override the names for other LDAP directories (OpenLDAP, 389-DS, …).
/// <para>
/// Connection details (domain-controller host, port, LDAPS, bind credentials) are intentionally
/// <b>not</b> here — they belong to the concrete <see cref="ILdapSearcher"/> so this backend stays
/// transport-agnostic.
/// </para>
/// </summary>
public sealed class LdapIdentityBackendOptions
{
    /// <summary>Search base DN, e.g. <c>DC=corp,DC=example,DC=com</c>. Required.</summary>
    public required string SearchBase { get; init; }

    /// <summary>
    /// Filter format for locating a user by account name (<c>{0}</c> = escaped sAMAccountName).
    /// </summary>
    public string UserByNameFilterFormat { get; init; } = "(&(objectClass=user)(sAMAccountName={0}))";

    /// <summary>Filter format for locating an object by SID (<c>{0}</c> = <c>\HH</c>-escaped binary SID).</summary>
    public string ObjectBySidFilterFormat { get; init; } = "(objectSid={0})";

    public string SamAccountNameAttribute { get; init; } = "sAMAccountName";
    public string ObjectSidAttribute { get; init; } = "objectSid";
    public string UserPrincipalNameAttribute { get; init; } = "userPrincipalName";

    /// <summary>
    /// Constructed AD attribute holding the <b>transitive</b> group SIDs of a user (the token groups).
    /// Preferred when available — it already includes nested and primary-group memberships.
    /// </summary>
    public string TokenGroupsAttribute { get; init; } = "tokenGroups";

    /// <summary>Fallback group attribute (DNs of direct groups) when <see cref="UseTokenGroups"/> is off.</summary>
    public string MemberOfAttribute { get; init; } = "memberOf";

    /// <summary>
    /// When true (AD default), read transitive group SIDs from <see cref="TokenGroupsAttribute"/>. When
    /// false, the backend resolves group SIDs from <see cref="MemberOfAttribute"/> DNs instead.
    /// </summary>
    public bool UseTokenGroups { get; init; } = true;

    /// <summary>How long a resolved identity is cached. <see cref="TimeSpan.Zero"/> disables caching.</summary>
    public TimeSpan CacheTtl { get; init; } = TimeSpan.FromMinutes(5);
}
