using System.Globalization;

namespace Smb.Auth.Ldap;

/// <summary>
/// <see cref="IIdentityBackend"/> backed by an LDAP directory / Active Directory (M2.2). Resolves a
/// <c>Domain\User</c> to a full <see cref="SecurityIdentity"/> — primary SID, transitive group SIDs and
/// UPN — by querying the directory through the injected <see cref="ILdapSearcher"/>. The searcher owns
/// the network binding (LDAP/LDAPS, credentials), so this backend is transport-agnostic and testable.
/// <para>
/// <b>NTLM note:</b> <see cref="TryGetNtHash"/> always returns <c>false</c> — Active Directory does not
/// expose NT password hashes over LDAP. NTLM verification against a real domain must go through Kerberos
/// or a Netlogon secure channel; this backend provides <i>identity resolution</i> (for authorization and
/// display), typically alongside Kerberos authentication (M2.1).
/// </para>
/// </summary>
public sealed class LdapIdentityBackend : IIdentityBackend, ISidResolver
{
    private readonly ILdapSearcher _searcher;
    private readonly LdapIdentityBackendOptions _options;
    private readonly TtlCache<string, SecurityIdentity> _identityCache;
    private readonly TtlCache<string, string> _accountBySidCache;
    private readonly TtlCache<string, string> _sidByAccountCache;

    public LdapIdentityBackend(ILdapSearcher searcher, LdapIdentityBackendOptions options, TimeProvider? timeProvider = null)
    {
        _searcher = searcher ?? throw new ArgumentNullException(nameof(searcher));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        if (string.IsNullOrWhiteSpace(_options.SearchBase))
            throw new ArgumentException("SearchBase is required.", nameof(options));

        TimeProvider clock = timeProvider ?? TimeProvider.System;
        _identityCache = new TtlCache<string, SecurityIdentity>(_options.CacheTtl, clock, StringComparer.OrdinalIgnoreCase);
        _accountBySidCache = new TtlCache<string, string>(_options.CacheTtl, clock, StringComparer.OrdinalIgnoreCase);
        _sidByAccountCache = new TtlCache<string, string>(_options.CacheTtl, clock, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Drops all cached identities and SID/name lookups (e.g. after a directory change).</summary>
    public void ClearCache()
    {
        _identityCache.Clear();
        _accountBySidCache.Clear();
        _sidByAccountCache.Clear();
    }

    /// <summary>
    /// Not supported: AD does not surface NT hashes over LDAP. Always returns <c>false</c> so callers
    /// fall back to Kerberos (or another NTLM verifier) — see the type remarks.
    /// </summary>
    public bool TryGetNtHash(string domain, string user, out byte[] ntHash)
    {
        ntHash = [];
        return false;
    }

    /// <summary>
    /// Resolves <paramref name="user"/> in <paramref name="domain"/> to a full identity. Throws
    /// <see cref="KeyNotFoundException"/> when the account is not found (same contract as
    /// <see cref="InMemoryIdentityBackend"/>).
    /// </summary>
    public SecurityIdentity Resolve(string domain, string user)
        => _identityCache.GetOrAdd($"{domain}\\{user}", () => ResolveUncached(domain, user));

    private SecurityIdentity ResolveUncached(string domain, string user)
    {
        LdapEntry entry = FindUser(user)
            ?? throw new KeyNotFoundException($"Unknown user {domain}\\{user}.");

        string? userSid = null;
        byte[]? sidBytes = entry.GetBytes(_options.ObjectSidAttribute);
        if (sidBytes is not null && SidConverter.TryToString(sidBytes, out string parsed))
            userSid = parsed;

        string userName = entry.GetString(_options.SamAccountNameAttribute) ?? user;
        string? upn = entry.GetString(_options.UserPrincipalNameAttribute);

        return new SecurityIdentity
        {
            DomainName = domain,
            UserName = userName,
            UserSid = userSid,
            UserPrincipalName = upn,
            GroupSids = ResolveGroupSids(entry),
        };
    }

    /// <summary>Resolves a SID to its sAMAccountName via an <c>objectSid</c> filter (cached).</summary>
    public bool TryGetAccountName(string sid, out string accountName)
    {
        accountName = string.Empty;
        if (!SidConverter.TryToBinary(sid, out byte[] binary)) return false;

        string? name = _accountBySidCache.GetOrAdd(sid, () =>
        {
            string filter = string.Format(
                CultureInfo.InvariantCulture, _options.ObjectBySidFilterFormat, SidConverter.ToLdapFilterValue(binary));
            IReadOnlyList<LdapEntry> hits = _searcher.Search(
                _options.SearchBase, filter, LdapSearchScope.Subtree, [_options.SamAccountNameAttribute]);
            return hits.Count > 0 ? hits[0].GetString(_options.SamAccountNameAttribute) ?? string.Empty : string.Empty;
        });

        if (string.IsNullOrEmpty(name)) return false;
        accountName = name;
        return true;
    }

    /// <summary>Resolves a sAMAccountName to its string SID (cached).</summary>
    public bool TryGetSid(string accountName, out string sid)
    {
        sid = string.Empty;
        string? found = _sidByAccountCache.GetOrAdd(accountName, () =>
        {
            LdapEntry? entry = FindUser(accountName);
            byte[]? sidBytes = entry?.GetBytes(_options.ObjectSidAttribute);
            return sidBytes is not null && SidConverter.TryToString(sidBytes, out string s) ? s : string.Empty;
        });

        if (string.IsNullOrEmpty(found)) return false;
        sid = found;
        return true;
    }

    private LdapEntry? FindUser(string user)
    {
        string filter = string.Format(
            CultureInfo.InvariantCulture, _options.UserByNameFilterFormat, LdapFilter.Escape(user));

        // memberOf is a normal attribute returned by the subtree search; tokenGroups is a *constructed*
        // attribute AD only returns for a Base-scope read of the user object (fetched separately below).
        string[] attributes = _options.UseTokenGroups
            ? [_options.SamAccountNameAttribute, _options.ObjectSidAttribute, _options.UserPrincipalNameAttribute]
            : [_options.SamAccountNameAttribute, _options.ObjectSidAttribute, _options.UserPrincipalNameAttribute, _options.MemberOfAttribute];

        IReadOnlyList<LdapEntry> hits = _searcher.Search(
            _options.SearchBase, filter, LdapSearchScope.Subtree, attributes);
        return hits.Count > 0 ? hits[0] : null;
    }

    private IReadOnlyList<string> ResolveGroupSids(LdapEntry entry)
    {
        if (_options.UseTokenGroups)
            return ReadTokenGroups(entry.DistinguishedName);

        // Fallback: memberOf yields group DNs; look up each group's objectSid.
        var result = new List<string>();
        foreach (string dn in entry.GetStrings(_options.MemberOfAttribute))
        {
            string? sid = LookupSidByDn(dn);
            if (sid is not null) result.Add(sid);
        }
        return result;
    }

    /// <summary>
    /// Reads the transitive group SIDs from the user object's <c>tokenGroups</c> — a constructed
    /// attribute that requires a Base-scope read of the user DN (it is empty on a subtree search). Each
    /// value is a binary SID and already includes nested and primary-group memberships.
    /// </summary>
    private IReadOnlyList<string> ReadTokenGroups(string userDn)
    {
        IReadOnlyList<LdapEntry> hits = _searcher.Search(
            userDn, "(objectClass=*)", LdapSearchScope.Base, [_options.TokenGroupsAttribute]);
        if (hits.Count == 0) return [];

        var sids = new List<string>();
        foreach (byte[] raw in hits[0].GetByteValues(_options.TokenGroupsAttribute))
            if (SidConverter.TryToString(raw, out string sid))
                sids.Add(sid);
        return sids;
    }

    private string? LookupSidByDn(string distinguishedName)
    {
        IReadOnlyList<LdapEntry> hits = _searcher.Search(
            distinguishedName, "(objectClass=*)", LdapSearchScope.Base, [_options.ObjectSidAttribute]);
        if (hits.Count == 0) return null;
        byte[]? sidBytes = hits[0].GetBytes(_options.ObjectSidAttribute);
        return sidBytes is not null && SidConverter.TryToString(sidBytes, out string sid) ? sid : null;
    }
}
