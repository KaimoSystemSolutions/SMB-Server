namespace Smb.Auth;

/// <summary>
/// Resolves between security identifiers (SIDs) and account names (Context §9, for ACL display in
/// Phase 3). Separate from <see cref="IIdentityBackend"/> because not every identity source can do
/// reverse lookups; a backend that can (e.g. <see cref="Ldap.LdapIdentityBackend"/>) implements both.
/// </summary>
public interface ISidResolver
{
    /// <summary>Resolves a string SID (<c>S-1-5-…</c>) to its account name (sAMAccountName). </summary>
    bool TryGetAccountName(string sid, out string accountName);

    /// <summary>Resolves an account name (sAMAccountName) to its string SID.</summary>
    bool TryGetSid(string accountName, out string sid);
}
