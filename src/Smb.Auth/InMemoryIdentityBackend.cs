using System.Collections.Concurrent;
using Smb.Crypto;

namespace Smb.Auth;

/// <summary>
/// Simple local user/hash database behind <see cref="IIdentityBackend"/>
/// (Context §9.3: "local user/hash DB" for standalone operation). Can later be replaced with an
/// LDAP/AD backend without changing the SMB or auth layer.
/// </summary>
public sealed class InMemoryIdentityBackend : IIdentityBackend
{
    private readonly ConcurrentDictionary<string, UserEntry> _users = new(StringComparer.OrdinalIgnoreCase);

    private sealed record UserEntry(string Domain, string User, byte[] NtHash, SecurityIdentity Identity);

    /// <summary>Adds a user with a clear-text password (the NT hash is computed).</summary>
    public InMemoryIdentityBackend AddUser(string domain, string user, string password,
        string? userSid = null, IReadOnlyList<string>? groupSids = null)
        => AddUserWithHash(domain, user, NtlmCryptography.NtHash(password), userSid, groupSids);

    /// <summary>Adds a user with an already-computed NT hash.</summary>
    public InMemoryIdentityBackend AddUserWithHash(string domain, string user, byte[] ntHash,
        string? userSid = null, IReadOnlyList<string>? groupSids = null)
    {
        var identity = new SecurityIdentity
        {
            DomainName = domain,
            UserName = user,
            UserSid = userSid,
            GroupSids = groupSids ?? [],
        };
        _users[Key(domain, user)] = new UserEntry(domain, user, ntHash, identity);
        return this;
    }

    public bool TryGetNtHash(string domain, string user, out byte[] ntHash)
    {
        if (TryFind(domain, user, out UserEntry? entry))
        {
            ntHash = entry.NtHash;
            return true;
        }
        ntHash = [];
        return false;
    }

    public SecurityIdentity Resolve(string domain, string user)
        => TryFind(domain, user, out UserEntry? entry)
            ? entry.Identity
            : throw new KeyNotFoundException($"Unknown user {domain}\\{user}.");

    /// <summary>
    /// Looks up a user: first exactly by <c>Domain\User</c>, then (fallback) by the user name only.
    /// Standalone servers do not treat the domain as a security boundary, so clients may leave it
    /// empty or send any value (e.g. the workgroup). The cryptographic NTProofStr check is
    /// unaffected by this (it uses the domain sent by the client consistently).
    /// </summary>
    private bool TryFind(string domain, string user, out UserEntry entry)
    {
        if (_users.TryGetValue(Key(domain, user), out entry!))
            return true;

        foreach (UserEntry candidate in _users.Values)
        {
            if (string.Equals(candidate.User, user, StringComparison.OrdinalIgnoreCase))
            {
                entry = candidate;
                return true;
            }
        }

        entry = null!;
        return false;
    }

    private static string Key(string domain, string user) => $"{domain}\\{user}";
}
