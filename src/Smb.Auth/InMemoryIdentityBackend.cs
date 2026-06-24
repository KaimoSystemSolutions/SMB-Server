using System.Collections.Concurrent;
using Smb.Crypto;

namespace Smb.Auth;

/// <summary>
/// Einfache lokale Benutzer-/Hash-Datenbank hinter <see cref="IIdentityBackend"/>
/// (Context §9.3: "lokale User-/Hash-DB" für Standalone-Betrieb). Später durch ein
/// LDAP/AD-Backend ersetzbar, ohne die SMB- oder Auth-Schicht zu ändern.
/// </summary>
public sealed class InMemoryIdentityBackend : IIdentityBackend
{
    private readonly ConcurrentDictionary<string, UserEntry> _users = new(StringComparer.OrdinalIgnoreCase);

    private sealed record UserEntry(string Domain, string User, byte[] NtHash, SecurityIdentity Identity);

    /// <summary>Fügt einen Benutzer mit Klartext-Passwort hinzu (NT-Hash wird berechnet).</summary>
    public InMemoryIdentityBackend AddUser(string domain, string user, string password,
        string? userSid = null, IReadOnlyList<string>? groupSids = null)
        => AddUserWithHash(domain, user, NtlmCryptography.NtHash(password), userSid, groupSids);

    /// <summary>Fügt einen Benutzer mit bereits berechnetem NT-Hash hinzu.</summary>
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
            : throw new KeyNotFoundException($"Unbekannter Benutzer {domain}\\{user}.");

    /// <summary>
    /// Sucht einen Benutzer: zuerst exakt nach <c>Domain\User</c>, dann (Fallback) nur nach dem
    /// Benutzernamen. Standalone-Server behandeln die Domain nicht als Sicherheitsgrenze, daher
    /// dürfen Clients sie leer lassen oder eine beliebige (z.B. die Workgroup) senden. Die
    /// kryptografische NTProofStr-Prüfung bleibt davon unberührt (sie nutzt die vom Client
    /// gesendete Domain konsistent).
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
