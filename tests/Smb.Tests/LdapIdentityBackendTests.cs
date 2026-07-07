using Smb.Auth;
using Smb.Auth.Ldap;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 2 / M2.2 increment C — identity resolution against a fake directory. Proves the mapping logic
/// (objectSid, group SIDs, UPN → <see cref="SecurityIdentity"/>) without any real LDAP dependency.
/// </summary>
public class LdapIdentityBackendTests
{
    private const string Base = "DC=corp,DC=example,DC=com";

    [Fact]
    public void Resolve_MapsSidUpnAndTokenGroups()
    {
        byte[] userSid = Sid("S-1-5-21-1-2-3-1105");
        byte[] g1 = Sid("S-1-5-21-1-2-3-513");
        byte[] g2 = Sid("S-1-5-32-544");

        var dir = new FakeLdapSearcher();
        dir.AddEntry("CN=Alice,OU=Users," + Base, e =>
        {
            e["sAMAccountName"] = Utf8("alice");
            e["userPrincipalName"] = Utf8("alice@corp.example.com");
            e["objectSid"] = userSid;
            e.AddBinary("tokenGroups", g1);
            e.AddBinary("tokenGroups", g2);
        });

        var backend = new LdapIdentityBackend(dir, new LdapIdentityBackendOptions { SearchBase = Base });
        SecurityIdentity id = backend.Resolve("CORP", "alice");

        Assert.Equal("CORP", id.DomainName);
        Assert.Equal("alice", id.UserName);
        Assert.Equal("alice@corp.example.com", id.UserPrincipalName);
        Assert.Equal("S-1-5-21-1-2-3-1105", id.UserSid);
        Assert.Equal(new[] { "S-1-5-21-1-2-3-513", "S-1-5-32-544" }, id.GroupSids);
    }

    [Fact]
    public void Resolve_UnknownUser_Throws()
    {
        var backend = new LdapIdentityBackend(new FakeLdapSearcher(), new LdapIdentityBackendOptions { SearchBase = Base });
        Assert.Throws<KeyNotFoundException>(() => backend.Resolve("CORP", "ghost"));
    }

    [Fact]
    public void Resolve_EscapesAccountNameInFilter()
    {
        var dir = new FakeLdapSearcher();
        var backend = new LdapIdentityBackend(dir, new LdapIdentityBackendOptions { SearchBase = Base });

        Assert.Throws<KeyNotFoundException>(() => backend.Resolve("CORP", "a)(b*"));

        // The injection characters must have been escaped in the emitted filter (RFC 4515).
        Assert.Contains(dir.LastFilter, f => f.Contains("a\\29\\28b\\2a"));
        Assert.DoesNotContain(dir.LastFilter, f => f.Contains("a)(b*"));
    }

    [Fact]
    public void Resolve_MemberOfFallback_LooksUpEachGroupSid()
    {
        var dir = new FakeLdapSearcher();
        dir.AddEntry("CN=Bob,OU=Users," + Base, e =>
        {
            e["sAMAccountName"] = Utf8("bob");
            e["objectSid"] = Sid("S-1-5-21-9-9-9-1200");
            e.AddString("memberOf", "CN=Devs,OU=Groups," + Base);
        });
        dir.AddEntry("CN=Devs,OU=Groups," + Base, e => e["objectSid"] = Sid("S-1-5-21-9-9-9-2001"));

        var backend = new LdapIdentityBackend(dir, new LdapIdentityBackendOptions
        {
            SearchBase = Base,
            UseTokenGroups = false,
        });
        SecurityIdentity id = backend.Resolve("CORP", "bob");

        Assert.Equal(new[] { "S-1-5-21-9-9-9-2001" }, id.GroupSids);
    }

    [Fact]
    public void TryGetNtHash_AlwaysFalse()
    {
        var backend = new LdapIdentityBackend(new FakeLdapSearcher(), new LdapIdentityBackendOptions { SearchBase = Base });
        Assert.False(backend.TryGetNtHash("CORP", "alice", out byte[] hash));
        Assert.Empty(hash);
    }

    // --- increment D: caching + reverse lookup ---

    [Fact]
    public void Resolve_CachesWithinTtl_AndReQueriesAfterExpiry()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var dir = new FakeLdapSearcher();
        dir.AddEntry("CN=Alice," + Base, e => { e["sAMAccountName"] = Utf8("alice"); e["objectSid"] = Sid("S-1-5-21-1-2-3-1105"); });
        var backend = new LdapIdentityBackend(dir, new LdapIdentityBackendOptions
        {
            SearchBase = Base,
            CacheTtl = TimeSpan.FromMinutes(5),
            UseTokenGroups = false,   // 1 search per uncached resolve (isolates cache accounting)
        }, clock);

        backend.Resolve("CORP", "alice");
        backend.Resolve("CORP", "alice");
        Assert.Equal(1, dir.SearchCount);                 // second call served from cache

        clock.Advance(TimeSpan.FromMinutes(6));            // past the TTL
        backend.Resolve("CORP", "alice");
        Assert.Equal(2, dir.SearchCount);                 // re-queried
    }

    [Fact]
    public void CacheTtlZero_DisablesCaching()
    {
        var dir = new FakeLdapSearcher();
        dir.AddEntry("CN=Alice," + Base, e => { e["sAMAccountName"] = Utf8("alice"); e["objectSid"] = Sid("S-1-5-21-1-2-3-1105"); });
        var backend = new LdapIdentityBackend(dir, new LdapIdentityBackendOptions
        {
            SearchBase = Base,
            CacheTtl = TimeSpan.Zero,
            UseTokenGroups = false,
        });

        backend.Resolve("CORP", "alice");
        backend.Resolve("CORP", "alice");
        Assert.Equal(2, dir.SearchCount);
    }

    [Fact]
    public void ClearCache_ForcesReQuery()
    {
        var dir = new FakeLdapSearcher();
        dir.AddEntry("CN=Alice," + Base, e => { e["sAMAccountName"] = Utf8("alice"); e["objectSid"] = Sid("S-1-5-21-1-2-3-1105"); });
        var backend = new LdapIdentityBackend(dir, new LdapIdentityBackendOptions
        {
            SearchBase = Base,
            CacheTtl = TimeSpan.FromMinutes(5),
            UseTokenGroups = false,
        });

        backend.Resolve("CORP", "alice");
        backend.ClearCache();
        backend.Resolve("CORP", "alice");
        Assert.Equal(2, dir.SearchCount);
    }

    [Fact]
    public void SidResolver_ResolvesNameFromSid_AndSidFromName()
    {
        var dir = new FakeLdapSearcher();
        dir.AddEntry("CN=Alice," + Base, e => { e["sAMAccountName"] = Utf8("alice"); e["objectSid"] = Sid("S-1-5-21-1-2-3-1105"); });
        var backend = new LdapIdentityBackend(dir, new LdapIdentityBackendOptions { SearchBase = Base });

        Assert.True(backend.TryGetAccountName("S-1-5-21-1-2-3-1105", out string name));
        Assert.Equal("alice", name);

        Assert.True(backend.TryGetSid("alice", out string sid));
        Assert.Equal("S-1-5-21-1-2-3-1105", sid);

        Assert.False(backend.TryGetAccountName("S-1-5-21-9-9-9-9999", out _)); // unknown SID
        Assert.False(backend.TryGetAccountName("not-a-sid", out _));           // malformed
    }

    // --- fakes ---

    /// <summary>Manually-advanced <see cref="TimeProvider"/> for deterministic TTL tests.</summary>
    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _now;
        public ManualTimeProvider(DateTimeOffset start) => _now = start;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }

    private static byte[] Utf8(string s) => System.Text.Encoding.UTF8.GetBytes(s);
    private static byte[] Sid(string sid) { Assert.True(SidConverter.TryToBinary(sid, out byte[] b)); return b; }

    /// <summary>In-memory <see cref="ILdapSearcher"/> for tests: a Base lookup matches by DN, a Subtree
    /// search returns the entry whose account name appears (escaped) in the filter.</summary>
    private sealed class FakeLdapSearcher : ILdapSearcher
    {
        private readonly List<(string Dn, EntryBuilder Attrs)> _entries = new();
        public List<string> LastFilter { get; } = new();
        public int SearchCount { get; private set; }

        public void AddEntry(string dn, Action<EntryBuilder> build)
        {
            var b = new EntryBuilder();
            build(b);
            _entries.Add((dn, b));
        }

        public IReadOnlyList<LdapEntry> Search(string baseDn, string filter, LdapSearchScope scope, IReadOnlyList<string> attributes)
        {
            SearchCount++;
            LastFilter.Add(filter);
            if (scope == LdapSearchScope.Base)
            {
                foreach (var (dn, attrs) in _entries)
                    if (string.Equals(dn, baseDn, StringComparison.OrdinalIgnoreCase))
                        return [attrs.Build(dn)];
                return [];
            }

            // Subtree: match by escaped sAMAccountName or by escaped binary objectSid in the filter.
            foreach (var (dn, attrs) in _entries)
            {
                string? sam = attrs.SamAccountName;
                if (sam is not null && filter.Contains(LdapFilter.Escape(sam)))
                    return [attrs.Build(dn)];
                byte[]? sid = attrs.ObjectSid;
                if (sid is not null && filter.Contains(SidConverter.ToLdapFilterValue(sid)))
                    return [attrs.Build(dn)];
            }
            return [];
        }
    }

    private sealed class EntryBuilder
    {
        private readonly Dictionary<string, List<byte[]>> _attrs = new(StringComparer.OrdinalIgnoreCase);

        public byte[] this[string attr] { set => _attrs[attr] = new List<byte[]> { value }; }
        public void AddBinary(string attr, byte[] value) => Get(attr).Add(value);
        public void AddString(string attr, string value) => Get(attr).Add(System.Text.Encoding.UTF8.GetBytes(value));

        public string? SamAccountName =>
            _attrs.TryGetValue("sAMAccountName", out List<byte[]>? v) && v.Count > 0
                ? System.Text.Encoding.UTF8.GetString(v[0]) : null;

        public byte[]? ObjectSid =>
            _attrs.TryGetValue("objectSid", out List<byte[]>? v) && v.Count > 0 ? v[0] : null;

        private List<byte[]> Get(string attr)
        {
            if (!_attrs.TryGetValue(attr, out List<byte[]>? v)) _attrs[attr] = v = new List<byte[]>();
            return v;
        }

        public LdapEntry Build(string dn)
        {
            var map = new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in _attrs) map[kv.Key] = kv.Value;
            return new LdapEntry(dn, map);
        }
    }
}
