namespace Smb.Auth.Ldap;

/// <summary>
/// Small thread-safe time-to-live cache used by <see cref="LdapIdentityBackend"/> to avoid re-querying
/// the directory for every request. A <see cref="TimeProvider"/> supplies the clock so expiry is
/// deterministically testable. A non-positive TTL disables caching (the factory runs every time).
/// Exceptions thrown by the factory propagate and are not cached (no negative caching).
/// </summary>
internal sealed class TtlCache<TKey, TValue> where TKey : notnull
{
    private readonly Dictionary<TKey, Entry> _map;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _ttl;
    private readonly object _gate = new();

    public TtlCache(TimeSpan ttl, TimeProvider clock, IEqualityComparer<TKey>? comparer = null)
    {
        _ttl = ttl;
        _clock = clock;
        _map = new Dictionary<TKey, Entry>(comparer);
    }

    private readonly record struct Entry(TValue Value, DateTimeOffset Expiry);

    /// <summary>Returns the cached value if still fresh, otherwise runs <paramref name="factory"/> and caches it.</summary>
    public TValue GetOrAdd(TKey key, Func<TValue> factory)
    {
        if (_ttl <= TimeSpan.Zero) return factory();

        DateTimeOffset now = _clock.GetUtcNow();
        lock (_gate)
        {
            if (_map.TryGetValue(key, out Entry e) && e.Expiry > now)
                return e.Value;
        }

        TValue value = factory();   // outside the lock: the factory may do I/O

        lock (_gate)
            _map[key] = new Entry(value, now + _ttl);
        return value;
    }

    /// <summary>Removes all entries (e.g. on a directory-change signal).</summary>
    public void Clear()
    {
        lock (_gate) _map.Clear();
    }
}
