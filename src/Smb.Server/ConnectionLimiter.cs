namespace Smb.Server;

/// <summary>
/// Admission control for incoming connections (Phase 8 / M8.3): caps the total number of concurrent
/// connections and the number per client IP, so a single client (or a flood) cannot exhaust server
/// resources. Thread-safe. The host calls <see cref="TryAdmit"/> right after <c>accept</c> and
/// <see cref="Release"/> when the connection closes; a rejected connection is dropped immediately
/// without allocating any session state.
/// </summary>
public sealed class ConnectionLimiter
{
    private readonly int _globalMax;
    private readonly int _perClientMax;
    private readonly object _gate = new();
    private readonly Dictionary<string, int> _perClient = new(StringComparer.Ordinal);
    private int _total;

    /// <param name="globalMax">Maximum concurrent connections overall (≤ 0 = unlimited).</param>
    /// <param name="perClientMax">Maximum concurrent connections per client address (≤ 0 = unlimited).</param>
    public ConnectionLimiter(int globalMax, int perClientMax)
    {
        _globalMax = globalMax;
        _perClientMax = perClientMax;
    }

    /// <summary>Current total number of admitted (not yet released) connections.</summary>
    public int Total
    {
        get { lock (_gate) return _total; }
    }

    /// <summary>Current number of admitted connections from <paramref name="clientAddress"/>.</summary>
    public int CountFor(string clientAddress)
    {
        lock (_gate)
            return _perClient.TryGetValue(clientAddress, out int c) ? c : 0;
    }

    /// <summary>
    /// Atomically admits a connection from <paramref name="clientAddress"/> if it is within both the
    /// global and per-client limits, incrementing the counters. Returns false (nothing incremented)
    /// when a limit is reached — the caller should then close the socket immediately.
    /// </summary>
    public bool TryAdmit(string clientAddress)
    {
        lock (_gate)
        {
            if (_globalMax > 0 && _total >= _globalMax)
                return false;
            _perClient.TryGetValue(clientAddress, out int current);
            if (_perClientMax > 0 && current >= _perClientMax)
                return false;
            _total++;
            _perClient[clientAddress] = current + 1;
            return true;
        }
    }

    /// <summary>Releases a previously admitted connection from <paramref name="clientAddress"/>.</summary>
    public void Release(string clientAddress)
    {
        lock (_gate)
        {
            if (_total > 0)
                _total--;
            if (_perClient.TryGetValue(clientAddress, out int current))
            {
                if (current <= 1)
                    _perClient.Remove(clientAddress);
                else
                    _perClient[clientAddress] = current - 1;
            }
        }
    }
}
