using System.Collections.Concurrent;
using Smb.Protocol.Enums;

namespace Smb.Server.Diagnostics;

/// <summary>
/// [D1] Per-command tracing scope (Phase D / D1). Returned by
/// <see cref="SmbServerMetrics.BeginCommand"/> at the start of a dispatched SMB2 command and disposed
/// when it completes. A diagnostics bridge (e.g. OpenTelemetry) wraps an <c>Activity</c> in it; the core
/// server never creates one (the base hook returns <c>null</c>), so there is no tracing dependency in core.
/// </summary>
public interface ISmbCommandTrace : IDisposable
{
    /// <summary>Records the command's resulting NT status (called once, just before <see cref="IDisposable.Dispose"/>).</summary>
    void SetStatus(NtStatus status);
}

/// <summary>
/// Server health &amp; performance counters (Phase 8 / M8.5). Thread-safe, lock-free (Interlocked) and
/// dependency-free — the server increments them at the relevant points and a consumer reads a
/// <see cref="Snapshot"/> for a health endpoint or bridges it to <c>System.Diagnostics.Metrics</c> /
/// OpenTelemetry. Always on (the counters are cheap); replace with a subclass to fan out live.
/// </summary>
public class SmbServerMetrics
{
    private long _connectionsAccepted;
    private long _authSuccess;
    private long _authFailure;
    private long _requestCount;
    private long _bytesRead;
    private long _bytesWritten;
    private long _lockContention;

    private long _activeConnections;
    private long _activeSessions;
    private long _activeTreeConnects;
    private long _openHandles;

    private readonly ConcurrentDictionary<string, long[]> _perShareBytes = new(StringComparer.OrdinalIgnoreCase);
    private readonly LatencyHistogram _latency = new();

    // --- monotonic counters ---
    public long ConnectionsAccepted => Interlocked.Read(ref _connectionsAccepted);
    public long AuthenticationSuccesses => Interlocked.Read(ref _authSuccess);
    public long AuthenticationFailures => Interlocked.Read(ref _authFailure);
    public long RequestCount => Interlocked.Read(ref _requestCount);
    public long BytesRead => Interlocked.Read(ref _bytesRead);
    public long BytesWritten => Interlocked.Read(ref _bytesWritten);
    public long LockContentionCount => Interlocked.Read(ref _lockContention);

    // --- gauges ---
    public long ActiveConnections => Interlocked.Read(ref _activeConnections);
    public long ActiveSessions => Interlocked.Read(ref _activeSessions);
    public long ActiveTreeConnects => Interlocked.Read(ref _activeTreeConnects);
    public long OpenHandles => Interlocked.Read(ref _openHandles);

    // --- mutation (called by the server internals; harmless if a consumer calls them) ---
    public virtual void OnConnectionAccepted() { Interlocked.Increment(ref _connectionsAccepted); Interlocked.Increment(ref _activeConnections); }
    public virtual void OnConnectionClosed() => Interlocked.Decrement(ref _activeConnections);
    public virtual void OnAuthenticationSucceeded() { Interlocked.Increment(ref _authSuccess); Interlocked.Increment(ref _activeSessions); }
    public virtual void OnAuthenticationFailed() => Interlocked.Increment(ref _authFailure);
    public virtual void OnSessionClosed() => Interlocked.Decrement(ref _activeSessions);
    public virtual void OnTreeConnected() => Interlocked.Increment(ref _activeTreeConnects);
    public virtual void OnTreeDisconnected() => Interlocked.Decrement(ref _activeTreeConnects);
    public virtual void OnHandleOpened() => Interlocked.Increment(ref _openHandles);
    public virtual void OnHandleClosed() => Interlocked.Decrement(ref _openHandles);
    public virtual void OnLockContention() => Interlocked.Increment(ref _lockContention);

    public virtual void OnRequestCompleted(double milliseconds)
    {
        Interlocked.Increment(ref _requestCount);
        _latency.Record(milliseconds);
    }

    /// <summary>
    /// [D1] Begins a tracing scope for a single dispatched SMB2 command (Phase D / D1). Called before the
    /// command is handled; the returned scope (if any) receives the resulting status via
    /// <see cref="ISmbCommandTrace.SetStatus"/> and is disposed on completion. The base implementation
    /// returns <c>null</c> (no tracing) so core stays free of any OpenTelemetry/Activity dependency — the
    /// <c>Smb.Server.OpenTelemetry</c> bridge overrides it to emit an <c>Activity</c> span and per-op metric.
    /// </summary>
    public virtual ISmbCommandTrace? BeginCommand(SmbCommand command) => null;

    public virtual void OnBytesRead(string share, long count)
    {
        Interlocked.Add(ref _bytesRead, count);
        Interlocked.Add(ref PerShare(share)[0], count);
    }

    public virtual void OnBytesWritten(string share, long count)
    {
        Interlocked.Add(ref _bytesWritten, count);
        Interlocked.Add(ref PerShare(share)[1], count);
    }

    /// <summary>Bytes {read, written} for <paramref name="share"/> since start.</summary>
    public (long Read, long Written) BytesForShare(string share)
        => _perShareBytes.TryGetValue(share, out long[]? v) ? (Interlocked.Read(ref v[0]), Interlocked.Read(ref v[1])) : (0, 0);

    private long[] PerShare(string share) => _perShareBytes.GetOrAdd(share, _ => new long[2]);

    /// <summary>An immutable point-in-time copy of all metrics.</summary>
    public MetricsSnapshot Snapshot()
    {
        var perShare = _perShareBytes.ToArray()
            .ToDictionary(kv => kv.Key, kv => (Interlocked.Read(ref kv.Value[0]), Interlocked.Read(ref kv.Value[1])));
        (double p50, double p95, double p99) = _latency.Percentiles();
        return new MetricsSnapshot
        {
            ConnectionsAccepted = ConnectionsAccepted,
            ActiveConnections = ActiveConnections,
            ActiveSessions = ActiveSessions,
            ActiveTreeConnects = ActiveTreeConnects,
            OpenHandles = OpenHandles,
            AuthenticationSuccesses = AuthenticationSuccesses,
            AuthenticationFailures = AuthenticationFailures,
            RequestCount = RequestCount,
            BytesRead = BytesRead,
            BytesWritten = BytesWritten,
            LockContentionCount = LockContentionCount,
            RequestLatencyP50Ms = p50,
            RequestLatencyP95Ms = p95,
            RequestLatencyP99Ms = p99,
            BytesPerShare = perShare,
        };
    }
}

/// <summary>An immutable snapshot of <see cref="SmbServerMetrics"/> (Phase 8 / M8.5).</summary>
public sealed record MetricsSnapshot
{
    public long ConnectionsAccepted { get; init; }
    public long ActiveConnections { get; init; }
    public long ActiveSessions { get; init; }
    public long ActiveTreeConnects { get; init; }
    public long OpenHandles { get; init; }
    public long AuthenticationSuccesses { get; init; }
    public long AuthenticationFailures { get; init; }
    public long RequestCount { get; init; }
    public long BytesRead { get; init; }
    public long BytesWritten { get; init; }
    public long LockContentionCount { get; init; }
    public double RequestLatencyP50Ms { get; init; }
    public double RequestLatencyP95Ms { get; init; }
    public double RequestLatencyP99Ms { get; init; }
    public IReadOnlyDictionary<string, (long Read, long Written)> BytesPerShare { get; init; }
        = new Dictionary<string, (long, long)>();
}

/// <summary>
/// A fixed-bucket latency histogram giving approximate percentiles without storing samples. Bucket
/// upper bounds are in milliseconds; a value falls into the first bucket whose bound it does not exceed,
/// with an overflow bucket beyond the last bound. Percentiles return the crossing bucket's upper bound.
/// </summary>
internal sealed class LatencyHistogram
{
    private static readonly double[] Bounds = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
    private readonly long[] _buckets = new long[Bounds.Length + 1]; // +1 overflow

    public void Record(double milliseconds)
    {
        int i = 0;
        while (i < Bounds.Length && milliseconds > Bounds[i])
            i++;
        Interlocked.Increment(ref _buckets[i]);
    }

    public (double P50, double P95, double P99) Percentiles()
        => (Percentile(0.50), Percentile(0.95), Percentile(0.99));

    private double Percentile(double q)
    {
        long total = 0;
        for (int i = 0; i < _buckets.Length; i++)
            total += Interlocked.Read(ref _buckets[i]);
        if (total == 0)
            return 0;

        long threshold = (long)Math.Ceiling(q * total);
        long cumulative = 0;
        for (int i = 0; i < _buckets.Length; i++)
        {
            cumulative += Interlocked.Read(ref _buckets[i]);
            if (cumulative >= threshold)
                return i < Bounds.Length ? Bounds[i] : double.PositiveInfinity;
        }
        return double.PositiveInfinity;
    }
}
