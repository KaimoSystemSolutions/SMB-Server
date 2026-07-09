using System.Threading;

namespace Smb.Protocol.Discovery;

/// <summary>
/// Stateful (but socket-free) WS-Discovery responder: turns an inbound Probe datagram into a ProbeMatches
/// datagram advertising this server, and produces Hello/Bye presence announcements. Owns the WS-Discovery
/// sequencing state (a stable per-instance <c>InstanceId</c> and a monotonic <c>MessageNumber</c>) so every
/// emitted message has a well-defined order — no ambiguous state, which is what an enterprise client relies
/// on to reconcile duplicates and out-of-order multicast. Thread-safe.
/// </summary>
public sealed class WsDiscoveryResponder
{
    private readonly Guid _endpointId;
    private readonly IReadOnlyList<WsDiscoveryQName> _types;
    private readonly IReadOnlyList<string> _xAddrs;
    private readonly HashSet<string> _typeSet;
    private readonly ulong _instanceId;
    private long _messageNumber;

    /// <param name="endpointId">The stable device UUID advertised as the endpoint reference address (urn:uuid:…).</param>
    /// <param name="types">The device types this server advertises and matches probes against (default: pub:Computer).</param>
    /// <param name="xAddrs">Transport addresses / metadata URLs where the device can be reached.</param>
    /// <param name="instanceId">
    /// WS-Discovery AppSequence InstanceId — a value that MUST increase whenever the service restarts. Defaults
    /// to the current Unix time so a restart always yields a higher instance than the previous run.
    /// </param>
    public WsDiscoveryResponder(
        Guid endpointId,
        IReadOnlyList<WsDiscoveryQName>? types = null,
        IReadOnlyList<string>? xAddrs = null,
        ulong? instanceId = null)
    {
        _endpointId = endpointId;
        _types = types is { Count: > 0 } ? types : [WsDiscoveryQName.Computer];
        _xAddrs = xAddrs ?? [];
        _typeSet = new HashSet<string>(_types.Select(t => t.Clark), StringComparer.Ordinal);
        _instanceId = instanceId ?? (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    }

    /// <summary>The device UUID advertised by this responder.</summary>
    public Guid EndpointId => _endpointId;

    /// <summary>The AppSequence InstanceId used for every message from this responder instance.</summary>
    public ulong InstanceId => _instanceId;

    /// <summary>
    /// Produces a ProbeMatches reply for <paramref name="datagram"/>, or null when it is not a Probe or its
    /// requested types do not match this server. Never throws on malformed input — an unparseable datagram
    /// simply yields null (no reply), keeping receive-side behavior fully defined.
    /// </summary>
    public byte[]? TryCreateProbeMatch(ReadOnlySpan<byte> datagram)
    {
        if (!WsDiscoveryMessage.TryParseProbe(datagram, out WsDiscoveryProbe probe))
            return null;
        if (!Matches(probe))
            return null;

        return WsDiscoveryMessage.BuildProbeMatches(
            probe.MessageId, _endpointId, _types, _xAddrs, _instanceId, NextMessageNumber());
    }

    /// <summary>Builds a Hello announcement (emit on start and periodically).</summary>
    public byte[] CreateHello()
        => WsDiscoveryMessage.BuildHello(_endpointId, _types, _xAddrs, _instanceId, NextMessageNumber());

    /// <summary>Builds a Bye announcement (emit on graceful shutdown).</summary>
    public byte[] CreateBye()
        => WsDiscoveryMessage.BuildBye(_endpointId, _types, _xAddrs, _instanceId, NextMessageNumber());

    /// <summary>
    /// True when the probe should be answered: a type-less probe ("probe-all") always matches; otherwise at
    /// least one requested type must equal one of this server's advertised types (namespace-resolved).
    /// </summary>
    private bool Matches(WsDiscoveryProbe probe)
        => probe.Types.Count == 0 || probe.Types.Any(_typeSet.Contains);

    private ulong NextMessageNumber() => (ulong)Interlocked.Increment(ref _messageNumber);
}
