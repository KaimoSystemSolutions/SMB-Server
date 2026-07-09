using System.Net;
using Smb.Protocol.Discovery;

namespace Smb.Host;

/// <summary>
/// [M11.3] Configuration for the WS-Discovery responder (Windows Explorer network browsing). Kept in the
/// host layer alongside the UDP listener so <c>Smb.Server</c>/<c>Smb.Protocol</c> stay transport-agnostic.
/// </summary>
public sealed class WsDiscoveryOptions
{
    /// <summary>
    /// The stable device UUID advertised as the endpoint reference. Generated once per process by default;
    /// set it to a persisted value so the server keeps the same identity across restarts (recommended for
    /// production, so clients recognize it as the same device).
    /// </summary>
    public Guid EndpointId { get; set; } = Guid.NewGuid();

    /// <summary>The device types advertised and matched against probes. Default: <c>pub:Computer</c>.</summary>
    public IReadOnlyList<WsDiscoveryQName> Types { get; set; } = [WsDiscoveryQName.Computer];

    /// <summary>
    /// Transport addresses / metadata URLs where the device can be reached (the XAddrs of a ProbeMatch/Hello).
    /// Typically the server's host name or IP; when empty the responder still answers but advertises no address.
    /// </summary>
    public IReadOnlyList<string> XAddrs { get; set; } = [];

    /// <summary>The UDP port to bind (WS-Discovery well-known port 3702).</summary>
    public int Port { get; set; } = WsDiscoveryConstants.Port;

    /// <summary>The address to bind the UDP socket to (default: all interfaces).</summary>
    public IPAddress BindAddress { get; set; } = IPAddress.Any;

    /// <summary>
    /// Join the IPv4 multicast group 239.255.255.250 to receive multicast probes. Default true. Set false
    /// (e.g. in tests) to accept only directed/unicast probes on the bound port with no group membership.
    /// </summary>
    public bool JoinMulticast { get; set; } = true;

    /// <summary>Send a Hello announcement to the multicast group on start / Bye on stop. Default true.</summary>
    public bool AnnouncePresence { get; set; } = true;

    internal void Validate()
    {
        if (Port is < 0 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(Port), Port, "WS-Discovery port must be in [0, 65535].");
        ArgumentNullException.ThrowIfNull(Types);
        ArgumentNullException.ThrowIfNull(XAddrs);
        ArgumentNullException.ThrowIfNull(BindAddress);
    }

    internal WsDiscoveryResponder CreateResponder()
        => new(EndpointId, Types, XAddrs);
}
