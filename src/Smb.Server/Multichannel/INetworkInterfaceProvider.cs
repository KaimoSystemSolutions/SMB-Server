using Smb.Protocol.Messages;

namespace Smb.Server.Multichannel;

/// <summary>
/// Source of the server's network interfaces reported to clients via
/// FSCTL_QUERY_NETWORK_INTERFACE_INFO (multichannel, MS-SMB2 §3.3.5.15.4). Behind a seam so the core
/// stays testable (a fake list) and a deployment can advertise exactly the interfaces it wants (e.g.
/// only the fast NICs, or with RSS/RDMA capability flags it knows about).
/// </summary>
public interface INetworkInterfaceProvider
{
    /// <summary>The interfaces the client may open additional channels on. An empty list is valid.</summary>
    IReadOnlyList<NetworkInterfaceInfo> GetInterfaces();
}
