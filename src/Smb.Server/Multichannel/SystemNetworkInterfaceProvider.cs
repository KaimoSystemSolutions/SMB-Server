using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Smb.Protocol.Messages;

namespace Smb.Server.Multichannel;

/// <summary>
/// Default <see cref="INetworkInterfaceProvider"/>: enumerates the operational, non-loopback system
/// NICs via <see cref="NetworkInterface.GetAllNetworkInterfaces"/> and reports their unicast IPv4/IPv6
/// addresses and link speed. RSS/RDMA capabilities are not detectable through the managed API, so they
/// are reported as <see cref="NetworkInterfaceCapability.None"/>; a deployment that knows better can
/// supply its own provider.
/// </summary>
public sealed class SystemNetworkInterfaceProvider : INetworkInterfaceProvider
{
    // Fallback advertised speed when the driver reports an unknown (-1) or zero link speed (1 Gbit/s).
    private const ulong DefaultLinkSpeed = 1_000_000_000UL;

    public IReadOnlyList<NetworkInterfaceInfo> GetInterfaces()
    {
        var result = new List<NetworkInterfaceInfo>();
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up ||
                nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                continue;

            IPInterfaceProperties props = nic.GetIPProperties();
            ulong speed = nic.Speed > 0 ? (ulong)nic.Speed : DefaultLinkSpeed;

            foreach (UnicastIPAddressInformation ua in props.UnicastAddresses)
            {
                IPAddress ip = ua.Address;
                if (IPAddress.IsLoopback(ip))
                    continue;

                uint ifIndex = InterfaceIndex(props, ip.AddressFamily);
                result.Add(new NetworkInterfaceInfo(ifIndex, NetworkInterfaceCapability.None, speed, ip));
            }
        }
        return result;
    }

    private static uint InterfaceIndex(IPInterfaceProperties props, AddressFamily family)
    {
        try
        {
            return family == AddressFamily.InterNetworkV6
                ? (uint)props.GetIPv6Properties().Index
                : (uint)props.GetIPv4Properties().Index;
        }
        catch (NetworkInformationException)
        {
            return 0; // Interface has no properties for this family — index is informational only.
        }
    }
}
