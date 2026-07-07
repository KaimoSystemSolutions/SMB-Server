using System.Net;
using System.Net.Sockets;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>NETWORK_INTERFACE_INFO capability flags (MS-SMB2 §2.2.32.5).</summary>
[Flags]
public enum NetworkInterfaceCapability : uint
{
    None = 0x00000000,
    RssCapable = 0x00000001,
    RdmaCapable = 0x00000002,
}

/// <summary>One server network interface for FSCTL_QUERY_NETWORK_INTERFACE_INFO (MS-SMB2 §2.2.32.5).</summary>
public readonly record struct NetworkInterfaceInfo(
    uint IfIndex,
    NetworkInterfaceCapability Capability,
    ulong LinkSpeedBitsPerSecond,
    IPAddress Address);

/// <summary>
/// FSCTL_QUERY_NETWORK_INTERFACE_INFO response (MS-SMB2 §2.2.31.5 request has no body; §2.2.32.5
/// response is a chained array of 152-byte <c>NETWORK_INTERFACE_INFO</c> structures). The client uses
/// it to discover additional server interfaces to open extra channels on (multichannel).
/// </summary>
public static class NetworkInterfaceInfoMessage
{
    /// <summary>FSCTL_QUERY_NETWORK_INTERFACE_INFO control code.</summary>
    public const uint FsctlQueryNetworkInterfaceInfo = 0x001401FC;

    /// <summary>Size of a single NETWORK_INTERFACE_INFO entry: 4+4+4+4+8 header + 128 SOCKADDR_STORAGE.</summary>
    public const int EntrySize = 152;

    private const int SockAddrStorageSize = 128;
    private const ushort AddressFamilyInet = 0x0002;   // AF_INET
    private const ushort AddressFamilyInet6 = 0x0017;  // AF_INET6 (Windows numbering, 23)

    /// <summary>
    /// Serializes the interface list as a chained NETWORK_INTERFACE_INFO array. <c>Next</c> is the byte
    /// offset from the start of an entry to the following one (0 on the last). An empty list produces an
    /// empty buffer.
    /// </summary>
    public static byte[] Build(IReadOnlyList<NetworkInterfaceInfo> interfaces)
    {
        var buffer = new byte[interfaces.Count * EntrySize];
        var w = new SpanWriter(buffer);
        for (int i = 0; i < interfaces.Count; i++)
        {
            NetworkInterfaceInfo ni = interfaces[i];
            bool last = i == interfaces.Count - 1;

            w.WriteUInt32(last ? 0u : (uint)EntrySize); // Next
            w.WriteUInt32(ni.IfIndex);                  // IfIndex
            w.WriteUInt32((uint)ni.Capability);         // Capability
            w.WriteUInt32(0);                           // Reserved
            w.WriteUInt64(ni.LinkSpeedBitsPerSecond);   // LinkSpeed
            WriteSockAddrStorage(ref w, ni.Address);    // SockAddr_Storage (128 bytes)
        }
        return buffer;
    }

    private static void WriteSockAddrStorage(ref SpanWriter w, IPAddress address)
    {
        int start = w.Position;
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            w.WriteUInt16(AddressFamilyInet6);          // ss_family
            w.WriteUInt16(0);                           // sin6_port
            w.WriteUInt32(0);                           // sin6_flowinfo
            w.WriteBytes(address.GetAddressBytes());    // sin6_addr (16)
            w.WriteUInt32((uint)address.ScopeId);       // sin6_scope_id
        }
        else
        {
            w.WriteUInt16(AddressFamilyInet);           // ss_family
            w.WriteUInt16(0);                           // sin_port
            w.WriteBytes(address.GetAddressBytes());    // sin_addr (4)
        }

        // Pad the remainder of the fixed 128-byte SOCKADDR_STORAGE.
        int written = w.Position - start;
        if (written < SockAddrStorageSize)
            w.WriteZeros(SockAddrStorageSize - written);
    }
}
