using System.Buffers.Binary;
using System.Text;
using Smb.Protocol.Wire;
using Smb.Server.Rpc;

namespace Smb.Server.Witness;

/// <summary>Witness (MS-SWN) RPC opnums for the <c>Witness</c> interface.</summary>
public enum WitnessOpnum : ushort
{
    GetInterfaceList = 0,
    Register = 1,
    UnRegister = 2,
    AsyncNotify = 3,
    RegisterEx = 4, // v2
}

/// <summary>Witness protocol versions (MS-SWN §2.2.2.1, the <c>Version</c> field of Register).</summary>
public static class WitnessVersion
{
    public const uint V1 = 0x00010001;
    public const uint V2 = 0x00020000;
}

/// <summary>Node/interface availability state (MS-SWN §2.2.2.3 <c>NodeState</c>).</summary>
public enum WitnessNodeState : ushort
{
    Unknown = 0x0000,
    Available = 0x0001,
    Unavailable = 0x00FF,
}

/// <summary>WITNESS_INTERFACE_INFO flags (MS-SWN §2.2.2.3 <c>Flags</c>).</summary>
[Flags]
public enum WitnessInterfaceFlags : uint
{
    None = 0,
    IPv4Valid = 0x00000001,
    IPv6Valid = 0x00000002,
    /// <summary>This interface is the one that provides the witness service (INTERFACE_WITNESS).</summary>
    InterfaceWitness = 0x00000004,
}

/// <summary>Async-notify message type (MS-SWN §2.2.2.6 <c>MessageType</c> of RESP_ASYNC_NOTIFY).</summary>
public enum WitnessNotifyType : uint
{
    ResourceChange = 1,
    ClientMove = 2,
    ShareMove = 3,
    IpChange = 4,
}

/// <summary>RESOURCE_CHANGE change type (MS-SWN §2.2.2.5 <c>ChangeType</c>).</summary>
public enum WitnessResourceChange : uint
{
    Unknown = 0x00000000,
    Available = 0x00000001,
    Unavailable = 0x000000FF,
}

/// <summary>WITNESS_IPADDR_INFO flags (MS-SWN §2.2.2.4 <c>Flags</c>) — carried by CLIENT_MOVE / SHARE_MOVE / IP_CHANGE.</summary>
[Flags]
public enum WitnessIpAddrFlags : uint
{
    None = 0,
    IPv4 = 0x00000001,
    IPv6 = 0x00000002,
    Online = 0x00000008,
    Offline = 0x00000010,
}

/// <summary>One WITNESS_IPADDR_INFO (MS-SWN §2.2.2.4): a destination/changed address for a move/IP-change message.</summary>
public sealed record WitnessIpAddr(WitnessIpAddrFlags Flags, uint IPv4, byte[]? IPv6 = null);

/// <summary>One witness interface advertised by <c>WitnessrGetInterfaceList</c>.</summary>
public sealed record WitnessInterfaceInfo(
    string InterfaceGroupName,
    uint Version,
    WitnessNodeState NodeState,
    uint IPv4,
    WitnessInterfaceFlags Flags);

/// <summary>Parsed arguments of a <c>WitnessrRegister</c> / <c>WitnessrRegisterEx</c> request stub.</summary>
public sealed record WitnessRegisterArgs(
    uint Version,
    string? NetName,
    string? ShareName,
    string? IpAddress,
    string? ClientComputerName,
    uint Flags,
    uint KeepAliveTimeoutSeconds);

/// <summary>
/// Wire encode/decode for the MS-SWN witness structures. The RPC transport around these
/// (BIND / context handles / opnum dispatch) lives in <c>WitnessEndpoint</c> (C1.2); this type is
/// pure marshaling so it can be unit-tested against goldens independently.
/// </summary>
public static class WitnessWire
{
    /// <summary>Length of the fixed <c>WCHAR InterfaceGroupName[260]</c> field (MS-SWN §2.2.2.3).</summary>
    public const int InterfaceGroupNameChars = 260;

    /// <summary>
    /// Witness interface UUID <c>ccd8c074-d0e5-4a40-92b4-d074faa6ba28</c> v1.1, in DCE wire byte order
    /// (Data1/2/3 little-endian, Data4 big-endian) — as it appears in the BIND abstract syntax.
    /// </summary>
    public static ReadOnlySpan<byte> InterfaceUuid =>
    [
        0x74, 0xC0, 0xD8, 0xCC, 0xE5, 0xD0, 0x40, 0x4A,
        0x92, 0xB4, 0xD0, 0x74, 0xFA, 0xA6, 0xBA, 0x28,
    ];

    // --- Encoders (server → client) -------------------------------------------------------------

    /// <summary>
    /// NDR stub for a <c>WitnessrGetInterfaceList</c> response: <c>[out] PWITNESS_INTERFACE_LIST*</c>
    /// followed by the DWORD return status.
    /// </summary>
    public static byte[] EncodeInterfaceList(IReadOnlyList<WitnessInterfaceInfo> interfaces, uint returnCode = 0)
    {
        var n = new NdrWriter();
        n.ReferentId();                       // ppInterfaceList -> WITNESS_INTERFACE_LIST
        n.UInt32((uint)interfaces.Count);     // NumberOfInterfaces
        n.ReferentId();                       // -> InterfaceInfo[] (size_is array)
        n.UInt32((uint)interfaces.Count);     // conformant array max_count

        foreach (WitnessInterfaceInfo i in interfaces)
        {
            n.FixedWideString(i.InterfaceGroupName, InterfaceGroupNameChars); // WCHAR[260]
            n.UInt32(i.Version);
            n.UInt16((ushort)i.NodeState);
            n.UInt32(i.IPv4);                 // NDR re-aligns to 4 before this
            for (int k = 0; k < 8; k++) n.UInt16(0); // IPV6[8] (unused; IPv4-only advertisement)
            n.UInt32((uint)i.Flags);
        }

        n.UInt32(returnCode);
        return n.ToArray();
    }

    /// <summary>
    /// NDR stub for a <c>WitnessrAsyncNotify</c> response: <c>[out] PRESP_ASYNC_NOTIFY*</c> whose
    /// custom-marshaled <paramref name="messageBuffer"/> carries <paramref name="messageCount"/> messages
    /// of type <paramref name="type"/>, followed by the DWORD return status.
    /// </summary>
    public static byte[] EncodeAsyncNotifyResponse(
        WitnessNotifyType type, int messageCount, ReadOnlySpan<byte> messageBuffer, uint returnCode = 0)
    {
        var n = new NdrWriter();
        n.ReferentId();                       // pResp -> RESP_ASYNC_NOTIFY
        n.UInt32((uint)type);                 // MessageType
        n.UInt32((uint)messageBuffer.Length); // Length
        n.UInt32((uint)messageCount);         // NumberOfMessages
        n.ReferentId();                       // -> MessageBuffer (size_is(Length) PBYTE)
        n.UInt32((uint)messageBuffer.Length); // conformant array max_count
        n.Bytes(messageBuffer);
        n.Align(4);
        n.UInt32(returnCode);
        return n.ToArray();
    }

    /// <summary>
    /// Custom-marshaled RESOURCE_CHANGE message body (MS-SWN §2.2.2.5): <c>Length(4) ChangeType(4)</c>
    /// then the NUL-terminated resource name as packed little-endian UTF-16 (not NDR-aligned). This is
    /// the <c>MessageBuffer</c> content for a <see cref="WitnessNotifyType.ResourceChange"/> notification.
    /// </summary>
    public static byte[] EncodeResourceChange(WitnessResourceChange change, string resourceName)
    {
        byte[] name = Encoding.Unicode.GetBytes(resourceName + "\0");
        var w = new GrowableWriter(8 + name.Length);
        w.WriteUInt32((uint)(8 + name.Length)); // Length (whole structure)
        w.WriteUInt32((uint)change);            // ChangeType
        w.WriteBytes(name);
        return w.ToArray();
    }

    /// <summary>Byte length of one custom-marshaled WITNESS_IPADDR_INFO: <c>Flags(4) IPV4(4) IPV6[16]</c>.</summary>
    private const int IpAddrInfoSize = 24;

    /// <summary>
    /// Custom-marshaled WITNESS_IPADDR_INFO_LIST (MS-SWN §2.2.2.4): <c>Reserved(4) Length(4) IPAddrInstances(4)</c>
    /// then one <c>Flags(4) IPV4(4) IPV6[16]</c> entry per address (little-endian, not NDR-aligned). This is the
    /// <c>MessageBuffer</c> content for <see cref="WitnessNotifyType.ClientMove"/>, <see cref="WitnessNotifyType.ShareMove"/>,
    /// and <see cref="WitnessNotifyType.IpChange"/> notifications.
    /// </summary>
    public static byte[] EncodeIpAddrInfoList(IReadOnlyList<WitnessIpAddr> addresses)
    {
        int length = 12 + addresses.Count * IpAddrInfoSize;
        var w = new GrowableWriter(length);
        w.WriteUInt32(0);                     // Reserved
        w.WriteUInt32((uint)length);          // Length (whole structure)
        w.WriteUInt32((uint)addresses.Count); // IPAddrInstances
        foreach (WitnessIpAddr a in addresses)
        {
            w.WriteUInt32((uint)a.Flags);
            w.WriteUInt32(a.IPv4);
            if (a.IPv6 is { Length: 16 }) w.WriteBytes(a.IPv6);
            else for (int k = 0; k < 16; k++) w.WriteByte(0); // IPV6[16] (zero when IPv4-only)
        }
        return w.ToArray();
    }

    // --- Decoders (client → server) -------------------------------------------------------------

    /// <summary>
    /// Parses a <c>WitnessrRegister</c> (opnum 1) request stub: <c>ULONG Version</c> then three
    /// <c>[in, unique, string]</c> pointers NetName, IpAddress, ClientComputerName (referent immediately
    /// followed by its string, per top-level NDR pointer marshaling). ShareName/Flags/KeepAlive are absent.
    /// </summary>
    public static WitnessRegisterArgs ParseRegister(ReadOnlyMemory<byte> stub)
    {
        var r = new NdrReader(stub);
        uint version = r.UInt32();
        string? netName = ReadUniqueString(r);
        string? ip = ReadUniqueString(r);
        string? client = ReadUniqueString(r);
        return new WitnessRegisterArgs(version, netName, ShareName: null, ip, client, Flags: 0, KeepAliveTimeoutSeconds: 0);
    }

    /// <summary>
    /// Parses a <c>WitnessrRegisterEx</c> (opnum 4) request stub: <c>ULONG Version</c>, four
    /// <c>[in, unique, string]</c> pointers NetName, ShareName, IpAddress, ClientComputerName, then
    /// <c>ULONG Flags</c> and <c>ULONG KeepAliveTimeout</c>.
    /// </summary>
    public static WitnessRegisterArgs ParseRegisterEx(ReadOnlyMemory<byte> stub)
    {
        var r = new NdrReader(stub);
        uint version = r.UInt32();
        string? netName = ReadUniqueString(r);
        string? shareName = ReadUniqueString(r);
        string? ip = ReadUniqueString(r);
        string? client = ReadUniqueString(r);
        uint flags = r.UInt32();
        uint keepAlive = r.UInt32();
        return new WitnessRegisterArgs(version, netName, shareName, ip, client, flags, keepAlive);
    }

    /// <summary>Reads a top-level <c>[unique, string]</c> pointer: referent id, then the string if non-null.</summary>
    private static string? ReadUniqueString(NdrReader r)
        => r.ReferentId() == 0 ? null : r.WideStringNullTerminated();
}
