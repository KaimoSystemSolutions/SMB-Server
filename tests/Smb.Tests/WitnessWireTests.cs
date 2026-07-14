using System.Buffers.Binary;
using System.Text;
using Smb.Protocol.Wire;
using Smb.Server.Rpc;
using Smb.Server.Witness;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// C1.1 — NDR reader/writer symmetry and the MS-SWN witness wire structures
/// (encode → decode round-trips and request-stub parsing), independent of the RPC transport.
/// </summary>
public class WitnessWireTests
{
    [Fact]
    public void Ndr_Scalars_And_WideString_RoundTrip()
    {
        var w = new NdrWriter();
        w.UInt32(0xDEADBEEF);
        w.UInt16(0x1234);
        w.WideStringNullTerminated("Hello");

        var r = new NdrReader(w.ToArray());
        Assert.Equal(0xDEADBEEFu, r.UInt32());
        Assert.Equal((ushort)0x1234, r.UInt16());
        Assert.Equal("Hello", r.WideStringNullTerminated());
    }

    [Fact]
    public void NdrReader_Truncated_Throws()
    {
        Assert.Throws<SmbWireFormatException>(() => new NdrReader(new byte[] { 0x01, 0x02 }).UInt32());
    }

    [Fact]
    public void ParseRegister_ReadsVersionAndStrings()
    {
        var w = new NdrWriter();
        w.UInt32(WitnessVersion.V1);
        w.ReferentId(); w.WideStringNullTerminated(@"\\cluster");
        w.ReferentId(); w.WideStringNullTerminated("10.0.0.5");
        w.ReferentId(); w.WideStringNullTerminated("CLIENT01");

        WitnessRegisterArgs args = WitnessWire.ParseRegister(w.ToArray());

        Assert.Equal(WitnessVersion.V1, args.Version);
        Assert.Equal(@"\\cluster", args.NetName);
        Assert.Equal("10.0.0.5", args.IpAddress);
        Assert.Equal("CLIENT01", args.ClientComputerName);
        Assert.Null(args.ShareName);
    }

    [Fact]
    public void ParseRegister_NullPointer_YieldsNull()
    {
        var w = new NdrWriter();
        w.UInt32(WitnessVersion.V1);
        w.NullPointer();                                   // NetName = null
        w.ReferentId(); w.WideStringNullTerminated("::1"); // IpAddress
        w.ReferentId(); w.WideStringNullTerminated("C");   // ClientComputerName

        WitnessRegisterArgs args = WitnessWire.ParseRegister(w.ToArray());

        Assert.Null(args.NetName);
        Assert.Equal("::1", args.IpAddress);
    }

    [Fact]
    public void ParseRegisterEx_ReadsShareFlagsAndKeepAlive()
    {
        var w = new NdrWriter();
        w.UInt32(WitnessVersion.V2);
        w.ReferentId(); w.WideStringNullTerminated(@"\\cluster");
        w.ReferentId(); w.WideStringNullTerminated("Data");
        w.ReferentId(); w.WideStringNullTerminated("10.0.0.5");
        w.ReferentId(); w.WideStringNullTerminated("CLIENT01");
        w.UInt32(0x00000001); // Flags
        w.UInt32(120);        // KeepAliveTimeout

        WitnessRegisterArgs args = WitnessWire.ParseRegisterEx(w.ToArray());

        Assert.Equal(WitnessVersion.V2, args.Version);
        Assert.Equal("Data", args.ShareName);
        Assert.Equal(0x00000001u, args.Flags);
        Assert.Equal(120u, args.KeepAliveTimeoutSeconds);
    }

    [Fact]
    public void EncodeInterfaceList_DecodesFieldByField()
    {
        var info = new WitnessInterfaceInfo(
            InterfaceGroupName: "node1",
            Version: WitnessVersion.V1,
            NodeState: WitnessNodeState.Available,
            IPv4: 0x0100000A, // 10.0.0.1 in network-order-as-uint (packed LE here)
            Flags: WitnessInterfaceFlags.IPv4Valid | WitnessInterfaceFlags.InterfaceWitness);

        var r = new NdrReader(WitnessWire.EncodeInterfaceList([info]));
        Assert.NotEqual(0u, r.ReferentId());          // ppInterfaceList
        Assert.Equal(1u, r.UInt32());                 // NumberOfInterfaces
        Assert.NotEqual(0u, r.ReferentId());          // -> array
        Assert.Equal(1u, r.UInt32());                 // max_count

        Assert.Equal("node1", r.FixedWideString(WitnessWire.InterfaceGroupNameChars));
        Assert.Equal(WitnessVersion.V1, r.UInt32());
        Assert.Equal((ushort)WitnessNodeState.Available, r.UInt16());
        Assert.Equal(0x0100000Au, r.UInt32());
        for (int k = 0; k < 8; k++) Assert.Equal((ushort)0, r.UInt16()); // IPV6[8]
        Assert.Equal((uint)(WitnessInterfaceFlags.IPv4Valid | WitnessInterfaceFlags.InterfaceWitness), r.UInt32());
        Assert.Equal(0u, r.UInt32());                 // return code
    }

    [Fact]
    public void EncodeAsyncNotify_WithResourceChange_RoundTrips()
    {
        byte[] msg = WitnessWire.EncodeResourceChange(WitnessResourceChange.Unavailable, "Data");
        byte[] stub = WitnessWire.EncodeAsyncNotifyResponse(WitnessNotifyType.ResourceChange, 1, msg);

        var r = new NdrReader(stub);
        Assert.NotEqual(0u, r.ReferentId());                       // pResp
        Assert.Equal((uint)WitnessNotifyType.ResourceChange, r.UInt32());
        uint length = r.UInt32();
        Assert.Equal((uint)msg.Length, length);
        Assert.Equal(1u, r.UInt32());                              // NumberOfMessages
        Assert.NotEqual(0u, r.ReferentId());                       // -> MessageBuffer
        Assert.Equal((uint)msg.Length, r.UInt32());                // max_count
        ReadOnlySpan<byte> body = r.Bytes((int)length);

        // Decode the embedded custom-marshaled RESOURCE_CHANGE.
        Assert.Equal((uint)msg.Length, BinaryPrimitives.ReadUInt32LittleEndian(body[..4]));
        Assert.Equal((uint)WitnessResourceChange.Unavailable, BinaryPrimitives.ReadUInt32LittleEndian(body.Slice(4, 4)));
        string name = Encoding.Unicode.GetString(body.Slice(8, body.Length - 8)).TrimEnd('\0');
        Assert.Equal("Data", name);
    }
}
