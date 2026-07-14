using System.Buffers.Binary;
using Smb.Protocol.Wire;
using Smb.Server.Rpc;
using Smb.Server.Witness;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// C1.2 — the <c>\PIPE\witness</c> DCERPC endpoint: BIND, GetInterfaceList, Register/UnRegister over the
/// synchronous opnum dispatch, exercised directly against <see cref="WitnessEndpoint"/> (no full SMB stack).
/// </summary>
public class WitnessEndpointTests
{
    private readonly WitnessRegistrationStore _store = new();
    private readonly Guid _conn = Guid.NewGuid();
    private readonly WitnessEndpoint _endpoint;

    public WitnessEndpointTests()
        => _endpoint = new WitnessEndpoint(_store, _conn, () => WitnessEndpoint.SelfInterfaces("NODE1"));

    [Fact]
    public void Bind_IsAcknowledged()
    {
        byte[] resp = _endpoint.HandlePdu(BuildBindPdu(callId: 7));
        Assert.Equal((byte)DcerpcPduType.BindAck, resp[2]);
    }

    [Fact]
    public void GetInterfaceList_ReturnsSelfInterface()
    {
        byte[] resp = _endpoint.HandlePdu(BuildRequestPdu(1, (ushort)WitnessOpnum.GetInterfaceList, []));
        var r = new NdrReader(resp.AsMemory(24));
        Assert.NotEqual(0u, r.ReferentId());
        Assert.Equal(1u, r.UInt32());      // NumberOfInterfaces
        r.ReferentId();
        r.UInt32();                        // max_count
        Assert.Equal("NODE1", r.FixedWideString(WitnessWire.InterfaceGroupNameChars));
    }

    [Fact]
    public void Register_ThenUnRegister_TracksAndDropsRegistration()
    {
        byte[] regStub = BuildRegisterStub(WitnessVersion.V1, @"\\cluster", "10.0.0.5", "CLIENT01");
        byte[] resp = _endpoint.HandlePdu(BuildRequestPdu(2, (ushort)WitnessOpnum.Register, regStub));

        ReadOnlySpan<byte> stub = Stub(resp);
        var handleId = new Guid(stub.Slice(4, 16));
        uint ret = BinaryPrimitives.ReadUInt32LittleEndian(stub.Slice(20, 4));
        Assert.Equal(0u, ret);                          // ERROR_SUCCESS
        Assert.NotEqual(Guid.Empty, handleId);
        Assert.True(_store.TryGet(handleId, out WitnessRegistration reg));
        Assert.Equal(@"\\cluster", reg.NetName);
        Assert.Equal(_conn, reg.ConnectionId);

        // UnRegister with the 20-byte context handle echoed back.
        byte[] unresp = _endpoint.HandlePdu(BuildRequestPdu(3, (ushort)WitnessOpnum.UnRegister, stub[..20].ToArray()));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(Stub(unresp).Slice(0, 4)));
        Assert.False(_store.TryGet(handleId, out _));
    }

    [Fact]
    public void Register_UnsupportedVersion_ReturnsRevisionMismatch_NoHandle()
    {
        byte[] regStub = BuildRegisterStub(0x00030000, @"\\cluster", "10.0.0.5", "CLIENT01");
        byte[] resp = _endpoint.HandlePdu(BuildRequestPdu(4, (ushort)WitnessOpnum.Register, regStub));

        ReadOnlySpan<byte> stub = Stub(resp);
        Assert.Equal(new Guid(new byte[16]), new Guid(stub.Slice(4, 16))); // null handle
        Assert.Equal(0x000004E7u, BinaryPrimitives.ReadUInt32LittleEndian(stub.Slice(20, 4))); // ERROR_REVISION_MISMATCH
        Assert.Empty(_store.Snapshot());
    }

    [Fact]
    public void UnRegister_UnknownHandle_ReturnsInvalidParameter()
    {
        byte[] bogus = new byte[20];
        Guid.NewGuid().TryWriteBytes(bogus.AsSpan(4));
        byte[] resp = _endpoint.HandlePdu(BuildRequestPdu(5, (ushort)WitnessOpnum.UnRegister, bogus));
        Assert.Equal(0x00000057u, BinaryPrimitives.ReadUInt32LittleEndian(Stub(resp).Slice(0, 4))); // ERROR_INVALID_PARAMETER
    }

    [Fact]
    public void AsyncNotify_Synchronous_Faults()
    {
        // Direct synchronous AsyncNotify (no async wiring) faults until C1.3 serves it out-of-band.
        byte[] resp = _endpoint.HandlePdu(BuildRequestPdu(6, (ushort)WitnessOpnum.AsyncNotify, new byte[20]));
        Assert.Equal((byte)DcerpcPduType.Fault, resp[2]);
    }

    [Fact]
    public void NotifyResourceChange_MatchesNetName_AndBuffersForNextAsyncNotify()
    {
        WitnessRegistration reg = _store.Add(_conn, WitnessVersion.V1, @"\\cluster", null, "10.0.0.5", "C1");

        // A non-matching net name notifies nobody.
        Assert.Equal(0, _store.NotifyResourceChange(@"\\other", WitnessResourceChange.Unavailable, "Data"));
        // A matching net name (case-insensitive) notifies the registration; with no waiter it buffers.
        Assert.Equal(1, _store.NotifyResourceChange(@"\\CLUSTER", WitnessResourceChange.Unavailable, "Data"));

        // The buffered notification is delivered to the next waiter.
        WitnessNotification? got = null;
        reg.Notifications.Wait(n => got = n);
        SpinWait.SpinUntil(() => got is not null, TimeSpan.FromSeconds(2));
        Assert.NotNull(got);
        Assert.Equal(WitnessNotifyType.ResourceChange, got!.Type);
    }

    [Fact]
    public void RemoveAllForConnection_DropsOnlyThatConnectionsRegistrations()
    {
        var otherConn = Guid.NewGuid();
        _store.Add(_conn, WitnessVersion.V1, @"\\c", null, "1", "a");
        _store.Add(_conn, WitnessVersion.V1, @"\\c", null, "2", "b");
        _store.Add(otherConn, WitnessVersion.V1, @"\\c", null, "3", "c");

        Assert.Equal(2, _store.RemoveAllForConnection(_conn));
        Assert.Single(_store.Snapshot());
    }

    // --- helpers ------------------------------------------------------------------------------------

    /// <summary>Response stub payload: everything past the 24-byte DCERPC response header.</summary>
    private static ReadOnlySpan<byte> Stub(byte[] responsePdu) => responsePdu.AsSpan(24);

    private static byte[] BuildRegisterStub(uint version, string netName, string ip, string client)
    {
        var w = new NdrWriter();
        w.UInt32(version);
        w.ReferentId(); w.WideStringNullTerminated(netName);
        w.ReferentId(); w.WideStringNullTerminated(ip);
        w.ReferentId(); w.WideStringNullTerminated(client);
        return w.ToArray();
    }

    private static byte[] BuildBindPdu(uint callId)
    {
        var w = new GrowableWriter(16);
        WriteHeader(w, DcerpcPduType.Bind, callId);
        return w.ToArray();
    }

    private static byte[] BuildRequestPdu(uint callId, ushort opnum, ReadOnlySpan<byte> stub)
    {
        var w = new GrowableWriter(24 + stub.Length);
        WriteHeader(w, DcerpcPduType.Request, callId);
        w.WriteUInt32((uint)stub.Length); // alloc_hint
        w.WriteUInt16(0);                 // p_cont_id
        w.WriteUInt16(opnum);             // opnum
        w.WriteBytes(stub);
        return w.ToArray();
    }

    private static void WriteHeader(GrowableWriter w, DcerpcPduType type, uint callId)
    {
        w.WriteByte(5); w.WriteByte(0); w.WriteByte((byte)type); w.WriteByte(0x03);
        w.WriteUInt32(0x00000010); // packed_drep (LE)
        w.WriteUInt16(0);          // frag_length (unused by the parser)
        w.WriteUInt16(0);          // auth_length
        w.WriteUInt32(callId);
    }
}
