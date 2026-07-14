using Smb.Protocol.Wire;
using Smb.Server.Rpc;

namespace Smb.Server.Witness;

/// <summary>
/// Witness service (MS-SWN) DCERPC endpoint at <c>\PIPE\witness</c>. Handles the synchronous opnums —
/// <c>WitnessrGetInterfaceList</c> (0), <c>WitnessrRegister</c> (1), <c>WitnessrUnRegister</c> (2),
/// <c>WitnessrRegisterEx</c> (4) — allocating a context handle per registration in the shared
/// <see cref="WitnessRegistrationStore"/>. <c>WitnessrAsyncNotify</c> (3) is the long-pending call handled
/// out-of-band at the IOCTL layer (C1.3); this endpoint faults it so a client that skips the async path
/// gets a clean error rather than a hang.
/// </summary>
public sealed class WitnessEndpoint : IRpcEndpoint
{
    // Win32 return codes used by the witness routines (MS-SWN §3.1.4).
    private const uint ErrorSuccess = 0x00000000;
    private const uint ErrorInvalidParameter = 0x00000057;
    private const uint ErrorRevisionMismatch = 0x000004E7; // version not supported
    private const uint RpcFaultOpRange = 0x1C010002;       // nca_op_rng_error (unknown opnum)

    private static readonly byte[] NullHandle = new byte[20];

    private readonly WitnessRegistrationStore _store;
    private readonly Guid _connectionId;
    private readonly Func<IReadOnlyList<WitnessInterfaceInfo>> _interfaces;

    public WitnessEndpoint(
        WitnessRegistrationStore store, Guid connectionId, Func<IReadOnlyList<WitnessInterfaceInfo>> interfaces)
    {
        _store = store;
        _connectionId = connectionId;
        _interfaces = interfaces;
    }

    /// <summary>A single-node default interface list: this server as the (only) witness, IPv4 unknown.</summary>
    public static IReadOnlyList<WitnessInterfaceInfo> SelfInterfaces(string serverName) =>
    [
        new WitnessInterfaceInfo(
            serverName, WitnessVersion.V1, WitnessNodeState.Available,
            IPv4: 0, WitnessInterfaceFlags.InterfaceWitness),
    ];

    /// <summary>
    /// If <paramref name="pdu"/> is a <c>WitnessrAsyncNotify</c> request for a live registration owned by
    /// this endpoint's connection, returns true and yields the registration plus the RPC call id — the
    /// caller then holds the response open and completes it out-of-band (C1.3). Any other PDU (or an
    /// unknown/foreign context handle) returns false and is handled synchronously via <see cref="HandlePdu"/>.
    /// </summary>
    public bool TryBeginAsyncNotify(ReadOnlySpan<byte> pdu, out WitnessRegistration registration, out uint callId)
    {
        registration = null!;
        callId = 0;

        DcerpcRequest req;
        try { req = Dcerpc.Parse(pdu); }
        catch { return false; }

        if (req.Type != DcerpcPduType.Request || (WitnessOpnum)req.Opnum != WitnessOpnum.AsyncNotify)
            return false;
        if (!WitnessRegistrationStore.TryReadContextHandle(req.Stub, out Guid id))
            return false;
        if (!_store.TryGet(id, out WitnessRegistration reg) || reg.ConnectionId != _connectionId)
            return false;

        registration = reg;
        callId = req.CallId;
        return true;
    }

    /// <summary>Wraps an async-notify payload in a DCERPC RESPONSE PDU echoing <paramref name="callId"/>.</summary>
    public static byte[] BuildAsyncNotifyPdu(uint callId, WitnessNotification notification)
        => Dcerpc.BuildResponse(
            callId,
            WitnessWire.EncodeAsyncNotifyResponse(notification.Type, notification.MessageCount, notification.MessageBuffer));

    public byte[] HandlePdu(ReadOnlySpan<byte> pdu)
    {
        DcerpcRequest req;
        try { req = Dcerpc.Parse(pdu); }
        catch { return []; }

        switch (req.Type)
        {
            case DcerpcPduType.Bind:
            case DcerpcPduType.AlterContext:
                return Dcerpc.BuildBindAck(req.CallId, @"\PIPE\witness");

            case DcerpcPduType.Request:
                return HandleRequest(req);

            default:
                return [];
        }
    }

    private byte[] HandleRequest(DcerpcRequest req)
    {
        switch ((WitnessOpnum)req.Opnum)
        {
            case WitnessOpnum.GetInterfaceList:
                return Dcerpc.BuildResponse(req.CallId, WitnessWire.EncodeInterfaceList(_interfaces()));

            case WitnessOpnum.Register:
                return HandleRegister(req, WitnessWire.ParseRegister(req.Stub));

            case WitnessOpnum.RegisterEx:
                return HandleRegister(req, WitnessWire.ParseRegisterEx(req.Stub));

            case WitnessOpnum.UnRegister:
                return HandleUnRegister(req);

            case WitnessOpnum.AsyncNotify:
                // Long-pending; served out-of-band by the IOCTL layer (C1.3). A direct synchronous call
                // here (no async wiring) is faulted rather than answered.
                return Dcerpc.BuildFault(req.CallId, RpcFaultOpRange);

            default:
                return Dcerpc.BuildFault(req.CallId, RpcFaultOpRange);
        }
    }

    private byte[] HandleRegister(DcerpcRequest req, WitnessRegisterArgs args)
    {
        if (args.Version != WitnessVersion.V1 && args.Version != WitnessVersion.V2)
            return Dcerpc.BuildResponse(req.CallId, EncodeRegisterResponse(NullHandle, ErrorRevisionMismatch));
        if (string.IsNullOrEmpty(args.NetName))
            return Dcerpc.BuildResponse(req.CallId, EncodeRegisterResponse(NullHandle, ErrorInvalidParameter));

        WitnessRegistration reg = _store.Add(
            _connectionId, args.Version, args.NetName, args.ShareName, args.IpAddress, args.ClientComputerName);
        return Dcerpc.BuildResponse(req.CallId, EncodeRegisterResponse(reg.ContextHandle(), ErrorSuccess));
    }

    private byte[] HandleUnRegister(DcerpcRequest req)
    {
        bool ok = WitnessRegistrationStore.TryReadContextHandle(req.Stub, out Guid id) && _store.Remove(id);
        return Dcerpc.BuildResponse(req.CallId, EncodeReturn(ok ? ErrorSuccess : ErrorInvalidParameter));
    }

    /// <summary>Register(Ex) response stub: the 20-byte <c>[out]</c> context handle then the DWORD return code.</summary>
    private static byte[] EncodeRegisterResponse(ReadOnlySpan<byte> contextHandle, uint returnCode)
    {
        var w = new GrowableWriter(24);
        w.WriteBytes(contextHandle);
        w.WriteUInt32(returnCode);
        return w.ToArray();
    }

    private static byte[] EncodeReturn(uint returnCode)
    {
        var w = new GrowableWriter(4);
        w.WriteUInt32(returnCode);
        return w.ToArray();
    }
}
