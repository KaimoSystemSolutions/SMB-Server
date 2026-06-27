using System.Buffers.Binary;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Server.Rpc;

/// <summary>DCERPC-PDU-Typen (Connection-oriented, C706 / MS-RPCE §2.2.2.3).</summary>
public enum DcerpcPduType : byte
{
    Request = 0,
    Response = 2,
    Fault = 3,
    Bind = 11,
    BindAck = 12,
    BindNak = 13,
    AlterContext = 14,
    AlterContextResp = 15,
}

/// <summary>Geparster DCERPC-PDU-Kopf plus (bei Request) Opnum und Stub.</summary>
public readonly record struct DcerpcRequest(DcerpcPduType Type, uint CallId, ushort Opnum, byte[] Stub);

/// <summary>
/// Minimaler Connection-oriented DCERPC-Layer (MS-RPCE). Genug, um einen Bind zu bestätigen und
/// einen Request an einen Endpoint weiterzureichen. Little-Endian (packed_drep 10 00 00 00).
/// </summary>
public static class Dcerpc
{
    public const int HeaderSize = 16;

    /// <summary>NDR-Transfer-Syntax 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0 (16 Byte UUID).</summary>
    public static ReadOnlySpan<byte> NdrTransferSyntax =>
    [
        0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
        0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
    ];

    public static DcerpcRequest Parse(ReadOnlySpan<byte> pdu)
    {
        if (pdu.Length < HeaderSize)
            throw new SmbWireFormatException("DCERPC-PDU zu kurz.");

        var type = (DcerpcPduType)pdu[2];
        uint callId = BinaryPrimitives.ReadUInt32LittleEndian(pdu.Slice(12, 4));

        if (type == DcerpcPduType.Request)
        {
            // Request-Body: alloc_hint(4) + p_cont_id(2) + opnum(2) + stub. The opnum sits at
            // offset 22..23, so the PDU must be at least 24 bytes; guard before slicing so a
            // truncated request yields a clean wire error instead of an ArgumentOutOfRangeException.
            if (pdu.Length < 24)
                throw new SmbWireFormatException("DCERPC request PDU too short for opnum.");
            ushort opnum = BinaryPrimitives.ReadUInt16LittleEndian(pdu.Slice(22, 2));
            byte[] stub = pdu.Length > 24 ? pdu[24..].ToArray() : [];
            return new DcerpcRequest(type, callId, opnum, stub);
        }

        return new DcerpcRequest(type, callId, 0, []);
    }

    /// <summary>Baut eine BIND_ACK-PDU mit einer akzeptierten Präsentation (NDR).</summary>
    public static byte[] BuildBindAck(uint callId, string secondaryAddress)
    {
        byte[] secAddr = Encoding.ASCII.GetBytes(secondaryAddress + "\0");

        var w = new GrowableWriter(96);
        WriteHeader(w, DcerpcPduType.BindAck, callId);
        w.WriteUInt16(4280);          // max_xmit_frag
        w.WriteUInt16(4280);          // max_recv_frag
        w.WriteUInt32(0x00000053);    // assoc_group_id (beliebig, ≠0)
        w.WriteUInt16((ushort)secAddr.Length);
        w.WriteBytes(secAddr);
        AlignTo4(w);

        // p_result_list: 1 Ergebnis (acceptance) mit NDR-Transfer-Syntax.
        w.WriteByte(1);               // n_results
        w.WriteByte(0);               // reserved
        w.WriteUInt16(0);             // reserved2
        w.WriteUInt16(0);             // result = acceptance
        w.WriteUInt16(0);             // reason
        w.WriteBytes(NdrTransferSyntax);
        w.WriteUInt32(2);             // transfer syntax version (2.0)

        PatchFragLength(w);
        return w.ToArray();
    }

    /// <summary>Baut eine RESPONSE-PDU mit dem NDR-Stub.</summary>
    public static byte[] BuildResponse(uint callId, ReadOnlySpan<byte> stub)
    {
        var w = new GrowableWriter(24 + stub.Length);
        WriteHeader(w, DcerpcPduType.Response, callId);
        w.WriteUInt32((uint)stub.Length); // alloc_hint
        w.WriteUInt16(0);                 // p_cont_id
        w.WriteByte(0);                   // cancel_count
        w.WriteByte(0);                   // reserved
        w.WriteBytes(stub);
        PatchFragLength(w);
        return w.ToArray();
    }

    /// <summary>Baut eine FAULT-PDU (z.B. für unbekannte Opnums).</summary>
    public static byte[] BuildFault(uint callId, uint status)
    {
        var w = new GrowableWriter(32);
        WriteHeader(w, DcerpcPduType.Fault, callId);
        w.WriteUInt32(0);     // alloc_hint
        w.WriteUInt16(0);     // p_cont_id
        w.WriteByte(0);       // cancel_count
        w.WriteByte(0);       // reserved
        w.WriteUInt32(status);
        w.WriteUInt32(0);     // reserved2
        PatchFragLength(w);
        return w.ToArray();
    }

    private static void WriteHeader(GrowableWriter w, DcerpcPduType type, uint callId)
    {
        w.WriteByte(5);       // rpc_vers
        w.WriteByte(0);       // rpc_vers_minor
        w.WriteByte((byte)type);
        w.WriteByte(0x03);    // pfc_flags = FIRST_FRAG | LAST_FRAG
        w.WriteUInt32(0x00000010); // packed_drep (LE, ASCII, IEEE)
        w.WriteUInt16(0);     // frag_length (patch)
        w.WriteUInt16(0);     // auth_length
        w.WriteUInt32(callId);
    }

    private static void PatchFragLength(GrowableWriter w)
        => w.PatchUInt16(8, (ushort)w.Position);

    private static void AlignTo4(GrowableWriter w)
    {
        while (w.Position % 4 != 0) w.WriteByte(0);
    }
}
