using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 NEGOTIATE Response (Context §6.3, MS-SMB2 §2.2.4). <c>StructureSize=65</c>
/// (fester Teil 64 Byte; das "+1" steht für den variablen Buffer, Context §4/§23).
/// </summary>
public sealed class NegotiateResponse
{
    public const ushort StructureSize = 65;

    public SmbSecurityMode SecurityMode { get; init; }
    public SmbDialect DialectRevision { get; init; }
    public byte[] ServerGuid { get; init; } = new byte[16];
    public Smb2Capabilities Capabilities { get; init; }
    public uint MaxTransactSize { get; init; }
    public uint MaxReadSize { get; init; }
    public uint MaxWriteSize { get; init; }

    /// <summary>FILETIME (100-ns seit 1601-01-01 UTC).</summary>
    public long SystemTime { get; init; }
    public long ServerStartTime { get; init; }

    /// <summary>SPNEGO NegTokenInit2 (Context §9); darf leer sein (raw NTLM ohne SPNEGO).</summary>
    public byte[] SecurityBuffer { get; init; } = [];

    /// <summary>Negotiate-Contexts (nur 3.1.1).</summary>
    public IReadOnlyList<NegotiateContext> NegotiateContexts { get; init; } = [];

    /// <summary>
    /// Serialisiert den Response-Body (ohne SMB2-Header). <paramref name="headerSize"/>
    /// ist der Offset des Bodys in der Gesamtnachricht (i.d.R. 64), nötig weil
    /// SecurityBufferOffset und NegotiateContextOffset absolut (ab Nachrichtenbeginn) sind.
    /// </summary>
    public byte[] ToBody(int headerSize = Smb2Header.Size)
    {
        var w = new GrowableWriter(128 + SecurityBuffer.Length);

        w.WriteUInt16(StructureSize);
        w.WriteUInt16((ushort)SecurityMode);
        w.WriteUInt16((ushort)DialectRevision);
        w.WriteUInt16((ushort)NegotiateContexts.Count); // NegotiateContextCount (0 bei <3.1.1)

        if (ServerGuid.Length != 16)
            throw new SmbWireFormatException("ServerGuid muss 16 Byte sein.");
        w.WriteBytes(ServerGuid);

        w.WriteUInt32((uint)Capabilities);
        w.WriteUInt32(MaxTransactSize);
        w.WriteUInt32(MaxReadSize);
        w.WriteUInt32(MaxWriteSize);
        w.WriteUInt64((ulong)SystemTime);
        w.WriteUInt64((ulong)ServerStartTime);

        int secOffsetPos = w.Position;
        w.WriteUInt16(0); // SecurityBufferOffset – patch
        w.WriteUInt16((ushort)SecurityBuffer.Length);
        int negCtxOffsetPos = w.Position;
        w.WriteUInt32(0); // NegotiateContextOffset – patch

        // Variabler Teil: SecurityBuffer (direkt nach dem 64-Byte-Festteil).
        int securityBufferStart = w.Position;
        if (SecurityBuffer.Length > 0)
        {
            w.WriteBytes(SecurityBuffer);
            w.PatchUInt16(secOffsetPos, (ushort)(headerSize + securityBufferStart));
        }
        else
        {
            w.PatchUInt16(secOffsetPos, 0);
        }

        // Negotiate-Contexts: jeder Context beginnt auf einer 8-Byte-Grenze relativ zum
        // Nachrichtenbeginn (= headerSize + Writer-Position). Das Padding zwischen Contexts
        // zählt nicht zur jeweiligen DataLength.
        if (NegotiateContexts.Count > 0)
        {
            PadToAbsolute8(w, headerSize);
            w.PatchUInt32(negCtxOffsetPos, (uint)(headerSize + w.Position));

            for (int i = 0; i < NegotiateContexts.Count; i++)
            {
                if (i > 0) PadToAbsolute8(w, headerSize);
                NegotiateContexts[i].Write(w);
            }
        }
        else
        {
            w.PatchUInt32(negCtxOffsetPos, 0);
        }

        return w.ToArray();
    }

    /// <summary>Padding bis die absolute Position (headerSize + Writer-Position) durch 8 teilbar ist.</summary>
    private static void PadToAbsolute8(GrowableWriter w, int headerSize)
    {
        int abs = headerSize + w.Position;
        int pad = (8 - (abs % 8)) % 8;
        if (pad > 0) w.WriteZeros(pad);
    }
}
