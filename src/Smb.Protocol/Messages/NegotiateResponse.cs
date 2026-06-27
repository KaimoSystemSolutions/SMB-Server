using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 NEGOTIATE Response (Context §6.3, MS-SMB2 §2.2.4). <c>StructureSize=65</c>
/// (fixed part 64 bytes; the "+1" stands for the variable buffer, Context §4/§23).
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

    /// <summary>FILETIME (100-ns since 1601-01-01 UTC).</summary>
    public long SystemTime { get; init; }
    public long ServerStartTime { get; init; }

    /// <summary>SPNEGO NegTokenInit2 (Context §9); may be empty (raw NTLM without SPNEGO).</summary>
    public byte[] SecurityBuffer { get; init; } = [];

    /// <summary>Negotiate contexts (3.1.1 only).</summary>
    public IReadOnlyList<NegotiateContext> NegotiateContexts { get; init; } = [];

    /// <summary>
    /// Serializes the response body (without the SMB2 header). <paramref name="headerSize"/>
    /// is the offset of the body within the whole message (usually 64), needed because
    /// SecurityBufferOffset and NegotiateContextOffset are absolute (from the start of the message).
    /// </summary>
    public byte[] ToBody(int headerSize = Smb2Header.Size)
    {
        var w = new GrowableWriter(128 + SecurityBuffer.Length);

        w.WriteUInt16(StructureSize);
        w.WriteUInt16((ushort)SecurityMode);
        w.WriteUInt16((ushort)DialectRevision);
        w.WriteUInt16((ushort)NegotiateContexts.Count); // NegotiateContextCount (0 for <3.1.1)

        if (ServerGuid.Length != 16)
            throw new SmbWireFormatException("ServerGuid must be 16 bytes.");
        w.WriteBytes(ServerGuid);

        w.WriteUInt32((uint)Capabilities);
        w.WriteUInt32(MaxTransactSize);
        w.WriteUInt32(MaxReadSize);
        w.WriteUInt32(MaxWriteSize);
        w.WriteUInt64((ulong)SystemTime);
        w.WriteUInt64((ulong)ServerStartTime);

        int secOffsetPos = w.Position;
        w.WriteUInt16(0); // SecurityBufferOffset – patched below
        w.WriteUInt16((ushort)SecurityBuffer.Length);
        int negCtxOffsetPos = w.Position;
        w.WriteUInt32(0); // NegotiateContextOffset – patched below

        // Variable part: SecurityBuffer (directly after the 64-byte fixed part).
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

        // Negotiate contexts: each context starts on an 8-byte boundary relative to the start of
        // the message (= headerSize + writer position). The padding between contexts does not count
        // toward each context's DataLength.
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

    /// <summary>Pads until the absolute position (headerSize + writer position) is divisible by 8.</summary>
    private static void PadToAbsolute8(GrowableWriter w, int headerSize)
    {
        int abs = headerSize + w.Position;
        int pad = (8 - (abs % 8)) % 8;
        if (pad > 0) w.WriteZeros(pad);
    }
}
