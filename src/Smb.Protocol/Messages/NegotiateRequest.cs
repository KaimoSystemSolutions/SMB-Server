using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 NEGOTIATE Request (Context §6.2, MS-SMB2 §2.2.3). <c>StructureSize=36</c>.
/// The body follows directly after the 64-byte header.
/// </summary>
public sealed class NegotiateRequest
{
    public const ushort ExpectedStructureSize = 36;

    public SmbSecurityMode SecurityMode { get; init; }
    public Smb2Capabilities Capabilities { get; init; }
    public byte[] ClientGuid { get; init; } = new byte[16];

    /// <summary>Dialects offered by the client (in list order).</summary>
    public IReadOnlyList<SmbDialect> Dialects { get; init; } = [];

    /// <summary>Negotiate contexts (only when 0x0311 is offered), otherwise empty.</summary>
    public IReadOnlyList<NegotiateContext> NegotiateContexts { get; init; } = [];

    /// <summary>True when the client offers SMB 3.1.1.</summary>
    public bool OffersSmb311 => Dialects.Contains(SmbDialect.Smb311);

    /// <summary>
    /// Parses the negotiate body. <paramref name="message"/> is the whole message;
    /// <paramref name="bodyOffset"/> is the absolute offset of the body within the message
    /// (usually 64) — needed because NegotiateContextOffset counts from the start of the message.
    /// </summary>
    public static NegotiateRequest Parse(ReadOnlySpan<byte> message, int bodyOffset)
    {
        ReadOnlySpan<byte> body = message[bodyOffset..];
        var r = new SpanReader(body);

        ushort structureSize = r.ReadUInt16();
        if (structureSize != ExpectedStructureSize)
            throw new SmbWireFormatException($"NEGOTIATE Request StructureSize {structureSize} ≠ {ExpectedStructureSize}.");

        int dialectCount = r.ReadUInt16();
        if (dialectCount is 0 or > 64)
            throw new SmbWireFormatException($"NEGOTIATE DialectCount {dialectCount} invalid.");

        var securityMode = (SmbSecurityMode)r.ReadUInt16();
        r.Skip(2); // Reserved
        var capabilities = (Smb2Capabilities)r.ReadUInt32();
        byte[] clientGuid = r.ReadByteArray(16);

        // Offset 28..35: for 3.1.1 NegotiateContextOffset(4)+Count(2)+Reserved2(2), otherwise ClientStartTime(8).
        uint negotiateContextOffset = r.ReadUInt32();
        ushort negotiateContextCount = r.ReadUInt16();
        r.Skip(2); // Reserved2 / part of ClientStartTime

        var dialects = new SmbDialect[dialectCount];
        for (int i = 0; i < dialectCount; i++)
            dialects[i] = (SmbDialect)r.ReadUInt16();

        var contexts = new List<NegotiateContext>();
        bool offers311 = Array.IndexOf(dialects, SmbDialect.Smb311) >= 0;
        if (offers311 && negotiateContextOffset != 0 && negotiateContextCount > 0)
        {
            ParseContexts(message, (int)negotiateContextOffset, negotiateContextCount, contexts);
        }

        return new NegotiateRequest
        {
            SecurityMode = securityMode,
            Capabilities = capabilities,
            ClientGuid = clientGuid,
            Dialects = dialects,
            NegotiateContexts = contexts,
        };
    }

    private static void ParseContexts(ReadOnlySpan<byte> message, int offset, int count, List<NegotiateContext> sink)
    {
        int pos = offset;
        for (int i = 0; i < count; i++)
        {
            if (pos + NegotiateContext.HeaderSize > message.Length)
                throw new SmbWireFormatException("Negotiate context extends past the end of the message.");

            NegotiateContext ctx = NegotiateContext.Read(message[pos..], out int consumed);
            sink.Add(ctx);
            pos += consumed;
            // Align contexts to 8 bytes between one another (except after the last one).
            if (i < count - 1) pos = Align8(pos);
        }
    }

    private static int Align8(int value) => (value + 7) & ~7;
}
