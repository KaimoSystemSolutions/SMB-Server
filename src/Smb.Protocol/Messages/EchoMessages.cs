using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>SMB2 ECHO Request/Response (Context §14, MS-SMB2 §2.2.27/§2.2.28). <c>StructureSize=4</c>.</summary>
public static class EchoMessage
{
    public const ushort StructureSize = 4;

    /// <summary>Validates an ECHO request body (StructureSize must be 4).</summary>
    public static void ValidateRequest(ReadOnlySpan<byte> body)
    {
        var r = new SpanReader(body);
        ushort ss = r.ReadUInt16();
        if (ss != StructureSize)
            throw new SmbWireFormatException($"ECHO Request StructureSize {ss} ≠ {StructureSize}.");
    }

    /// <summary>Builds the 4-byte ECHO response body.</summary>
    public static byte[] BuildResponseBody()
    {
        var body = new byte[4];
        var w = new SpanWriter(body);
        w.WriteUInt16(StructureSize);
        w.WriteUInt16(0); // Reserved
        return body;
    }
}
