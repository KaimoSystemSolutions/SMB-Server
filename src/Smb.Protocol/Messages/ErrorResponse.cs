using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 ERROR Response Body (MS-SMB2 §2.2.2). <c>StructureSize=9</c>. Sent instead of the
/// command-specific body on every error response (Context §18, §19.1).
/// </summary>
public static class ErrorResponse
{
    public const ushort StructureSize = 9;

    /// <summary>
    /// Builds an error body. If <paramref name="errorData"/> is empty, a single zero byte is written
    /// as ErrorData per the spec (the "+1" of the StructureSize).
    /// </summary>
    public static byte[] BuildBody(ReadOnlySpan<byte> errorData = default)
    {
        int dataLen = Math.Max(errorData.Length, 1);
        var body = new byte[8 + dataLen];
        var w = new SpanWriter(body);
        w.WriteUInt16(StructureSize);
        w.WriteByte(0); // ErrorContextCount
        w.WriteByte(0); // Reserved
        w.WriteUInt32((uint)errorData.Length); // ByteCount
        if (errorData.Length > 0)
            w.WriteBytes(errorData);
        else
            w.WriteByte(0); // one mandatory ErrorData byte
        return body;
    }
}
