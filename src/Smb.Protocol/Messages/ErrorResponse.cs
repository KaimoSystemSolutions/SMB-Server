using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 ERROR Response Body (MS-SMB2 §2.2.2). <c>StructureSize=9</c>. Sent instead of the
/// command-specific body on every error response (Context §18, §19.1).
/// </summary>
public static class ErrorResponse
{
    public const ushort StructureSize = 9;

    /// <summary>SMB2_ERROR_ID_DEFAULT (MS-SMB2 §2.2.2.1): the ordinary error-context id.</summary>
    public const uint Smb2ErrorIdDefault = 0x00000000;

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

    /// <summary>
    /// Builds an error body whose ErrorData is a single SMB2_ERROR_CONTEXT (MS-SMB2 §2.2.2.1), the format
    /// mandated for the SMB 3.1.1 dialect when extended error information is present. The context wraps
    /// <paramref name="errorContextData"/> (e.g. a SYMLINK_ERROR_RESPONSE) with its length and
    /// <paramref name="errorId"/>. A single context needs no trailing 8-byte alignment padding — the body
    /// starts 8-byte aligned within the message and the context is the last element.
    /// </summary>
    public static byte[] BuildBodyWithContext(ReadOnlySpan<byte> errorContextData, uint errorId = Smb2ErrorIdDefault)
    {
        // SMB2_ERROR_CONTEXT: ErrorDataLength (4) + ErrorId (4) + ErrorContextData (variable).
        int contextLen = 8 + errorContextData.Length;
        var body = new byte[8 + contextLen];
        var w = new SpanWriter(body);
        w.WriteUInt16(StructureSize);
        w.WriteByte(1); // ErrorContextCount = 1
        w.WriteByte(0); // Reserved
        w.WriteUInt32((uint)contextLen); // ByteCount = total ErrorData length
        w.WriteUInt32((uint)errorContextData.Length); // ErrorContext.ErrorDataLength
        w.WriteUInt32(errorId); // ErrorContext.ErrorId
        w.WriteBytes(errorContextData); // ErrorContext.ErrorContextData
        return body;
    }

    /// <summary>
    /// Reads the ERROR Response body (§2.2.2, starting at StructureSize) and returns the extended error
    /// payload: the first SMB2_ERROR_CONTEXT's data when ErrorContextCount &gt; 0 (SMB 3.1.1), otherwise
    /// the raw ErrorData. Handles both wire formats so a caller need not know the negotiated dialect.
    /// </summary>
    public static byte[] ReadErrorData(ReadOnlySpan<byte> body)
    {
        if (body.Length < 8)
            throw new SmbWireFormatException($"ERROR response body too short: {body.Length} bytes.");

        int contextCount = body[2];
        int byteCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(body.Slice(4, 4));
        ReadOnlySpan<byte> errorData = body.Slice(8, byteCount);

        if (contextCount == 0)
            return errorData.ToArray();

        // First SMB2_ERROR_CONTEXT: ErrorDataLength (4) + ErrorId (4) + ErrorContextData (variable).
        int dataLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(errorData.Slice(0, 4));
        return errorData.Slice(8, dataLength).ToArray();
    }
}
