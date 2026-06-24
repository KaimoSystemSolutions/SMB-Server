using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 ERROR Response Body (MS-SMB2 §2.2.2). <c>StructureSize=9</c>. Wird bei jeder
/// Fehlerantwort statt des command-spezifischen Bodys gesendet (Context §18, §19.1).
/// </summary>
public static class ErrorResponse
{
    public const ushort StructureSize = 9;

    /// <summary>
    /// Baut einen Error-Body. Ist <paramref name="errorData"/> leer, wird gemäß Spec ein
    /// einzelnes Nullbyte als ErrorData geschrieben (das "+1" der StructureSize).
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
            w.WriteByte(0); // ein Pflicht-Byte ErrorData
        return body;
    }
}
