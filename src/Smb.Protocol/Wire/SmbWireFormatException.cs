namespace Smb.Protocol.Wire;

/// <summary>
/// Thrown when a message does not match the expected wire format (too short, wrong
/// <c>StructureSize</c>, invalid offsets, …). The server generally translates this into
/// <c>STATUS_INVALID_PARAMETER</c> (Context §18, §19.1 step 6).
/// </summary>
public sealed class SmbWireFormatException : Exception
{
    public SmbWireFormatException(string message) : base(message) { }
    public SmbWireFormatException(string message, Exception inner) : base(message, inner) { }
}
