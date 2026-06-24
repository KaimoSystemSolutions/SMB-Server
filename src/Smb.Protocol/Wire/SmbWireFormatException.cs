namespace Smb.Protocol.Wire;

/// <summary>
/// Wird geworfen, wenn eine Nachricht nicht dem erwarteten Wire-Format entspricht
/// (zu kurz, falsche <c>StructureSize</c>, ungültige Offsets …). Der Server übersetzt
/// dies generell in <c>STATUS_INVALID_PARAMETER</c> (Context §18, §19.1 Schritt 6).
/// </summary>
public sealed class SmbWireFormatException : Exception
{
    public SmbWireFormatException(string message) : base(message) { }
    public SmbWireFormatException(string message, Exception inner) : base(message, inner) { }
}
