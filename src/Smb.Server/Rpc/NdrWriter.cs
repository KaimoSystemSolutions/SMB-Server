using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Server.Rpc;

/// <summary>
/// Minimaler NDR-Encoder (NDR20, Little-Endian) für die hier benötigten SRVSVC-Strukturen
/// (MS-RPCE / C706). Deckt 4-Byte-Skalare, Unique-Pointer (Referent-IDs) und
/// conformant+varying NUL-terminierte Wide-Strings ab.
/// </summary>
public sealed class NdrWriter
{
    private readonly GrowableWriter _w = new(256);
    private uint _nextReferent = 0x00020000;

    public int Position => _w.Position;

    /// <summary>Richtet auf eine <paramref name="alignment"/>-Byte-Grenze aus (NDR-Alignment).</summary>
    public void Align(int alignment)
    {
        while (_w.Position % alignment != 0) _w.WriteByte(0);
    }

    public void UInt32(uint value)
    {
        Align(4);
        _w.WriteUInt32(value);
    }

    /// <summary>Schreibt eine neue, eindeutige (nicht-null) Referent-ID für einen Unique-Pointer.</summary>
    public void ReferentId()
    {
        UInt32(_nextReferent);
        _nextReferent += 4;
    }

    /// <summary>Schreibt einen Null-Pointer (Referent 0).</summary>
    public void NullPointer() => UInt32(0);

    /// <summary>
    /// Conformant+varying, NUL-terminierter Wide-String: MaxCount, Offset(0), ActualCount, Zeichen.
    /// Anschließend auf 4-Byte-Grenze aufgefüllt.
    /// </summary>
    public void WideStringNullTerminated(string value)
    {
        string s = value + "\0";
        UInt32((uint)s.Length); // MaxCount (inkl. NUL)
        UInt32(0);              // Offset
        UInt32((uint)s.Length); // ActualCount
        byte[] chars = Encoding.Unicode.GetBytes(s);
        foreach (byte b in chars) _w.WriteByte(b);
        Align(4);
    }

    public byte[] ToArray() => _w.ToArray();
}
