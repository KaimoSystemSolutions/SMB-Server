using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Server.Rpc;

/// <summary>
/// Minimal NDR encoder (NDR20, little-endian) for the SRVSVC structures needed here
/// (MS-RPCE / C706). Covers 4-byte scalars, unique pointers (referent IDs) and
/// conformant+varying NUL-terminated wide strings.
/// </summary>
public sealed class NdrWriter
{
    private readonly GrowableWriter _w = new(256);
    private uint _nextReferent = 0x00020000;

    public int Position => _w.Position;

    /// <summary>Aligns to an <paramref name="alignment"/>-byte boundary (NDR alignment).</summary>
    public void Align(int alignment)
    {
        while (_w.Position % alignment != 0) _w.WriteByte(0);
    }

    public void UInt16(ushort value)
    {
        Align(2);
        _w.WriteUInt16(value);
    }

    public void UInt32(uint value)
    {
        Align(4);
        _w.WriteUInt32(value);
    }

    /// <summary>Writes raw bytes verbatim (no alignment); used for fixed-size octet fields.</summary>
    public void Bytes(ReadOnlySpan<byte> value)
    {
        foreach (byte b in value) _w.WriteByte(b);
    }

    /// <summary>
    /// Writes a fixed-length WCHAR array (<paramref name="lengthChars"/> UTF-16 code units): the value is
    /// NUL-terminated, then truncated or zero-padded to exactly the fixed width. No count prefix (NDR fixed array).
    /// </summary>
    public void FixedWideString(string value, int lengthChars)
    {
        Span<byte> chars = new byte[lengthChars * 2]; // zero-filled = NUL padding
        int copy = Math.Min(value.Length, lengthChars - 1); // reserve one code unit for the terminator
        if (copy > 0) Encoding.Unicode.GetBytes(value.AsSpan(0, copy), chars);
        Bytes(chars);
    }

    /// <summary>Writes a new, unique (non-null) referent ID for a unique pointer.</summary>
    public void ReferentId()
    {
        UInt32(_nextReferent);
        _nextReferent += 4;
    }

    /// <summary>Writes a null pointer (referent 0).</summary>
    public void NullPointer() => UInt32(0);

    /// <summary>
    /// Conformant+varying, NUL-terminated wide string: MaxCount, Offset(0), ActualCount, chars.
    /// Padded to a 4-byte boundary afterwards.
    /// </summary>
    public void WideStringNullTerminated(string value)
    {
        string s = value + "\0";
        UInt32((uint)s.Length); // MaxCount (incl. NUL)
        UInt32(0);              // Offset
        UInt32((uint)s.Length); // ActualCount
        byte[] chars = Encoding.Unicode.GetBytes(s);
        foreach (byte b in chars) _w.WriteByte(b);
        Align(4);
    }

    public byte[] ToArray() => _w.ToArray();
}
