using System.Buffers.Binary;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Server.Rpc;

/// <summary>
/// Minimal NDR decoder (NDR20, little-endian) — the read counterpart to <see cref="NdrWriter"/>.
/// Covers 2/4-byte scalars, unique-pointer referent IDs, alignment, and conformant+varying
/// NUL-terminated wide strings (the shapes the witness <c>WitnessrRegister(Ex)</c> request stub
/// uses). A truncated or malformed stub raises <see cref="SmbWireFormatException"/> so the caller
/// can fault the RPC cleanly instead of throwing an index-out-of-range.
/// </summary>
public sealed class NdrReader
{
    private readonly ReadOnlyMemory<byte> _buf;
    private int _pos;

    public NdrReader(ReadOnlyMemory<byte> buffer) => _buf = buffer;

    /// <summary>Bytes still unread.</summary>
    public int Remaining => _buf.Length - _pos;

    private ReadOnlySpan<byte> Span => _buf.Span;

    private void Require(int count)
    {
        if (_pos + count > _buf.Length)
            throw new SmbWireFormatException("NDR stub truncated.");
    }

    /// <summary>Advances the cursor to the next <paramref name="alignment"/>-byte boundary (NDR alignment).</summary>
    public void Align(int alignment)
    {
        while (_pos % alignment != 0)
        {
            Require(1);
            _pos++;
        }
    }

    public ushort UInt16()
    {
        Align(2);
        Require(2);
        ushort v = BinaryPrimitives.ReadUInt16LittleEndian(Span.Slice(_pos, 2));
        _pos += 2;
        return v;
    }

    public uint UInt32()
    {
        Align(4);
        Require(4);
        uint v = BinaryPrimitives.ReadUInt32LittleEndian(Span.Slice(_pos, 4));
        _pos += 4;
        return v;
    }

    /// <summary>Reads a unique-pointer referent ID (0 = null pointer).</summary>
    public uint ReferentId() => UInt32();

    /// <summary>Reads <paramref name="count"/> raw bytes verbatim (no alignment); the counterpart to <see cref="NdrWriter.Bytes"/>.</summary>
    public ReadOnlySpan<byte> Bytes(int count)
    {
        Require(count);
        ReadOnlySpan<byte> s = Span.Slice(_pos, count);
        _pos += count;
        return s;
    }

    /// <summary>Reads a fixed-length WCHAR array (<paramref name="lengthChars"/> code units), trimmed at the first NUL.</summary>
    public string FixedWideString(int lengthChars)
    {
        ReadOnlySpan<byte> raw = Bytes(lengthChars * 2);
        string s = Encoding.Unicode.GetString(raw);
        int nul = s.IndexOf('\0');
        return nul >= 0 ? s[..nul] : s;
    }

    /// <summary>
    /// Reads a conformant+varying, NUL-terminated wide string (MaxCount, Offset, ActualCount, chars),
    /// returning the value without the trailing NUL and re-aligning to 4 bytes. <paramref name="maxChars"/>
    /// caps ActualCount so a hostile stub cannot request an unbounded allocation.
    /// </summary>
    public string WideStringNullTerminated(int maxChars = 32768)
    {
        uint maxCount = UInt32();
        uint offset = UInt32();
        uint actualCount = UInt32();
        if (offset != 0 || actualCount > maxCount || actualCount > (uint)maxChars)
            throw new SmbWireFormatException("NDR wide string bounds invalid.");

        int byteLen = checked((int)actualCount * 2);
        Require(byteLen);
        string s = Encoding.Unicode.GetString(Span.Slice(_pos, byteLen));
        _pos += byteLen;
        Align(4);
        return actualCount > 0 && s[^1] == '\0' ? s[..^1] : s;
    }
}
