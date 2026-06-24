using System.Buffers.Binary;
using System.Text;

namespace Smb.Protocol.Wire;

/// <summary>
/// Vorwärts-schreibender Cursor über einen <see cref="Span{T}"/>. Little-Endian (SMB2).
/// Wächst nicht selbst — der Aufrufer stellt einen ausreichend großen Zielpuffer.
/// Für dynamisches Wachstum siehe <see cref="GrowableWriter"/>.
/// </summary>
public ref struct SpanWriter
{
    private readonly Span<byte> _buffer;
    private int _position;

    public SpanWriter(Span<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }

    public readonly int Position => _position;
    public readonly int Remaining => _buffer.Length - _position;

    public void Seek(int position)
    {
        if ((uint)position > (uint)_buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(position));
        _position = position;
    }

    public void WriteByte(byte value)
    {
        EnsureAvailable(1);
        _buffer[_position++] = value;
    }

    public void WriteUInt16(ushort value)
    {
        EnsureAvailable(2);
        BinaryPrimitives.WriteUInt16LittleEndian(_buffer.Slice(_position, 2), value);
        _position += 2;
    }

    public void WriteInt16(short value) => WriteUInt16(unchecked((ushort)value));

    public void WriteUInt32(uint value)
    {
        EnsureAvailable(4);
        BinaryPrimitives.WriteUInt32LittleEndian(_buffer.Slice(_position, 4), value);
        _position += 4;
    }

    public void WriteInt32(int value) => WriteUInt32(unchecked((uint)value));

    public void WriteUInt64(ulong value)
    {
        EnsureAvailable(8);
        BinaryPrimitives.WriteUInt64LittleEndian(_buffer.Slice(_position, 8), value);
        _position += 8;
    }

    public void WriteInt64(long value) => WriteUInt64(unchecked((ulong)value));

    public void WriteBytes(ReadOnlySpan<byte> value)
    {
        EnsureAvailable(value.Length);
        value.CopyTo(_buffer.Slice(_position, value.Length));
        _position += value.Length;
    }

    /// <summary>Schreibt einen String als UTF-16LE und liefert die geschriebene Byte-Länge.</summary>
    public int WriteUtf16(string value)
    {
        int byteCount = Encoding.Unicode.GetByteCount(value);
        EnsureAvailable(byteCount);
        Encoding.Unicode.GetBytes(value, _buffer.Slice(_position, byteCount));
        _position += byteCount;
        return byteCount;
    }

    /// <summary>Füllt bis zur nächsten <paramref name="alignment"/>-Byte-Grenze mit Nullen auf.</summary>
    public void AlignTo(int alignment)
    {
        int rem = _position % alignment;
        if (rem == 0) return;
        int pad = alignment - rem;
        EnsureAvailable(pad);
        _buffer.Slice(_position, pad).Clear();
        _position += pad;
    }

    /// <summary>Schreibt <paramref name="count"/> Nullbytes.</summary>
    public void WriteZeros(int count)
    {
        EnsureAvailable(count);
        _buffer.Slice(_position, count).Clear();
        _position += count;
    }

    /// <summary>Direktzugriff auf einen bereits geschriebenen Bereich (z.B. nachträgliches Patchen von Offsets).</summary>
    public readonly Span<byte> SliceWritten(int offset, int count)
    {
        if ((uint)offset > (uint)_position || (uint)count > (uint)(_position - offset))
            throw new ArgumentOutOfRangeException(nameof(offset));
        return _buffer.Slice(offset, count);
    }

    private readonly void EnsureAvailable(int count)
    {
        if (count < 0 || count > Remaining)
            throw new SmbWireFormatException(
                $"Schreiben über Pufferende hinaus: benötigt {count}, verfügbar {Remaining}.");
    }
}
