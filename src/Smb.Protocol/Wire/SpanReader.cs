using System.Buffers.Binary;
using System.Text;

namespace Smb.Protocol.Wire;

/// <summary>
/// Allocation-light, forward-reading cursor over a <see cref="ReadOnlySpan{T}"/>.
/// All multi-byte fields are read <b>little-endian</b> — matching SMB2
/// (Context §2, §23: "SMB2 = little-endian"). The only big-endian field in the protocol
/// is the NBSS length prefix; that is handled separately in <c>NbssFrame</c>.
/// </summary>
public ref struct SpanReader
{
    private readonly ReadOnlySpan<byte> _buffer;
    private int _position;

    public SpanReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }

    /// <summary>Current read position (offset from the start of the buffer).</summary>
    public readonly int Position => _position;

    /// <summary>Number of bytes not yet read.</summary>
    public readonly int Remaining => _buffer.Length - _position;

    /// <summary>Total length of the underlying buffer.</summary>
    public readonly int Length => _buffer.Length;

    /// <summary>Sets the read position absolutely (e.g. to follow an offset field).</summary>
    public void Seek(int position)
    {
        if ((uint)position > (uint)_buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(position));
        _position = position;
    }

    /// <summary>Skips <paramref name="count"/> bytes.</summary>
    public void Skip(int count)
    {
        EnsureAvailable(count);
        _position += count;
    }

    public byte ReadByte()
    {
        EnsureAvailable(1);
        return _buffer[_position++];
    }

    public ushort ReadUInt16()
    {
        EnsureAvailable(2);
        ushort value = BinaryPrimitives.ReadUInt16LittleEndian(_buffer.Slice(_position, 2));
        _position += 2;
        return value;
    }

    public short ReadInt16() => unchecked((short)ReadUInt16());

    public uint ReadUInt32()
    {
        EnsureAvailable(4);
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.Slice(_position, 4));
        _position += 4;
        return value;
    }

    public int ReadInt32() => unchecked((int)ReadUInt32());

    public ulong ReadUInt64()
    {
        EnsureAvailable(8);
        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(_buffer.Slice(_position, 8));
        _position += 8;
        return value;
    }

    public long ReadInt64() => unchecked((long)ReadUInt64());

    /// <summary>Reads <paramref name="count"/> bytes as a (non-copied) slice.</summary>
    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        EnsureAvailable(count);
        ReadOnlySpan<byte> slice = _buffer.Slice(_position, count);
        _position += count;
        return slice;
    }

    /// <summary>Copies <paramref name="count"/> bytes into a new array.</summary>
    public byte[] ReadByteArray(int count) => ReadBytes(count).ToArray();

    /// <summary>Reads a UTF-16LE string of fixed byte length (SMB2 name fields).</summary>
    public string ReadUtf16(int byteLength)
    {
        ReadOnlySpan<byte> slice = ReadBytes(byteLength);
        return Encoding.Unicode.GetString(slice);
    }

    /// <summary>Returns a slice at an absolute position without moving the cursor.</summary>
    public readonly ReadOnlySpan<byte> Slice(int offset, int count)
    {
        if ((uint)offset > (uint)_buffer.Length || (uint)count > (uint)(_buffer.Length - offset))
            throw new ArgumentOutOfRangeException(nameof(offset));
        return _buffer.Slice(offset, count);
    }

    private readonly void EnsureAvailable(int count)
    {
        if (count < 0 || count > Remaining)
            throw new SmbWireFormatException(
                $"Read past end of buffer: needs {count}, available {Remaining} (position {_position}/{_buffer.Length}).");
    }
}
