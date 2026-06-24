using System.Buffers.Binary;
using System.Text;

namespace Smb.Protocol.Wire;

/// <summary>
/// Allokationsarmer, vorwärts-lesender Cursor über einen <see cref="ReadOnlySpan{T}"/>.
/// Alle Mehrbyte-Felder werden <b>Little-Endian</b> gelesen — das entspricht SMB2
/// (Context §2, §23: "SMB2 = Little-Endian"). Das einzige Big-Endian-Feld im Protokoll
/// ist das NBSS-Längenpräfix; dieses wird gesondert in <c>NbssFrame</c> behandelt.
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

    /// <summary>Aktuelle Leseposition (Offset ab Beginn des Puffers).</summary>
    public readonly int Position => _position;

    /// <summary>Anzahl noch nicht gelesener Bytes.</summary>
    public readonly int Remaining => _buffer.Length - _position;

    /// <summary>Gesamtlänge des zugrunde liegenden Puffers.</summary>
    public readonly int Length => _buffer.Length;

    /// <summary>Setzt die Leseposition absolut (z.B. um einem Offset-Feld zu folgen).</summary>
    public void Seek(int position)
    {
        if ((uint)position > (uint)_buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(position));
        _position = position;
    }

    /// <summary>Überspringt <paramref name="count"/> Bytes.</summary>
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

    /// <summary>Liest <paramref name="count"/> Bytes als (nicht kopierten) Slice.</summary>
    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        EnsureAvailable(count);
        ReadOnlySpan<byte> slice = _buffer.Slice(_position, count);
        _position += count;
        return slice;
    }

    /// <summary>Kopiert <paramref name="count"/> Bytes in ein neues Array.</summary>
    public byte[] ReadByteArray(int count) => ReadBytes(count).ToArray();

    /// <summary>Liest einen UTF-16LE-String fester Byte-Länge (SMB2-Namensfelder).</summary>
    public string ReadUtf16(int byteLength)
    {
        ReadOnlySpan<byte> slice = ReadBytes(byteLength);
        return Encoding.Unicode.GetString(slice);
    }

    /// <summary>Liefert einen Slice an absoluter Position, ohne den Cursor zu bewegen.</summary>
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
                $"Lesen über Pufferende hinaus: benötigt {count}, verfügbar {Remaining} (Position {_position}/{_buffer.Length}).");
    }
}
