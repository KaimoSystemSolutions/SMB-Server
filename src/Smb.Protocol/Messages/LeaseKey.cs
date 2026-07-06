using System.Buffers.Binary;

namespace Smb.Protocol.Messages;

/// <summary>
/// A 16-byte, client-assigned lease key (MS-SMB2 §2.2.13.2.8). Identifies a lease within the
/// scope of a client (ClientGuid); multiple opens of the same file by the same client that share
/// caching state carry the identical key. Stored as two little-endian 64-bit halves so it can be
/// used as a cheap, allocation-free dictionary key with value equality.
/// </summary>
public readonly struct LeaseKey : IEquatable<LeaseKey>
{
    public const int Size = 16;

    private readonly ulong _lo;
    private readonly ulong _hi;

    public LeaseKey(ulong lo, ulong hi)
    {
        _lo = lo;
        _hi = hi;
    }

    /// <summary>True for the all-zero key (i.e. "no lease key").</summary>
    public bool IsZero => _lo == 0 && _hi == 0;

    /// <summary>Reads a lease key from exactly 16 bytes (little-endian halves).</summary>
    public static LeaseKey From(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Size)
            throw new ArgumentException($"LeaseKey requires {Size} bytes, got {bytes.Length}.", nameof(bytes));
        return new LeaseKey(
            BinaryPrimitives.ReadUInt64LittleEndian(bytes),
            BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]));
    }

    /// <summary>Writes the key into a 16-byte destination.</summary>
    public void WriteTo(Span<byte> dest)
    {
        if (dest.Length < Size)
            throw new ArgumentException($"Destination needs at least {Size} bytes.", nameof(dest));
        BinaryPrimitives.WriteUInt64LittleEndian(dest, _lo);
        BinaryPrimitives.WriteUInt64LittleEndian(dest[8..], _hi);
    }

    /// <summary>Returns the key as a new 16-byte array.</summary>
    public byte[] ToBytes()
    {
        var b = new byte[Size];
        WriteTo(b);
        return b;
    }

    public bool Equals(LeaseKey other) => _lo == other._lo && _hi == other._hi;
    public override bool Equals(object? obj) => obj is LeaseKey other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(_lo, _hi);
    public static bool operator ==(LeaseKey left, LeaseKey right) => left.Equals(right);
    public static bool operator !=(LeaseKey left, LeaseKey right) => !left.Equals(right);

    public override string ToString() => Convert.ToHexString(ToBytes());
}
