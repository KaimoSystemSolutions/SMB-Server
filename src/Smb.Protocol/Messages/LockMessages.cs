using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>Flags of an SMB2_LOCK element (MS-SMB2 §2.2.26.1).</summary>
[Flags]
public enum LockFlags : uint
{
    None = 0x00000000,
    SharedLock = 0x00000001,
    ExclusiveLock = 0x00000002,
    Unlock = 0x00000004,
    FailImmediately = 0x00000010,
}

/// <summary>A single byte-range lock element of the LOCK request (MS-SMB2 §2.2.26.1).</summary>
public readonly record struct LockEntry(ulong Offset, ulong Length, uint Flags)
{
    public bool IsUnlock => (Flags & (uint)LockFlags.Unlock) != 0;
    public bool IsExclusive => (Flags & (uint)LockFlags.ExclusiveLock) != 0;
    public bool IsShared => (Flags & (uint)LockFlags.SharedLock) != 0;
    public bool FailImmediately => (Flags & (uint)LockFlags.FailImmediately) != 0;
}

/// <summary>SMB2 LOCK Request/Response (Context §15, MS-SMB2 §2.2.26/§2.2.27).</summary>
public static class LockMessage
{
    public const ushort RequestStructureSize = 48;
    public const ushort ResponseStructureSize = 4;
    public const int LockElementSize = 24; // Offset(8) + Length(8) + Flags(4) + Reserved(4)

    public sealed record Request(
        ulong PersistentId,
        ulong VolatileId,
        uint LockSequence,
        IReadOnlyList<LockEntry> Locks);

    public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != RequestStructureSize)
            throw new SmbWireFormatException($"LOCK Request StructureSize {ss} ≠ {RequestStructureSize}.");

        ushort lockCount = r.ReadUInt16();
        uint lockSequence = r.ReadUInt32();         // LockSequenceNumber(4 bits) ‖ LockSequenceIndex(28 bits)
        ulong persistent = r.ReadUInt64();
        ulong vol = r.ReadUInt64();

        if (lockCount == 0)
            throw new SmbWireFormatException("LOCK request with LockCount 0.");

        var locks = new LockEntry[lockCount];
        for (int i = 0; i < lockCount; i++)
        {
            ulong offset = r.ReadUInt64();
            ulong length = r.ReadUInt64();
            uint flags = r.ReadUInt32();
            r.Skip(4);                              // Reserved
            locks[i] = new LockEntry(offset, length, flags);
        }

        return new Request(persistent, vol, lockSequence, locks);
    }

    /// <summary>Builds the LOCK response (fixed 4-byte body).</summary>
    public static byte[] BuildResponseBody()
    {
        var body = new byte[4];
        var w = new SpanWriter(body);
        w.WriteUInt16(ResponseStructureSize);
        w.WriteUInt16(0);                           // Reserved
        return body;
    }
}
