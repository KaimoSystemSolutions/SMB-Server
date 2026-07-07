using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Security;

/// <summary>
/// An access control entry (MS-DTYP §2.4.4). Models the basic ACE types
/// (ACCESS_ALLOWED / ACCESS_DENIED / SYSTEM_AUDIT / SYSTEM_ALARM), whose body is
/// <c>AccessMask(4) · Sid</c>. Unknown/object ACE types are preserved verbatim in
/// <see cref="RawData"/> so a descriptor round-trips losslessly.
/// <para>ACE header: <c>AceType(1) · AceFlags(1) · AceSize(2)</c>, then the type-specific body.</para>
/// </summary>
public sealed class Ace
{
    private const int HeaderSize = 4;

    public required AceType Type { get; init; }
    public AceFlags Flags { get; init; }

    /// <summary>Access mask (rights granted/denied/audited). Meaningful for the basic ACE types.</summary>
    public uint AccessMask { get; init; }

    /// <summary>Trustee SID (set for the basic ACE types; <c>null</c> for a preserved unknown ACE).</summary>
    public Sid? Sid { get; init; }

    /// <summary>Verbatim body of an unknown/object ACE type (everything after the 4-byte header).</summary>
    public byte[]? RawData { get; init; }

    /// <summary>True for the basic ACE types this library evaluates.</summary>
    public bool IsBasic => Type is AceType.AccessAllowed or AceType.AccessDenied
                               or AceType.SystemAudit or AceType.SystemAlarm;

    /// <summary>Total encoded size in bytes (a multiple of 4).</summary>
    public int BinaryLength => HeaderSize + (IsBasic ? 4 + Sid!.BinaryLength : RawData?.Length ?? 0);

    // --- factories for the common cases ---

    public static Ace Allow(Sid sid, uint accessMask, AceFlags flags = AceFlags.None)
        => new() { Type = AceType.AccessAllowed, Flags = flags, AccessMask = accessMask, Sid = sid };

    public static Ace Deny(Sid sid, uint accessMask, AceFlags flags = AceFlags.None)
        => new() { Type = AceType.AccessDenied, Flags = flags, AccessMask = accessMask, Sid = sid };

    public static Ace Audit(Sid sid, uint accessMask, AceFlags flags)
        => new() { Type = AceType.SystemAudit, Flags = flags, AccessMask = accessMask, Sid = sid };

    // --- wire ---

    public static Ace Parse(ReadOnlySpan<byte> data, out int consumed)
    {
        if (data.Length < HeaderSize)
            throw new SmbWireFormatException($"ACE header needs {HeaderSize} bytes, has {data.Length}.");

        var type = (AceType)data[0];
        var flags = (AceFlags)data[1];
        int size = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(2, 2));
        if (size < HeaderSize || size > data.Length)
            throw new SmbWireFormatException($"ACE size {size} invalid (buffer {data.Length}).");

        ReadOnlySpan<byte> body = data.Slice(HeaderSize, size - HeaderSize);
        consumed = size;

        bool basic = type is AceType.AccessAllowed or AceType.AccessDenied
                          or AceType.SystemAudit or AceType.SystemAlarm;
        if (basic)
        {
            if (body.Length < 4)
                throw new SmbWireFormatException("ACE body too short for AccessMask.");
            uint mask = BinaryPrimitives.ReadUInt32LittleEndian(body.Slice(0, 4));
            Sid sid = Sid.Parse(body[4..]);
            return new Ace { Type = type, Flags = flags, AccessMask = mask, Sid = sid };
        }

        return new Ace { Type = type, Flags = flags, RawData = body.ToArray() };
    }

    public void Write(ref SpanWriter w)
    {
        int size = BinaryLength;
        w.WriteByte((byte)Type);
        w.WriteByte((byte)Flags);
        w.WriteUInt16((ushort)size);
        if (IsBasic)
        {
            w.WriteUInt32(AccessMask);
            Sid!.Write(ref w);
        }
        else if (RawData is { Length: > 0 })
        {
            w.WriteBytes(RawData);
        }
    }

    public byte[] ToBytes()
    {
        var bytes = new byte[BinaryLength];
        var w = new SpanWriter(bytes);
        Write(ref w);
        return bytes;
    }
}
