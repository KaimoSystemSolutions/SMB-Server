using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Security;

/// <summary>
/// An access control list (MS-DTYP §2.4.5) — an ordered sequence of <see cref="Ace"/>. Used for both
/// the DACL (discretionary, access control) and SACL (system, auditing) of a
/// <see cref="SecurityDescriptor"/>.
/// <para>Header: <c>AclRevision(1) · Sbz1(1) · AclSize(2) · AceCount(2) · Sbz2(2)</c>, then the ACEs.</para>
/// </summary>
public sealed class Acl
{
    /// <summary>ACL_REVISION — the usual revision for file-system ACLs.</summary>
    public const byte RevisionDefault = 2;

    /// <summary>ACL_REVISION_DS — used when object ACEs are present (directory services).</summary>
    public const byte RevisionDs = 4;

    private const int HeaderSize = 8;

    public byte Revision { get; init; } = RevisionDefault;

    public IReadOnlyList<Ace> Aces { get; init; } = [];

    /// <summary>Encoded size in bytes (header + all ACEs).</summary>
    public int BinaryLength
    {
        get
        {
            int total = HeaderSize;
            foreach (Ace ace in Aces) total += ace.BinaryLength;
            return total;
        }
    }

    public static Acl Parse(ReadOnlySpan<byte> data, out int consumed)
    {
        if (data.Length < HeaderSize)
            throw new SmbWireFormatException($"ACL header needs {HeaderSize} bytes, has {data.Length}.");

        byte revision = data[0];
        int size = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(2, 2));
        int aceCount = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(4, 2));
        if (size < HeaderSize || size > data.Length)
            throw new SmbWireFormatException($"ACL size {size} invalid (buffer {data.Length}).");

        var aces = new List<Ace>(aceCount);
        int pos = HeaderSize;
        for (int i = 0; i < aceCount; i++)
        {
            Ace ace = Ace.Parse(data.Slice(pos, size - pos), out int used);
            aces.Add(ace);
            pos += used;
        }

        consumed = size;   // AclSize is authoritative (may include trailing padding)
        return new Acl { Revision = revision, Aces = aces };
    }

    public void Write(ref SpanWriter w)
    {
        w.WriteByte(Revision);
        w.WriteByte(0);                          // Sbz1
        w.WriteUInt16((ushort)BinaryLength);
        w.WriteUInt16((ushort)Aces.Count);
        w.WriteUInt16(0);                        // Sbz2
        foreach (Ace ace in Aces) ace.Write(ref w);
    }

    public byte[] ToBytes()
    {
        var bytes = new byte[BinaryLength];
        var w = new SpanWriter(bytes);
        Write(ref w);
        return bytes;
    }
}
