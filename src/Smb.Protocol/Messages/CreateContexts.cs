using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// A single SMB2 CREATE context (MS-SMB2 §2.2.13.2): a name-tagged, variable-length data blob
/// attached to a CREATE request/response. Used to carry leases, durable-handle requests,
/// maximal-access queries, etc. The <see cref="Name"/> is the raw tag (4 ASCII bytes for the
/// well-known contexts); <see cref="Tag"/> exposes it as a big-endian <see cref="uint"/> for
/// convenient comparison against <see cref="CreateContextNames"/>.
/// </summary>
public sealed class CreateContext
{
    public required byte[] Name { get; init; }
    public required byte[] Data { get; init; }

    /// <summary>The 4-byte name as a big-endian <see cref="uint"/> (0 if the name is not 4 bytes).</summary>
    public uint Tag => Name.Length == 4 ? BinaryPrimitives.ReadUInt32BigEndian(Name) : 0u;
}

/// <summary>Well-known CREATE context name tags (MS-SMB2 §2.2.13.2), as big-endian 4-byte ASCII.</summary>
public static class CreateContextNames
{
    /// <summary>"RqLs" — SMB2_CREATE_REQUEST_LEASE / _V2 (lease request; §2.2.13.2.8/§2.2.13.2.10).</summary>
    public const uint Lease = 0x52714C73;

    /// <summary>"DHnQ" — SMB2_CREATE_DURABLE_HANDLE_REQUEST (§2.2.13.2.3).</summary>
    public const uint DurableHandleRequest = 0x44486E51;

    /// <summary>"DHnC" — SMB2_CREATE_DURABLE_HANDLE_RECONNECT (§2.2.13.2.4).</summary>
    public const uint DurableHandleReconnect = 0x44486E43;

    /// <summary>"DH2Q" — SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 (§2.2.13.2.11).</summary>
    public const uint DurableHandleRequestV2 = 0x44483251;

    /// <summary>"DH2C" — SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 (§2.2.13.2.12).</summary>
    public const uint DurableHandleReconnectV2 = 0x44483243;

    /// <summary>"MxAc" — SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST (§2.2.13.2.5).</summary>
    public const uint MaximalAccess = 0x4D784163;

    /// <summary>"QFid" — SMB2_CREATE_QUERY_ON_DISK_ID (§2.2.13.2.9).</summary>
    public const uint QueryOnDiskId = 0x51466964;
}

/// <summary>
/// Parses and serializes the CREATE-context chain (MS-SMB2 §2.2.13.2). Each context has the layout
/// <c>Next(4) ‖ NameOffset(2) ‖ NameLength(2) ‖ Reserved(2) ‖ DataOffset(2) ‖ DataLength(4) ‖ Buffer</c>,
/// where the offsets are relative to the start of that context and <c>Next</c> chains to the
/// following one (0 = last). Contexts are 8-byte aligned.
/// </summary>
public static class CreateContextList
{
    /// <summary>
    /// Parses the chain that begins at <paramref name="contextsOffset"/> (relative to the whole
    /// <paramref name="message"/>) and spans <paramref name="contextsLength"/> bytes. A zero offset
    /// or length yields an empty list. Malformed offsets throw <see cref="SmbWireFormatException"/>.
    /// </summary>
    public static IReadOnlyList<CreateContext> Parse(ReadOnlySpan<byte> message, int contextsOffset, int contextsLength)
    {
        // In a real request an absent context chain is signalled by length 0 (offset is then also 0);
        // a zero offset with a non-zero length is legitimate when the chain starts at the buffer head.
        if (contextsLength <= 0)
            return Array.Empty<CreateContext>();
        if (contextsOffset < 0 || (uint)contextsOffset > (uint)message.Length
            || (uint)(contextsOffset + contextsLength) > (uint)message.Length)
            throw new SmbWireFormatException("CREATE contexts extend past the message.");

        var result = new List<CreateContext>();
        int cursor = contextsOffset;
        int chainEnd = contextsOffset + contextsLength;

        while (true)
        {
            if (cursor + 16 > chainEnd)
                throw new SmbWireFormatException("CREATE context header extends past the context chain.");

            ReadOnlySpan<byte> ctx = message[cursor..chainEnd];
            uint next = BinaryPrimitives.ReadUInt32LittleEndian(ctx);
            int nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(ctx[4..]);
            int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(ctx[6..]);
            // ctx[8..10] = Reserved
            int dataOffset = BinaryPrimitives.ReadUInt16LittleEndian(ctx[10..]);
            int dataLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(ctx[12..]);

            byte[] name = ReadSlice(ctx, nameOffset, nameLength, "name");
            byte[] data = dataLength > 0 ? ReadSlice(ctx, dataOffset, dataLength, "data") : Array.Empty<byte>();
            result.Add(new CreateContext { Name = name, Data = data });

            if (next == 0) break;
            long nextCursor = cursor + next;
            if (nextCursor <= cursor || nextCursor + 16 > chainEnd)
                throw new SmbWireFormatException("CREATE context Next offset out of range.");
            cursor = (int)nextCursor;
        }

        return result;
    }

    /// <summary>Returns the first context matching <paramref name="tag"/>, or <c>null</c>.</summary>
    public static CreateContext? Find(IReadOnlyList<CreateContext> contexts, uint tag)
    {
        foreach (CreateContext c in contexts)
            if (c.Tag == tag) return c;
        return null;
    }

    /// <summary>
    /// Serializes a list of contexts into a single, 8-byte-aligned chain (as embedded in a CREATE
    /// response's context buffer). Returns an empty array for an empty list.
    /// </summary>
    public static byte[] Serialize(IReadOnlyList<CreateContext> contexts)
    {
        if (contexts.Count == 0) return Array.Empty<byte>();

        var w = new GrowableWriter(64);
        for (int i = 0; i < contexts.Count; i++)
        {
            CreateContext c = contexts[i];
            bool isLast = i == contexts.Count - 1;
            int start = w.Position;

            w.WriteUInt32(0);                         // Next   @0 — patched below
            w.WriteUInt16(0);                         // NameOffset   @4 — patched below
            w.WriteUInt16((ushort)c.Name.Length);     // NameLength   @6
            w.WriteUInt16(0);                         // Reserved     @8
            w.WriteUInt16(0);                         // DataOffset   @10 — patched below
            w.WriteUInt32((uint)c.Data.Length);       // DataLength   @12

            int nameOffset = w.Position - start;
            w.WriteBytes(c.Name);
            w.PatchUInt16(start + 4, (ushort)nameOffset);

            int dataOffset = 0;
            if (c.Data.Length > 0)
            {
                w.AlignTo(8, start);
                dataOffset = w.Position - start;
                w.WriteBytes(c.Data);
            }
            w.PatchUInt16(start + 10, (ushort)dataOffset);

            if (!isLast)
            {
                w.AlignTo(8, start);
                w.PatchUInt32(start, (uint)(w.Position - start));
            }
        }
        return w.ToArray();
    }

    private static byte[] ReadSlice(ReadOnlySpan<byte> ctx, int offset, int length, string what)
    {
        if (length == 0) return Array.Empty<byte>();
        if (offset < 0 || length < 0 || (uint)(offset + length) > (uint)ctx.Length)
            throw new SmbWireFormatException($"CREATE context {what} extends past the context.");
        return ctx.Slice(offset, length).ToArray();
    }
}
