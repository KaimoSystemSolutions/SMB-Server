using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 CHANGE_NOTIFY Request/Response (Context §16, MS-SMB2 §2.2.35/§2.2.36) including the
/// FILE_NOTIFY_INFORMATION structure (MS-FSCC §2.7.1). Watches a directory handle for changes;
/// the response is usually delivered asynchronously (STATUS_PENDING + final response).
/// </summary>
public static class ChangeNotifyMessage
{
    public const ushort RequestStructureSize = 32;
    public const ushort ResponseStructureSize = 9;
    public const ushort FlagWatchTree = 0x0001;

    public readonly record struct Request(
        ushort Flags, uint OutputBufferLength, ulong PersistentId, ulong VolatileId, uint CompletionFilter)
    {
        public bool WatchTree => (Flags & FlagWatchTree) != 0;
    }

    public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != RequestStructureSize)
            throw new SmbWireFormatException($"CHANGE_NOTIFY Request StructureSize {ss} ≠ {RequestStructureSize}.");

        ushort flags = r.ReadUInt16();
        uint outputBufferLength = r.ReadUInt32();
        ulong persistent = r.ReadUInt64();
        ulong vol = r.ReadUInt64();
        uint completionFilter = r.ReadUInt32();
        r.Skip(4); // Reserved
        return new Request(flags, outputBufferLength, persistent, vol, completionFilter);
    }

    /// <summary>
    /// Builds the CHANGE_NOTIFY response from the changes (Action + directory-relative name).
    /// If the FILE_NOTIFY_INFORMATION list exceeds <paramref name="maxBufferLength"/>, <c>overflow</c>
    /// is set (the caller then replies with <c>STATUS_NOTIFY_ENUM_DIR</c> and an empty buffer — the
    /// client re-enumerates itself, MS-SMB2 §3.3.5.19).
    /// </summary>
    public static (byte[] body, bool overflow) BuildResponseBody(
        IReadOnlyList<(uint Action, string Name)> changes, uint maxBufferLength)
    {
        var buf = new GrowableWriter(64);
        for (int i = 0; i < changes.Count; i++)
        {
            int entryStart = buf.Position;
            byte[] name = Encoding.Unicode.GetBytes(changes[i].Name);

            int nextOffPos = buf.Position;
            buf.WriteUInt32(0);                    // NextEntryOffset (patched below if needed)
            buf.WriteUInt32(changes[i].Action);
            buf.WriteUInt32((uint)name.Length);    // FileNameLength in bytes
            buf.WriteBytes(name);

            if (i < changes.Count - 1)
            {
                int pad = (4 - (buf.Position % 4)) % 4; // entries are 4-byte aligned
                if (pad > 0) buf.WriteZeros(pad);
                buf.PatchUInt32(nextOffPos, (uint)(buf.Position - entryStart));
            }
        }

        byte[] notifyBuffer = buf.ToArray();
        if (notifyBuffer.Length > maxBufferLength)
            return (BuildEmptyResponseBody(), true);

        var body = new GrowableWriter(8 + notifyBuffer.Length);
        body.WriteUInt16(ResponseStructureSize);
        body.WriteUInt16((ushort)(Smb2Header.Size + 8)); // OutputBufferOffset = 72
        body.WriteUInt32((uint)notifyBuffer.Length);
        body.WriteBytes(notifyBuffer);
        return (body.ToArray(), false);
    }

    /// <summary>Response without content (OutputBufferLength 0) — for STATUS_NOTIFY_ENUM_DIR.</summary>
    public static byte[] BuildEmptyResponseBody()
    {
        var body = new byte[8];
        var w = new SpanWriter(body);
        w.WriteUInt16(ResponseStructureSize);
        w.WriteUInt16(0); // OutputBufferOffset (irrelevant when length is 0)
        w.WriteUInt32(0); // OutputBufferLength
        return body;
    }
}
