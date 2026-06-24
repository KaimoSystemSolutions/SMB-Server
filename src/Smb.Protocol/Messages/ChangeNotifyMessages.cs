using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 CHANGE_NOTIFY Request/Response (Context §16, MS-SMB2 §2.2.35/§2.2.36) inklusive der
/// FILE_NOTIFY_INFORMATION-Struktur (MS-FSCC §2.7.1). Überwacht ein Verzeichnis-Handle auf
/// Änderungen; die Antwort folgt i.d.R. asynchron (STATUS_PENDING + finale Antwort).
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
    /// Baut die CHANGE_NOTIFY-Response aus den Änderungen (Action + verzeichnis-relativer Name).
    /// Überschreitet die FILE_NOTIFY_INFORMATION-Liste <paramref name="maxBufferLength"/>, wird
    /// <c>overflow</c> gesetzt (der Aufrufer antwortet dann mit <c>STATUS_NOTIFY_ENUM_DIR</c> und
    /// leerem Puffer — der Client enumeriert selbst neu, MS-SMB2 §3.3.5.19).
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
            buf.WriteUInt32(0);                    // NextEntryOffset (ggf. unten gepatcht)
            buf.WriteUInt32(changes[i].Action);
            buf.WriteUInt32((uint)name.Length);    // FileNameLength in Bytes
            buf.WriteBytes(name);

            if (i < changes.Count - 1)
            {
                int pad = (4 - (buf.Position % 4)) % 4; // Entries 4-Byte-aligned
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

    /// <summary>Response ohne Inhalt (OutputBufferLength 0) — für STATUS_NOTIFY_ENUM_DIR.</summary>
    public static byte[] BuildEmptyResponseBody()
    {
        var body = new byte[8];
        var w = new SpanWriter(body);
        w.WriteUInt16(ResponseStructureSize);
        w.WriteUInt16(0); // OutputBufferOffset (irrelevant bei Länge 0)
        w.WriteUInt32(0); // OutputBufferLength
        return body;
    }
}
