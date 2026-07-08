using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages.Fscc;

/// <summary>
/// One entry for FILE_STREAM_INFORMATION (MS-FSCC §2.4.43). <see cref="StreamName"/> is the bare
/// stream name (empty for the default unnamed <c>$DATA</c> stream); the serializer decorates it as
/// <c>:name:$DATA</c> (or <c>::$DATA</c> for the default).
/// </summary>
public readonly record struct FsccStreamEntry(string StreamName, long Size, long AllocationSize);

/// <summary>
/// One FILE_FULL_EA_INFORMATION entry (MS-FSCC §2.4.15): a named extended attribute with an opaque
/// value and flags (e.g. FILE_NEED_EA = 0x80). <see cref="Name"/> is an OEM/ASCII string.
/// </summary>
public readonly record struct FsccEaEntry(byte Flags, string Name, byte[] Value);

/// <summary>
/// Serialization of FILE_STREAM_INFORMATION (Phase 9 / M9.1, MS-FSCC §2.4.43): a chained list of the
/// named data streams of a file. Pure — the backend supplies the stream list.
/// </summary>
public static class StreamInformation
{
    /// <summary>
    /// Serializes the stream list as a chained FILE_STREAM_INFORMATION array. Entries are 8-byte
    /// aligned and linked via <c>NextEntryOffset</c>; the last has <c>NextEntryOffset = 0</c>. An empty
    /// list produces an empty buffer (e.g. a directory has no data streams).
    /// </summary>
    public static byte[] Build(IReadOnlyList<FsccStreamEntry> streams)
    {
        if (streams.Count == 0)
            return [];

        var serialized = new List<byte[]>(streams.Count);
        foreach (FsccStreamEntry s in streams)
            serialized.Add(SerializeEntry(s));

        var w = new GrowableWriter(64);
        for (int i = 0; i < serialized.Count; i++)
        {
            int entryStart = w.Position;
            w.WriteBytes(serialized[i]);

            bool last = i == serialized.Count - 1;
            if (!last)
            {
                int padded = Align8(w.Position - entryStart);
                int pad = padded - (w.Position - entryStart);
                if (pad > 0) w.WriteZeros(pad);
                w.PatchUInt32(entryStart, (uint)(w.Position - entryStart)); // NextEntryOffset
            }
            else
            {
                w.PatchUInt32(entryStart, 0);
            }
        }
        return w.ToArray();
    }

    private static byte[] SerializeEntry(FsccStreamEntry s)
    {
        // Wire form of the stream name: ":<name>:$DATA" — ":" + name + ":$DATA"; default = "::$DATA".
        byte[] name = Encoding.Unicode.GetBytes($":{s.StreamName}:$DATA");
        var w = new GrowableWriter(24 + name.Length);
        w.WriteUInt32(0);                        // NextEntryOffset (patched by caller)
        w.WriteUInt32((uint)name.Length);        // StreamNameLength (bytes)
        w.WriteUInt64((ulong)s.Size);            // StreamSize
        w.WriteUInt64((ulong)s.AllocationSize);  // StreamAllocationSize
        w.WriteBytes(name);
        return w.ToArray();
    }

    private static int Align8(int v) => (v + 7) & ~7;
}

/// <summary>
/// Serialization and parsing of FILE_FULL_EA_INFORMATION (Phase 9 / M9.2, MS-FSCC §2.4.15): the
/// chained extended-attribute list used by QUERY_INFO / SET_INFO. Pure.
/// </summary>
public static class FullEaInformation
{
    /// <summary>Serializes the EA list as a chained FILE_FULL_EA_INFORMATION array (4-byte aligned).</summary>
    public static byte[] Build(IReadOnlyList<FsccEaEntry> eas)
    {
        if (eas.Count == 0)
            return [];

        var serialized = new List<byte[]>(eas.Count);
        foreach (FsccEaEntry ea in eas)
            serialized.Add(SerializeEntry(ea));

        var w = new GrowableWriter(64);
        for (int i = 0; i < serialized.Count; i++)
        {
            int entryStart = w.Position;
            w.WriteBytes(serialized[i]);

            bool last = i == serialized.Count - 1;
            if (!last)
            {
                int padded = Align4(w.Position - entryStart);
                int pad = padded - (w.Position - entryStart);
                if (pad > 0) w.WriteZeros(pad);
                w.PatchUInt32(entryStart, (uint)(w.Position - entryStart)); // NextEntryOffset
            }
            else
            {
                w.PatchUInt32(entryStart, 0);
            }
        }
        return w.ToArray();
    }

    private static byte[] SerializeEntry(FsccEaEntry ea)
    {
        byte[] name = Encoding.ASCII.GetBytes(ea.Name);
        byte[] value = ea.Value ?? [];
        var w = new GrowableWriter(8 + name.Length + 1 + value.Length);
        w.WriteUInt32(0);                        // NextEntryOffset (patched by caller)
        w.WriteByte(ea.Flags);                   // Flags
        w.WriteByte((byte)name.Length);          // EaNameLength (excl. null)
        w.WriteUInt16((ushort)value.Length);     // EaValueLength
        w.WriteBytes(name);
        w.WriteByte(0);                          // null terminator
        w.WriteBytes(value);
        return w.ToArray();
    }

    /// <summary>
    /// Parses a chained FILE_FULL_EA_INFORMATION buffer (SET_INFO input). An entry with a zero-length
    /// value is a delete request (MS-FSCC §2.4.15 / §3.1.5). Names are treated case-insensitively by the
    /// backend; here they are returned verbatim.
    /// </summary>
    public static IReadOnlyList<FsccEaEntry> Parse(ReadOnlySpan<byte> buffer)
    {
        var result = new List<FsccEaEntry>();
        int offset = 0;
        while (offset < buffer.Length)
        {
            var r = new SpanReader(buffer[offset..]);
            uint next = r.ReadUInt32();
            byte flags = r.ReadByte();
            int nameLen = r.ReadByte();
            int valueLen = r.ReadUInt16();
            string name = nameLen > 0 ? Encoding.ASCII.GetString(r.ReadBytes(nameLen)) : string.Empty;
            r.ReadByte();                        // null terminator
            byte[] value = valueLen > 0 ? r.ReadByteArray(valueLen) : [];
            result.Add(new FsccEaEntry(flags, name, value));

            if (next == 0)
                break;
            offset += (int)next;
        }
        return result;
    }

    /// <summary>
    /// Computes the value reported by FileEaInformation (MS-FSCC §2.4.12): the number of bytes the
    /// full EA list would occupy — 4 (NextEntryOffset) + 4 (Flags/NameLen/ValueLen) + name + 1 (null) +
    /// value, per entry, 4-byte aligned like the serialized form.
    /// </summary>
    public static uint ComputeEaSize(IReadOnlyList<FsccEaEntry> eas)
    {
        long total = 0;
        for (int i = 0; i < eas.Count; i++)
        {
            int entry = 8 + eas[i].Name.Length + 1 + (eas[i].Value?.Length ?? 0);
            total += i == eas.Count - 1 ? entry : Align4(entry);
        }
        return (uint)total;
    }

    private static int Align4(int v) => (v + 3) & ~3;
}
