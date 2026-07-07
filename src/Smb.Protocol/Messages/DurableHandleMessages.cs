using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// Parse/serialize helpers for the durable-handle CREATE contexts (MS-SMB2 §2.2.13.2.3/4/11/12,
/// §2.2.14.2.3/12). A durable handle survives a transport disconnect: the client re-opens it after
/// reconnecting by echoing the original FileId (v1) or the durable create GUID (v2).
/// <list type="bullet">
/// <item><b>v1 request</b> "DHnQ" — 16-byte reserved <c>DurableRequest</c> (no meaningful fields).</item>
/// <item><b>v1 response</b> "DHnQ" — 8-byte reserved.</item>
/// <item><b>v1 reconnect</b> "DHnC" — a 16-byte <c>SMB2_FILEID</c> (Persistent(8) ‖ Volatile(8)).</item>
/// <item><b>v2 request</b> "DH2Q" — <c>Timeout(4) ‖ Flags(4) ‖ Reserved(8) ‖ CreateGuid(16)</c>.</item>
/// <item><b>v2 response</b> "DH2Q" — <c>Timeout(4) ‖ Flags(4)</c>.</item>
/// <item><b>v2 reconnect</b> "DH2C" — <c>FileId(16) ‖ CreateGuid(16) ‖ Flags(4)</c>.</item>
/// </list>
/// </summary>
public static class DurableHandleMessages
{
    /// <summary>SMB2_DHANDLE_FLAG_PERSISTENT — the handle is persistent (CA share), v2 only.</summary>
    public const uint FlagPersistent = 0x00000002;

    // --- v1 ---

    /// <summary>Builds the "DHnQ" durable-handle response context (8-byte reserved, §2.2.14.2.3).</summary>
    public static CreateContext BuildV1ResponseContext()
        => new() { Name = NameBytes(CreateContextNames.DurableHandleRequest), Data = new byte[8] };

    /// <summary>Data of a "DHnC" reconnect context: the FileId to restore.</summary>
    public static byte[] BuildReconnectData(ulong persistentId, ulong volatileId)
    {
        var data = new byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(data, persistentId);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(8), volatileId);
        return data;
    }

    /// <summary>Parses the FileId out of a "DHnC" reconnect context's data.</summary>
    public static (ulong persistentId, ulong volatileId) ParseReconnect(ReadOnlySpan<byte> data)
    {
        if (data.Length < 16)
            throw new SmbWireFormatException($"Durable reconnect needs 16 bytes, has {data.Length}.");
        return (BinaryPrimitives.ReadUInt64LittleEndian(data),
                BinaryPrimitives.ReadUInt64LittleEndian(data[8..]));
    }

    // --- v2 ---

    /// <summary>Parsed "DH2Q" durable-handle-v2 request.</summary>
    public readonly record struct V2Request(uint TimeoutMs, uint Flags, Guid CreateGuid)
    {
        public bool IsPersistent => (Flags & FlagPersistent) != 0;
    }

    /// <summary>Parses a "DH2Q" durable-handle-v2 request context (§2.2.13.2.11).</summary>
    public static V2Request ParseV2Request(ReadOnlySpan<byte> data)
    {
        if (data.Length < 32)
            throw new SmbWireFormatException($"Durable v2 request needs 32 bytes, has {data.Length}.");
        uint timeout = BinaryPrimitives.ReadUInt32LittleEndian(data);
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(data[4..]);
        // data[8..16] reserved
        var guid = new Guid(data.Slice(16, 16));
        return new V2Request(timeout, flags, guid);
    }

    /// <summary>Builds the "DH2Q" durable-handle-v2 response context (Timeout(4) ‖ Flags(4), §2.2.14.2.12).</summary>
    public static CreateContext BuildV2ResponseContext(uint timeoutMs, bool persistent)
    {
        var data = new byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(data, timeoutMs);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), persistent ? FlagPersistent : 0u);
        return new CreateContext { Name = NameBytes(CreateContextNames.DurableHandleRequestV2), Data = data };
    }

    /// <summary>Parsed "DH2C" durable-handle-v2 reconnect.</summary>
    public readonly record struct V2Reconnect(ulong PersistentId, ulong VolatileId, Guid CreateGuid, uint Flags)
    {
        public bool IsPersistent => (Flags & FlagPersistent) != 0;
    }

    /// <summary>Parses a "DH2C" durable-handle-v2 reconnect context (§2.2.13.2.12).</summary>
    public static V2Reconnect ParseV2Reconnect(ReadOnlySpan<byte> data)
    {
        if (data.Length < 36)
            throw new SmbWireFormatException($"Durable v2 reconnect needs 36 bytes, has {data.Length}.");
        ulong persistent = BinaryPrimitives.ReadUInt64LittleEndian(data);
        ulong vol = BinaryPrimitives.ReadUInt64LittleEndian(data[8..]);
        var guid = new Guid(data.Slice(16, 16));
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(data[32..]);
        return new V2Reconnect(persistent, vol, guid, flags);
    }

    /// <summary>Builds the data of a "DH2C" reconnect context (for a client / tests).</summary>
    public static byte[] BuildV2ReconnectData(ulong persistentId, ulong volatileId, Guid createGuid, bool persistent)
    {
        var data = new byte[36];
        BinaryPrimitives.WriteUInt64LittleEndian(data, persistentId);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(8), volatileId);
        createGuid.TryWriteBytes(data.AsSpan(16, 16));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(32), persistent ? FlagPersistent : 0u);
        return data;
    }

    /// <summary>Builds the data of a "DH2Q" v2 request context (for a client / tests).</summary>
    public static byte[] BuildV2RequestData(uint timeoutMs, Guid createGuid, bool persistent)
    {
        var data = new byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(data, timeoutMs);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), persistent ? FlagPersistent : 0u);
        createGuid.TryWriteBytes(data.AsSpan(16, 16));
        return data;
    }

    /// <summary>The 4-byte big-endian ASCII name for a well-known context tag.</summary>
    public static byte[] NameBytes(uint tag)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, tag);
        return b;
    }
}
