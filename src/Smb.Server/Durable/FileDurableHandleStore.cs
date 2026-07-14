using System.Collections.Concurrent;
using System.Text.Json;

namespace Smb.Server.Durable;

/// <summary>
/// A durable-handle store that persists <c>IsPersistent</c> (continuously-available) handle metadata to a
/// directory so those handles survive a full server restart (C2). Non-persistent durable handles behave
/// exactly like <see cref="InMemoryDurableHandleStore"/> (warm, in-process, survive a TCP drop but not a
/// restart); persistent handles additionally get a <see cref="PersistentHandleRecord"/> written as one JSON
/// file per FileId. On construction the directory is scanned and every record is loaded as a <i>cold</i>
/// entry, which the dispatcher claims and rehydrates on reconnect.
/// <para>Thread-safe: connection loops add/claim/persist concurrently. File writes are atomic (temp + move).</para>
/// </summary>
public sealed class FileDurableHandleStore : IDurableHandleStore, IPersistentHandleStore
{
    private readonly string _directory;
    private readonly ConcurrentDictionary<(ulong, ulong), DurableHandle> _warm = new();
    private readonly ConcurrentDictionary<(ulong, ulong), PersistentHandleRecord> _cold = new();

    public FileDurableHandleStore(string directory)
    {
        _directory = directory;
        Directory.CreateDirectory(_directory);
        LoadCold();
    }

    public ulong HighestPersistentId { get; private set; }

    // --- IDurableHandleStore (warm behavior mirrors InMemoryDurableHandleStore) ---------------------

    public void Add(DurableHandle handle) => _warm[handle.Key] = handle;

    public bool TryClaim(ulong persistentId, ulong volatileId, out DurableHandle handle)
        => _warm.TryRemove((persistentId, volatileId), out handle!);

    public IReadOnlyList<DurableHandle> TakeExpired(DateTimeOffset now)
    {
        var expired = new List<DurableHandle>();
        foreach (DurableHandle h in _warm.Values)
        {
            if (h.IsPersistent || h.Deadline > now)
                continue;
            if (_warm.TryRemove(h.Key, out DurableHandle? removed))
                expired.Add(removed);
        }
        return expired;
    }

    /// <summary>
    /// Removes and returns all <b>warm</b> handles (shutdown/drain). Persistent <i>records</i> on storage are
    /// deliberately left in place so a restart can rehydrate them — only <see cref="RemovePersisted"/> (a real
    /// close) deletes them.
    /// </summary>
    public IReadOnlyList<DurableHandle> TakeAll()
    {
        var all = new List<DurableHandle>(_warm.Values);
        _warm.Clear();
        return all;
    }

    // --- IPersistentHandleStore --------------------------------------------------------------------

    public void Persist(PersistentHandleRecord record)
    {
        WriteRecord(record);
        HighestPersistentId = Math.Max(HighestPersistentId, record.PersistentId);
    }

    public void RemovePersisted(ulong persistentId, ulong volatileId)
    {
        _cold.TryRemove((persistentId, volatileId), out _);
        try { File.Delete(RecordPath(persistentId, volatileId)); }
        catch (DirectoryNotFoundException) { /* already gone */ }
    }

    public bool TryClaimColdRecord(ulong persistentId, ulong volatileId, out PersistentHandleRecord record)
        => _cold.TryRemove((persistentId, volatileId), out record!);

    public void ReturnColdRecord(PersistentHandleRecord record) => _cold[(record.PersistentId, record.VolatileId)] = record;

    // --- persistence ------------------------------------------------------------------------------

    private void LoadCold()
    {
        foreach (string file in Directory.EnumerateFiles(_directory, "*.json"))
        {
            PersistentHandleRecord? record;
            try { record = JsonSerializer.Deserialize<PersistentHandleRecord>(File.ReadAllBytes(file)); }
            catch (JsonException) { continue; } // skip a corrupt/partial record rather than fail startup
            if (record is null) continue;
            _cold[(record.PersistentId, record.VolatileId)] = record;
            HighestPersistentId = Math.Max(HighestPersistentId, record.PersistentId);
        }
    }

    private void WriteRecord(PersistentHandleRecord record)
    {
        string path = RecordPath(record.PersistentId, record.VolatileId);
        string tmp = path + ".tmp";
        File.WriteAllBytes(tmp, JsonSerializer.SerializeToUtf8Bytes(record));
        File.Move(tmp, path, overwrite: true); // atomic replace so a reader never sees a half-written file
        // Note: _cold is populated only by LoadCold at startup — an active handle's reconnect goes through the
        // warm table, so a runtime cold entry would risk a spurious second rehydration of a still-active open.
    }

    private string RecordPath(ulong persistentId, ulong volatileId)
        => System.IO.Path.Combine(_directory, $"{persistentId:x16}_{volatileId:x16}.json");
}
