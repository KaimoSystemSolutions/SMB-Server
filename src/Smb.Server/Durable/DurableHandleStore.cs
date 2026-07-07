using System.Collections.Concurrent;
using Smb.Server.State;

namespace Smb.Server.Durable;

/// <summary>
/// A disconnected durable/persistent open, kept alive across a transport drop until it is reconnected
/// or scavenged (MS-SMB2 §3.3.1.10, GlobalOpenTable durable entries). The backend handle, byte-range
/// locks, oplock/lease and share-mode reservation of <see cref="Open"/> stay intact while it waits here.
/// </summary>
public sealed class DurableHandle
{
    public required ulong PersistentId { get; init; }
    public required ulong VolatileId { get; init; }
    public required SmbOpen Open { get; init; }

    /// <summary>When the handle is scavenged if not reconnected (UTC). Ignored for <see cref="IsPersistent"/>.</summary>
    public required DateTimeOffset Deadline { get; init; }

    /// <summary>Identity key of the owner — a reconnect must present the same principal (§3.3.5.9.7).</summary>
    public required string OwnerKey { get; init; }

    /// <summary>Durable-v2 create GUID (<see cref="Guid.Empty"/> for v1). A v2 reconnect must match it.</summary>
    public Guid CreateGuid { get; init; }

    /// <summary>Persistent handle (v2 CA share): survives even a full server restart and never times out.</summary>
    public bool IsPersistent { get; init; }

    public (ulong Persistent, ulong Volatile) Key => (PersistentId, VolatileId);
}

/// <summary>
/// Holds durable/persistent opens between a transport drop and the client's reconnect (Phase 4). The
/// default <see cref="InMemoryDurableHandleStore"/> keeps live <see cref="DurableHandle"/>s in process
/// memory — it survives TCP drops but not a process restart.
/// <para>
/// <b>Implementing an out-of-process store (M4.3)</b> — e.g. SQLite/Redis for restart-surviving
/// persistent (CA) handles: persist the reconnectable <i>metadata</i> of each entry — the FileId
/// (<see cref="DurableHandle.PersistentId"/>/<see cref="DurableHandle.VolatileId"/>),
/// <see cref="DurableHandle.OwnerKey"/>, <see cref="DurableHandle.CreateGuid"/>,
/// <see cref="DurableHandle.IsPersistent"/>, <see cref="DurableHandle.Deadline"/>, plus the open's path,
/// granted access and share mode (from <see cref="DurableHandle.Open"/>). On <see cref="TryClaim"/>
/// after a restart the implementation must <b>rehydrate a live <see cref="SmbOpen"/></b> (re-open the
/// backend handle, restore locks/oplock/lease/share-mode reservation) before returning it, since the
/// dispatcher resumes I/O directly on <see cref="DurableHandle.Open"/>. Non-persistent entries may be
/// dropped on restart; only <see cref="DurableHandle.IsPersistent"/> entries must be recoverable.
/// </para>
/// <para>All members must be thread-safe: connection loops add/claim entries concurrently.</para>
/// </summary>
public interface IDurableHandleStore
{
    /// <summary>Registers a disconnected durable open.</summary>
    void Add(DurableHandle handle);

    /// <summary>
    /// Atomically removes and returns the durable open with the given FileId (a reconnect claims it), or
    /// returns <c>false</c> if none is registered.
    /// </summary>
    bool TryClaim(ulong persistentId, ulong volatileId, out DurableHandle handle);

    /// <summary>
    /// Removes and returns every non-persistent handle whose <see cref="DurableHandle.Deadline"/> is at or
    /// before <paramref name="now"/> (the scavenger). Persistent handles never expire.
    /// </summary>
    IReadOnlyList<DurableHandle> TakeExpired(DateTimeOffset now);

    /// <summary>Removes and returns all handles (server shutdown / draining).</summary>
    IReadOnlyList<DurableHandle> TakeAll();
}

/// <summary>Default process-local <see cref="IDurableHandleStore"/> (survives TCP drops, not restarts).</summary>
public sealed class InMemoryDurableHandleStore : IDurableHandleStore
{
    private readonly ConcurrentDictionary<(ulong, ulong), DurableHandle> _handles = new();

    public void Add(DurableHandle handle) => _handles[handle.Key] = handle;

    public bool TryClaim(ulong persistentId, ulong volatileId, out DurableHandle handle)
        => _handles.TryRemove((persistentId, volatileId), out handle!);

    public IReadOnlyList<DurableHandle> TakeExpired(DateTimeOffset now)
    {
        var expired = new List<DurableHandle>();
        foreach (DurableHandle h in _handles.Values)
        {
            if (h.IsPersistent || h.Deadline > now)
                continue;
            if (_handles.TryRemove(h.Key, out DurableHandle? removed))
                expired.Add(removed);
        }
        return expired;
    }

    public IReadOnlyList<DurableHandle> TakeAll()
    {
        var all = new List<DurableHandle>(_handles.Values);
        _handles.Clear();
        return all;
    }
}
