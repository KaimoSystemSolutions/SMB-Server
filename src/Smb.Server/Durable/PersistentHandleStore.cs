namespace Smb.Server.Durable;

/// <summary>
/// Restart-surviving metadata for one persistent (continuously-available) handle (C2). This is exactly the
/// state needed to rehydrate a live <c>SmbOpen</c> after a server restart: the FileId, the owning principal
/// and create GUID (validated on reconnect), and the share/path/access needed to re-open the backend and
/// re-establish the share-mode reservation. Locks/oplock/lease are <b>not</b> persisted (see
/// <see cref="IPersistentHandleStore"/> remarks).
/// </summary>
public sealed record PersistentHandleRecord(
    ulong PersistentId,
    ulong VolatileId,
    string OwnerKey,
    Guid CreateGuid,
    string ShareName,
    string Path,
    uint GrantedAccess,
    uint ShareAccess);

/// <summary>
/// Optional capability of an <see cref="IDurableHandleStore"/> that persists <c>IsPersistent</c> handle
/// <i>metadata</i> across a full server restart (C2). A store implementing this keeps the usual warm
/// (in-process) durable table via <see cref="IDurableHandleStore"/> and, in addition, writes a
/// <see cref="PersistentHandleRecord"/> for each persistent handle to durable storage. After a restart the
/// warm table is empty but the records survive: the dispatcher claims a cold record and rehydrates a live
/// open from it (re-opens the backend, re-reserves the share mode).
/// <para>
/// <b>Scope (v1):</b> only the reconnectable metadata is persisted. Byte-range locks, oplocks and leases are
/// <b>not</b> reconstructed — after a restart a rehydrated handle resumes READ/WRITE but holds no lock/lease
/// until re-acquired. This matches the value proposition of persistent handles (survive a node/server restart
/// and keep operating on the file) while keeping the restart path bounded.
/// </para>
/// </summary>
public interface IPersistentHandleStore
{
    /// <summary>Writes (or refreshes) the restart-surviving record for a persistent handle (called when it is granted).</summary>
    void Persist(PersistentHandleRecord record);

    /// <summary>Removes the record when the persistent handle is permanently closed/invalidated.</summary>
    void RemovePersisted(ulong persistentId, ulong volatileId);

    /// <summary>
    /// Atomically claims a cold (loaded-from-storage, not yet reclaimed since startup) record for a reconnect,
    /// or returns false if none is registered. The on-storage copy is retained so the handle can survive a
    /// <i>subsequent</i> restart; it is removed only by <see cref="RemovePersisted"/> (close).
    /// </summary>
    bool TryClaimColdRecord(ulong persistentId, ulong volatileId, out PersistentHandleRecord record);

    /// <summary>Re-registers a cold record after a failed reconnect validation (wrong principal / create GUID).</summary>
    void ReturnColdRecord(PersistentHandleRecord record);

    /// <summary>Highest persistent FileId among records loaded at startup (0 if none) — used to seed the id counter so a fresh allocation cannot collide with a rehydrated handle.</summary>
    ulong HighestPersistentId { get; }
}
