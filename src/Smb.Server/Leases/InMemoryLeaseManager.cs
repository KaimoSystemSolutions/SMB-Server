using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.State;

namespace Smb.Server.Leases;

/// <summary>
/// Process-local default <see cref="ILeaseManager"/>: manages granted leases in memory, grouped per
/// file (key = actual backend path of the open, identical to <see cref="Locking.InMemoryLockManager"/>
/// and <see cref="Oplocks.InMemoryOplockManager"/>). Opens sharing one <see cref="LeaseKey"/> share a
/// single lease. The granting policy is intentionally conservative and mirrors the oplock manager:
/// <list type="bullet">
/// <item>While only <b>one</b> lease key is present on a file, that lease receives the fully
/// requested state — including Read+Write+Handle.</item>
/// <item>Once a <b>second, distinct</b> lease key accesses the same file, all write/handle caching
/// breaks down to Read (shared read caching is preserved); the new lease also receives at most Read.</item>
/// </list>
/// The <c>Epoch</c> (lease V2) is incremented on every server-initiated state change.
/// <para>
/// <b>Directory leases (M1.3):</b> a lease whose open is a directory is tracked as a directory lease.
/// <see cref="BreakDirectoryLease"/> downgrades such a lease (dropping Handle caching, keeping at most
/// shared Read) when a child is added/removed/renamed inside the directory, so the client re-reads its
/// cached enumeration.
/// </para>
/// <para>
/// <b>Waiting for the acknowledgment is the dispatcher's job</b> and, since W1, happens: a CREATE that
/// forces one of the breaks reported by <see cref="RequestLease"/> is parked until the holder acknowledges
/// or the break times out (§3.3.5.9.8). The state here is downgraded eagerly when the break is decided —
/// the wait is about the holder's client-side dirty data, not about this dictionary. Breaks from
/// <see cref="BreakDirectoryLease"/> are the exception and are never waited on: they invalidate a cached
/// listing of a different file than the one being created (§3.3.4.18).
/// </para>
/// </summary>
public sealed class InMemoryLeaseManager : ILeaseManager
{
    private readonly object _gate = new();

    /// <summary>fileKey → lease keys currently held on that file.</summary>
    private readonly Dictionary<string, HashSet<LeaseKey>> _fileKeys = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>leaseKey → holder (global; lease keys are effectively unique per client+file).</summary>
    private readonly Dictionary<LeaseKey, LeaseHolder> _byKey = new();

    /// <summary>open → lease key it is attached to (for release without touching backend state).</summary>
    private readonly Dictionary<SmbOpen, LeaseKey> _openIndex = new();

    public LeaseGrant RequestLease(SmbOpen open, LeaseRequest request)
    {
        LeaseState requested = request.RequestedState & LeaseState.ReadWriteHandle;
        LeaseKey key = request.Key;
        if (key.IsZero) return LeaseGrant.None;   // no lease key → no lease

        string fileKey = FileKey(open);
        lock (_gate)
        {
            HashSet<LeaseKey> keysOnFile = GetOrAddFile(fileKey);
            bool hasOtherKey = HasOtherKey(keysOnFile, key);

            // A distinct second key joining the file forces write/handle caching of the other
            // leases down to shared Read caching (§3.3.5.9.8, conservative). The dispatcher parks the
            // triggering CREATE behind these breaks — losing Write/Handle means the holder must flush first.
            var breaks = new List<LeaseBreak>();
            if (hasOtherKey)
            {
                foreach (LeaseKey other in keysOnFile)
                {
                    if (other == key) continue;
                    LeaseHolder h = _byKey[other];
                    LeaseState shareable = h.State & LeaseState.Read;
                    if (shareable != h.State)
                    {
                        LeaseState from = h.State;
                        h.State = shareable;
                        h.Epoch++;
                        breaks.Add(new LeaseBreak(h.Key, from, shareable, h.Epoch, First(h.Opens)));
                    }
                }
            }

            // Grant for this key: shared file → read caching only; solo → the full request.
            LeaseState granted = hasOtherKey ? (requested & LeaseState.Read) : requested;

            if (_byKey.TryGetValue(key, out LeaseHolder? holder))
            {
                holder.Opens.Add(open);
                if (granted != holder.State) holder.Epoch++;
                holder.State = granted;
            }
            else
            {
                holder = new LeaseHolder(key, fileKey)
                {
                    State = granted,
                    Epoch = request.IsV2 ? request.Epoch : (ushort)0,
                    IsDirectory = open.LocalOpen?.IsDirectory ?? false,
                };
                holder.Opens.Add(open);
                _byKey[key] = holder;
                keysOnFile.Add(key);
            }
            _openIndex[open] = key;

            return new LeaseGrant(holder.State, holder.Epoch, breaks);
        }
    }

    public LeaseState Acknowledge(LeaseKey key, LeaseState newState)
    {
        lock (_gate)
        {
            if (!_byKey.TryGetValue(key, out LeaseHolder? holder))
                return LeaseState.None;

            // An acknowledgment only confirms a downgrade; the epoch was already bumped when the
            // break was decided, so it is not incremented again here.
            holder.State = newState & LeaseState.ReadWriteHandle;
            return holder.State;
        }
    }

    public bool ReleaseOwner(SmbOpen open)
    {
        lock (_gate)
        {
            if (!_openIndex.Remove(open, out LeaseKey key)) return false;
            if (!_byKey.TryGetValue(key, out LeaseHolder? holder)) return false;

            holder.Opens.Remove(open);
            if (holder.Opens.Count != 0) return false;  // other opens keep the lease alive

            _byKey.Remove(key);
            if (_fileKeys.TryGetValue(holder.FileKey, out HashSet<LeaseKey>? keys))
            {
                keys.Remove(key);
                if (keys.Count == 0) _fileKeys.Remove(holder.FileKey);
            }
            // Decided under _gate, atomically with the removal: of two concurrent closers exactly one
            // sees the count reach zero and reports "lease fully released" (the interface contract).
            return true;
        }
    }

    public IReadOnlyList<LeaseBreak> BreakDirectoryLease(string directoryFileKey)
    {
        lock (_gate)
        {
            if (!_fileKeys.TryGetValue(directoryFileKey, out HashSet<LeaseKey>? keys) || keys.Count == 0)
                return Array.Empty<LeaseBreak>();

            List<LeaseBreak>? breaks = null;
            foreach (LeaseKey key in keys)
            {
                LeaseHolder h = _byKey[key];
                if (!h.IsDirectory) continue;   // only directory leases care about child changes

                // A change inside the directory invalidates the client's cached handle/enumeration:
                // drop Handle caching (a directory lease never holds Write), keeping at most shared Read.
                LeaseState reduced = h.State & LeaseState.Read;
                if (reduced == h.State) continue;   // already ≤ Read → nothing to break

                LeaseState from = h.State;
                h.State = reduced;
                h.Epoch++;
                (breaks ??= new List<LeaseBreak>()).Add(new LeaseBreak(h.Key, from, reduced, h.Epoch, First(h.Opens)));
            }
            return breaks ?? (IReadOnlyList<LeaseBreak>)Array.Empty<LeaseBreak>();
        }
    }

    // --- internal ---

    private HashSet<LeaseKey> GetOrAddFile(string fileKey)
    {
        if (!_fileKeys.TryGetValue(fileKey, out HashSet<LeaseKey>? keys))
            _fileKeys[fileKey] = keys = new HashSet<LeaseKey>();
        return keys;
    }

    private static bool HasOtherKey(HashSet<LeaseKey> keys, LeaseKey self)
    {
        foreach (LeaseKey k in keys)
            if (k != self) return true;
        return false;
    }

    private static SmbOpen First(HashSet<SmbOpen> opens)
    {
        foreach (SmbOpen o in opens) return o;
        throw new InvalidOperationException("Lease holder has no opens.");
    }

    private static string FileKey(SmbOpen open) => open.LocalOpen?.PhysicalPath ?? open.PathName;

    private sealed class LeaseHolder(LeaseKey key, string fileKey)
    {
        public LeaseKey Key { get; } = key;
        public string FileKey { get; } = fileKey;
        public LeaseState State { get; set; }
        public ushort Epoch { get; set; }
        public bool IsDirectory { get; init; }
        public HashSet<SmbOpen> Opens { get; } = new();
    }
}
