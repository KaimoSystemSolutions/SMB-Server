using Smb.Server.State;

namespace Smb.Server.Locking;

/// <summary>
/// Process-local default <see cref="ILockManager"/>: holds byte-range locks in memory, grouped
/// per file (key = actual backend path of the open). Conflicts are only checked between
/// <i>different</i> opens; an open never conflicts with itself. Blocking
/// locks (without <c>FAIL_IMMEDIATELY</c>) wait asynchronously via a
/// <see cref="TaskCompletionSource{TResult}"/> that is re-evaluated on unlock/close.
/// </summary>
public sealed class InMemoryLockManager : ILockManager
{
    private readonly object _gate = new();
    private readonly Dictionary<string, FileLockState> _files = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// owner → the file key its locks live under. Captured when the owner first takes a lock and used at
    /// release — <b>never recomputed</b>. <see cref="FileKey"/> reads the backend physical path, which a
    /// rename relocates in place; recomputing at release would look under the new name and strand the
    /// owner's locks under the old one. A stranded exclusive lock then blocks a later blocking lock on the
    /// reused name forever (no holder ever unlocks it). Same defect and fix as
    /// <c>InMemoryOplockManager</c>.
    /// </summary>
    private readonly Dictionary<SmbOpen, string> _ownerKeys = new();

    public Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> elements, bool failImmediately, CancellationToken ct)
    {
        if (elements.Count == 0) return Task.FromResult(LockOutcome.Granted);

        lock (_gate)
        {
            // Stay on the key this owner already locked under, if any, so a rename between two lock calls
            // cannot split one owner's locks across two states.
            string key = _ownerKeys.TryGetValue(owner, out string? existing) ? existing : FileKey(owner);
            FileLockState state = GetOrAdd(key);

            if (elements[0].Unlock)
                return Task.FromResult(ApplyUnlocks(state, owner, elements));

            // Lock path: atomically check all elements for conflicts.
            bool conflict = false;
            foreach (LockElement e in elements)
                if (Conflicts(state, owner, e.Offset, e.Length, e.Exclusive)) { conflict = true; break; }

            if (!conflict)
            {
                foreach (LockElement e in elements)
                    state.Active.Add(new ActiveLock(owner, e.Offset, e.Length, e.Exclusive));
                _ownerKeys[owner] = key;
                return Task.FromResult(LockOutcome.Granted);
            }

            // Conflict: fail immediately without waiting (or for multi-element locks).
            if (failImmediately || elements.Count != 1)
                return Task.FromResult(LockOutcome.Conflict);

            // Exactly one blocking lock → wait asynchronously until the range becomes free.
            LockElement single = elements[0];
            var tcs = new TaskCompletionSource<LockOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
            var waiter = new Waiter(owner, single.Offset, single.Length, single.Exclusive, tcs);
            state.Waiters.Add(waiter);
            _ownerKeys[owner] = key;
            // CANCEL/Close triggers ct → remove waiter and cancel.
            waiter.Registration = ct.Register(() =>
            {
                lock (_gate) { if (!state.Waiters.Remove(waiter)) return; }
                tcs.TrySetResult(LockOutcome.Cancelled);
            });
            return tcs.Task;
        }
    }

    public bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool forWrite)
    {
        if (length == 0) return true;
        string key = FileKey(owner);
        lock (_gate)
        {
            if (!_files.TryGetValue(key, out FileLockState? state)) return true;
            foreach (ActiveLock a in state.Active)
            {
                if (ReferenceEquals(a.Owner, owner)) continue;       // own locks never block
                if (!Overlaps(offset, length, a.Offset, a.Length)) continue;
                if (forWrite || a.Exclusive) return false;           // read conflicts only with exclusive
            }
            return true;
        }
    }

    public void ReleaseOwner(SmbOpen owner)
    {
        lock (_gate)
        {
            // Release under the key the owner locked with (see _ownerKeys), not the possibly-renamed
            // current path. No entry → this owner never took a lock, nothing to release.
            if (!_ownerKeys.Remove(owner, out string? key) || !_files.TryGetValue(key, out FileLockState? state)) return;

            state.Active.RemoveAll(a => ReferenceEquals(a.Owner, owner));
            for (int i = state.Waiters.Count - 1; i >= 0; i--)
            {
                if (!ReferenceEquals(state.Waiters[i].Owner, owner)) continue;
                Waiter w = state.Waiters[i];
                state.Waiters.RemoveAt(i);
                w.Registration.Dispose();
                w.Tcs.TrySetResult(LockOutcome.Cancelled);
            }

            WakeWaiters(state);
            if (state.Active.Count == 0 && state.Waiters.Count == 0)
                _files.Remove(key);
        }
    }

    // --- intern ---

    private LockOutcome ApplyUnlocks(FileLockState state, SmbOpen owner, IReadOnlyList<LockElement> elements)
    {
        // Each unlock must match exactly one lock from the same open (offset+length). Find all first
        // (atomicity), then remove — if any is missing return STATUS_RANGE_NOT_LOCKED without change.
        var indices = new List<int>(elements.Count);
        foreach (LockElement e in elements)
        {
            int found = -1;
            for (int i = 0; i < state.Active.Count; i++)
            {
                ActiveLock a = state.Active[i];
                if (ReferenceEquals(a.Owner, owner) && a.Offset == e.Offset && a.Length == e.Length && !indices.Contains(i))
                { found = i; break; }
            }
            if (found < 0) return LockOutcome.RangeNotLocked;
            indices.Add(found);
        }

        indices.Sort();
        for (int i = indices.Count - 1; i >= 0; i--)
            state.Active.RemoveAt(indices[i]);

        WakeWaiters(state);
        return LockOutcome.Granted;
    }

    /// <summary>Re-evaluates waiting locks and grants all that are now conflict-free.</summary>
    private static void WakeWaiters(FileLockState state)
    {
        for (int i = 0; i < state.Waiters.Count; )
        {
            Waiter w = state.Waiters[i];
            if (!Conflicts(state, w.Owner, w.Offset, w.Length, w.Exclusive))
            {
                state.Active.Add(new ActiveLock(w.Owner, w.Offset, w.Length, w.Exclusive));
                state.Waiters.RemoveAt(i);
                w.Registration.Dispose();
                w.Tcs.TrySetResult(LockOutcome.Granted);
            }
            else i++;
        }
    }

    private static bool Conflicts(FileLockState state, SmbOpen owner, ulong offset, ulong length, bool exclusive)
    {
        if (length == 0) return false;
        foreach (ActiveLock a in state.Active)
        {
            if (ReferenceEquals(a.Owner, owner)) continue;
            if (!Overlaps(offset, length, a.Offset, a.Length)) continue;
            if (exclusive || a.Exclusive) return true;   // conflict as soon as one side is exclusive
        }
        return false;
    }

    /// <summary>Overlap of two byte ranges, overflow-safe via 128-bit end calculation.</summary>
    private static bool Overlaps(ulong aOff, ulong aLen, ulong bOff, ulong bLen)
    {
        if (aLen == 0 || bLen == 0) return false;
        UInt128 aEnd = (UInt128)aOff + aLen;
        UInt128 bEnd = (UInt128)bOff + bLen;
        return (UInt128)aOff < bEnd && (UInt128)bOff < aEnd;
    }

    private FileLockState GetOrAdd(string key)
    {
        if (!_files.TryGetValue(key, out FileLockState? state))
            _files[key] = state = new FileLockState();
        return state;
    }

    private static string FileKey(SmbOpen owner) => owner.LocalOpen?.PhysicalPath ?? owner.PathName;

    private readonly record struct ActiveLock(SmbOpen Owner, ulong Offset, ulong Length, bool Exclusive);

    private sealed class FileLockState
    {
        public List<ActiveLock> Active { get; } = new();
        public List<Waiter> Waiters { get; } = new();
    }

    private sealed class Waiter(SmbOpen owner, ulong offset, ulong length, bool exclusive, TaskCompletionSource<LockOutcome> tcs)
    {
        public SmbOpen Owner { get; } = owner;
        public ulong Offset { get; } = offset;
        public ulong Length { get; } = length;
        public bool Exclusive { get; } = exclusive;
        public TaskCompletionSource<LockOutcome> Tcs { get; } = tcs;
        public CancellationTokenRegistration Registration { get; set; }
    }
}
