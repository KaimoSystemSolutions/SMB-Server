using Smb.Server.State;

namespace Smb.Server.Locking;

/// <summary>
/// Prozesslokaler Default-<see cref="ILockManager"/>: hält Byte-Range-Locks in-memory, gruppiert
/// pro Datei (Schlüssel = realer Backend-Pfad des Open). Konflikte werden nur zwischen
/// <i>verschiedenen</i> Opens geprüft; ein Open kollidiert nie mit sich selbst. Blockierende
/// Locks (ohne <c>FAIL_IMMEDIATELY</c>) warten asynchron über einen
/// <see cref="TaskCompletionSource{TResult}"/>, der bei Unlock/Close erneut ausgewertet wird.
/// </summary>
public sealed class InMemoryLockManager : ILockManager
{
    private readonly object _gate = new();
    private readonly Dictionary<string, FileLockState> _files = new(StringComparer.OrdinalIgnoreCase);

    public Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> elements, bool failImmediately, CancellationToken ct)
    {
        if (elements.Count == 0) return Task.FromResult(LockOutcome.Granted);
        string key = FileKey(owner);

        lock (_gate)
        {
            FileLockState state = GetOrAdd(key);

            if (elements[0].Unlock)
                return Task.FromResult(ApplyUnlocks(state, owner, elements));

            // Lock-Pfad: alle Elemente atomar auf Konflikt prüfen.
            bool conflict = false;
            foreach (LockElement e in elements)
                if (Conflicts(state, owner, e.Offset, e.Length, e.Exclusive)) { conflict = true; break; }

            if (!conflict)
            {
                foreach (LockElement e in elements)
                    state.Active.Add(new ActiveLock(owner, e.Offset, e.Length, e.Exclusive));
                return Task.FromResult(LockOutcome.Granted);
            }

            // Konflikt: ohne Warten (oder bei Mehrfach-Locks) sofort scheitern.
            if (failImmediately || elements.Count != 1)
                return Task.FromResult(LockOutcome.Conflict);

            // Genau ein blockierendes Lock → asynchron warten, bis der Bereich frei wird.
            LockElement single = elements[0];
            var tcs = new TaskCompletionSource<LockOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
            var waiter = new Waiter(owner, single.Offset, single.Length, single.Exclusive, tcs);
            state.Waiters.Add(waiter);
            // CANCEL/Close lösen ct aus → Waiter entfernen und abbrechen.
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
                if (ReferenceEquals(a.Owner, owner)) continue;       // eigene Locks blockieren nie
                if (!Overlaps(offset, length, a.Offset, a.Length)) continue;
                if (forWrite || a.Exclusive) return false;           // Read kollidiert nur mit exklusiven
            }
            return true;
        }
    }

    public void ReleaseOwner(SmbOpen owner)
    {
        string key = FileKey(owner);
        lock (_gate)
        {
            if (!_files.TryGetValue(key, out FileLockState? state)) return;

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
        // Jeder Unlock muss exakt ein Lock desselben Open treffen (Offset+Length). Erst alle finden
        // (Atomarität), dann entfernen — bei Fehlen STATUS_RANGE_NOT_LOCKED ohne Änderung.
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

    /// <summary>Prüft wartende Locks erneut und gewährt alle, die jetzt konfliktfrei sind.</summary>
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
            if (exclusive || a.Exclusive) return true;   // Konflikt, sobald eine Seite exklusiv ist
        }
        return false;
    }

    /// <summary>Überlappung zweier Byte-Bereiche, überlaufsicher via 128-Bit-Endberechnung.</summary>
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
