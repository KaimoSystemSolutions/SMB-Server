namespace Smb.Server.Concurrency;

/// <summary>
/// An async, per-key mutual-exclusion lock (docs/ENTERPRISE_HARDENING_ROADMAP.md, A1). Operations that
/// address the same <typeparamref name="TKey"/> are serialized; operations on different keys run fully
/// in parallel. This is the primitive that lets Phase A replace the per-connection dispatch barrier with
/// fine-grained per-Open / per-Path serialization while keeping SMB2 state coherent.
/// <para>
/// The lock is <b>not</b> reentrant: acquiring the same key twice on the same logical flow without
/// releasing in between deadlocks — mirror the non-reentrant contract of <see cref="SemaphoreSlim"/>.
/// Idle keys are reference-counted and evicted the moment their last holder releases, so a server that
/// touches millions of distinct paths over its lifetime does not accumulate lock state.
/// </para>
/// <example>
/// <code>
/// using (await _pathLocks.AcquireAsync(key, ct))
/// {
///     // ... critical section for `key` ...
/// } // released here
/// </code>
/// </example>
/// </summary>
/// <typeparam name="TKey">Lock key. Value semantics recommended (a record struct / value tuple); a custom
/// <see cref="IEqualityComparer{T}"/> may be supplied for reference keys.</typeparam>
public sealed class KeyedAsyncLock<TKey> where TKey : notnull
{
    internal sealed class Entry
    {
        public readonly SemaphoreSlim Semaphore = new(1, 1);

        /// <summary>Number of holders + waiters currently referencing this entry (guarded by <c>_gate</c>).</summary>
        public int RefCount;
    }

    private readonly Dictionary<TKey, Entry> _entries;
    private readonly object _gate = new();

    public KeyedAsyncLock(IEqualityComparer<TKey>? comparer = null)
        => _entries = new Dictionary<TKey, Entry>(comparer);

    /// <summary>Number of keys with at least one holder or waiter — for tests/diagnostics only.</summary>
    public int TrackedKeyCount
    {
        get { lock (_gate) return _entries.Count; }
    }

    /// <summary>
    /// Waits until <paramref name="key"/> is free, then takes it. Dispose the returned
    /// <see cref="Releaser"/> exactly once to release — a <c>using</c> statement is the intended pattern.
    /// If the wait is cancelled, the key is not taken and its reference is dropped again.
    /// </summary>
    public async ValueTask<Releaser> AcquireAsync(TKey key, CancellationToken cancellationToken = default)
    {
        Entry entry;
        lock (_gate)
        {
            if (!_entries.TryGetValue(key, out entry!))
            {
                entry = new Entry();
                _entries[key] = entry;
            }
            entry.RefCount++;
        }

        try
        {
            await entry.Semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Cancelled/faulted before acquiring — drop the reference we added above (never touch
            // the semaphore's count: WaitAsync did not take it).
            Release(key, entry, semaphoreWasTaken: false);
            throw;
        }

        return new Releaser(this, key, entry);
    }

    private void Release(TKey key, Entry entry, bool semaphoreWasTaken)
    {
        // Release the count first: at this point RefCount still includes this holder, so the entry
        // (and its SemaphoreSlim) cannot have been evicted/disposed underneath us.
        if (semaphoreWasTaken)
            entry.Semaphore.Release();

        lock (_gate)
        {
            if (--entry.RefCount == 0)
            {
                _entries.Remove(key);
                entry.Semaphore.Dispose();
            }
        }
    }

    /// <summary>Releases the held key on <see cref="Dispose"/>. Dispose exactly once.</summary>
    public readonly struct Releaser : IDisposable
    {
        private readonly KeyedAsyncLock<TKey>? _owner;
        private readonly TKey _key;
        private readonly Entry _entry;

        internal Releaser(KeyedAsyncLock<TKey> owner, TKey key, Entry entry)
        {
            _owner = owner;
            _key = key;
            _entry = entry;
        }

        public void Dispose() => _owner?.Release(_key, _entry, semaphoreWasTaken: true);
    }
}
