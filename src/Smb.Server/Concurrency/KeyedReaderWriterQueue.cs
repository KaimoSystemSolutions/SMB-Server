namespace Smb.Server.Concurrency;

/// <summary>Shared (reader) or exclusive (writer) acquisition mode for <see cref="KeyedReaderWriterQueue{TKey}"/>.</summary>
public enum LockMode
{
    /// <summary>Compatible with other <see cref="Shared"/> holders of the same key — they run in parallel.</summary>
    Shared = 0,

    /// <summary>Runs alone: excludes every other holder (shared or exclusive) of the same key.</summary>
    Exclusive = 1,
}

/// <summary>
/// An async, per-key reader/writer queue with FIFO fairness (docs/ENTERPRISE_HARDENING_ROADMAP.md, A2a).
/// It is the dispatch-ordering primitive for Phase A: it lets metadata ops leave the per-connection
/// barrier while keeping SMB2 state coherent.
/// <para>
/// It is deliberately <b>two-phase</b>:
/// </para>
/// <list type="number">
/// <item><see cref="Reserve"/> is called <b>synchronously on the connection read loop</b>, in frame
/// arrival order. It fixes this frame's position in the key's FIFO queue — this is what makes ordering
/// deterministic even though the actual work runs later on pool threads.</item>
/// <item><see cref="Reservation.AcquireAsync"/> is called <b>off the read loop</b> by the executing
/// task and completes once the reservation is granted per FIFO + reader/writer rules.</item>
/// </list>
/// <para>
/// Grant rules: a run of leading <see cref="LockMode.Shared"/> reservations is granted together (they
/// run in parallel); an <see cref="LockMode.Exclusive"/> reservation is granted alone once it reaches
/// the head. Fairness is strict FIFO, so a stream of shared reservations cannot starve a queued
/// exclusive one (readers arriving <i>behind</i> a queued writer wait for it). Idle keys are
/// reference-counted and evicted when their queue fully drains.
/// </para>
/// </summary>
/// <typeparam name="TKey">Queue key; value semantics recommended (a record struct / value tuple).</typeparam>
public sealed class KeyedReaderWriterQueue<TKey> where TKey : notnull
{
    internal sealed class Node
    {
        public required LockMode Mode { get; init; }
        // Continuations MUST run asynchronously: the granting Tcs.SetResult happens while holding _gate.
        public readonly TaskCompletionSource Tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public LinkedListNode<Node>? Link;   // position while queued; null once granted or removed
        public bool Granted;
    }

    internal sealed class KeyState
    {
        public readonly LinkedList<Node> Waiters = new();
        public int ActiveCount;
        public LockMode ActiveMode;
        public int RefCount;                 // queued + active nodes referencing this state (for eviction)
    }

    private readonly Dictionary<TKey, KeyState> _keys;
    private readonly object _gate = new();

    public KeyedReaderWriterQueue(IEqualityComparer<TKey>? comparer = null)
        => _keys = new Dictionary<TKey, KeyState>(comparer);

    /// <summary>Number of keys with at least one queued or active node — for tests/diagnostics only.</summary>
    public int TrackedKeyCount
    {
        get { lock (_gate) return _keys.Count; }
    }

    /// <summary>
    /// Reserves a FIFO slot for <paramref name="key"/> in the given <paramref name="mode"/>. Call this
    /// synchronously and in arrival order (on the read loop). Then <see cref="Reservation.AcquireAsync"/>
    /// the returned reservation on the executing task, and dispose the resulting <see cref="Releaser"/>
    /// exactly once.
    /// </summary>
    public Reservation Reserve(TKey key, LockMode mode)
    {
        lock (_gate)
        {
            if (!_keys.TryGetValue(key, out KeyState? ks))
            {
                ks = new KeyState();
                _keys[key] = ks;
            }
            ks.RefCount++;
            var node = new Node { Mode = mode };
            node.Link = ks.Waiters.AddLast(node);
            Pump(ks);
            return new Reservation(this, key, ks, node);
        }
    }

    /// <summary>Grants as many nodes from the head of the queue as the reader/writer rules allow.</summary>
    private static void Pump(KeyState ks)
    {
        while (ks.Waiters.First is { } headLink)
        {
            Node head = headLink.Value;

            if (ks.ActiveCount == 0)
            {
                Grant(ks, headLink);
                ks.ActiveMode = head.Mode;
                if (head.Mode == LockMode.Exclusive)
                    break;                       // exclusive runs alone
                continue;                        // leading shared: keep granting shared behind it
            }

            if (ks.ActiveMode == LockMode.Shared && head.Mode == LockMode.Shared)
            {
                Grant(ks, headLink);             // join the active shared batch
                continue;
            }

            break; // active exclusive, or shared active with an exclusive at the head → must wait
        }
    }

    private static void Grant(KeyState ks, LinkedListNode<Node> link)
    {
        Node node = link.Value;
        ks.Waiters.Remove(link);
        node.Link = null;
        node.Granted = true;
        ks.ActiveCount++;
        node.Tcs.SetResult();                    // async continuation (RunContinuationsAsynchronously)
    }

    private async ValueTask<Releaser> AcquireAsync(TKey key, KeyState ks, Node node, CancellationToken ct)
    {
        if (!ct.CanBeCanceled)
        {
            await node.Tcs.Task.ConfigureAwait(false);
            return new Releaser(this, key, ks, node);
        }

        await using CancellationTokenRegistration reg =
            ct.Register(static state =>
            {
                var (self, k, s, n, token) = ((KeyedReaderWriterQueue<TKey>, TKey, KeyState, Node, CancellationToken))state!;
                self.CancelWaiter(k, s, n, token);
            }, (this, key, ks, node, ct));

        await node.Tcs.Task.ConfigureAwait(false);
        return new Releaser(this, key, ks, node);
    }

    private void CancelWaiter(TKey key, KeyState ks, Node node, CancellationToken ct)
    {
        lock (_gate)
        {
            if (node.Granted) return;            // already granted under the gate — release will handle it
            if (node.Link is not null)
            {
                ks.Waiters.Remove(node.Link);
                node.Link = null;
            }
            node.Tcs.TrySetCanceled(ct);
            Pump(ks);                            // a cancelled head may have been blocking others
            DropRef(key, ks);
        }
    }

    private void Release(TKey key, KeyState ks, Node node)
    {
        lock (_gate)
        {
            if (!node.Granted) return;           // defensive: only a granted node holds the lock
            node.Granted = false;
            ks.ActiveCount--;
            if (ks.ActiveCount == 0)
                ks.ActiveMode = LockMode.Shared; // irrelevant while idle; reset to the default
            Pump(ks);
            DropRef(key, ks);
        }
    }

    /// <summary>Drops one reference to the key state and evicts it once nothing references it. Caller holds <c>_gate</c>.</summary>
    private void DropRef(TKey key, KeyState ks)
    {
        if (--ks.RefCount == 0)
            _keys.Remove(key);
    }

    /// <summary>A fixed FIFO position for a key. Call <see cref="AcquireAsync"/> once, off the read loop.</summary>
    public readonly struct Reservation
    {
        private readonly KeyedReaderWriterQueue<TKey> _owner;
        private readonly TKey _key;
        private readonly KeyState _ks;
        private readonly Node _node;

        internal Reservation(KeyedReaderWriterQueue<TKey> owner, TKey key, KeyState ks, Node node)
        {
            _owner = owner;
            _key = key;
            _ks = ks;
            _node = node;
        }

        /// <summary>Completes when this reservation is granted per FIFO + reader/writer rules.</summary>
        public ValueTask<Releaser> AcquireAsync(CancellationToken cancellationToken = default)
            => _owner.AcquireAsync(_key, _ks, _node, cancellationToken);
    }

    /// <summary>Releases the held key on <see cref="Dispose"/>. Dispose exactly once.</summary>
    public readonly struct Releaser : IDisposable
    {
        private readonly KeyedReaderWriterQueue<TKey>? _owner;
        private readonly TKey _key;
        private readonly KeyState _ks;
        private readonly Node _node;

        internal Releaser(KeyedReaderWriterQueue<TKey> owner, TKey key, KeyState ks, Node node)
        {
            _owner = owner;
            _key = key;
            _ks = ks;
            _node = node;
        }

        public void Dispose() => _owner?.Release(_key, _ks, _node);
    }
}
