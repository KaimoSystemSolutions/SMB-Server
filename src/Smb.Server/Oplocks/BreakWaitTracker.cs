using Smb.Protocol.Messages;
using Smb.Server.Diagnostics;
using Smb.Server.State;

namespace Smb.Server.Oplocks;

/// <summary>
/// [W1] Tracks oplock/lease breaks that have been sent to a holder and are waiting for its
/// acknowledgment, so the conflicting access that triggered them can wait until the holder has
/// flushed its cached data (break-before-grant, MS-SMB2 §3.3.5.9.8). Without this the holder is
/// downgraded in state while its dirty pages are still client-side — the second opener reads stale
/// data (baseline finding #2), and a holder that never acknowledges is never cleaned up (#3).
/// <para>
/// <b>Two key spaces, because the two acknowledgments identify their break differently:</b> the
/// classic oplock acknowledgment (§2.2.24.1) carries a FileId ⇒ keyed by the holding
/// <see cref="SmbOpen"/>; the lease acknowledgment (§2.2.24.2) carries no FileId at all ⇒ keyed by
/// <see cref="LeaseKey"/>. <see cref="BreakKey"/> unifies both into one dictionary.
/// </para>
/// <para>
/// A wait ends one of three ways (§3.3.5.9.8): the holder <b>acknowledges</b>, the holder's open is
/// <b>closed</b> (<see cref="CompleteOplockBreakOnClose"/> / <see cref="CompleteLeaseBreakOnClose"/> —
/// the Windows redirector's standard reply to a batch break on a deferred-close handle is a CLOSE, not
/// an ack), or the <b>timeout</b> fires. Every registered break carries its own clock
/// (<see cref="TimeProvider"/>): if neither ack nor close arrives within the timeout, the wait completes
/// anyway (<see cref="BreakOutcome.TimedOut"/>) rather than hanging the triggering request forever — a
/// client that stops acknowledging must not be able to freeze another client's CREATE. An acknowledgment
/// arriving after that is a clean no-op (the entry is already gone), and one arriving for a break nobody
/// registered is a no-op too: the ack is still answered normally by the dispatcher, only the wait side
/// ignores it.
/// </para>
/// <para><b>Note on "force downgrade":</b> the default managers downgrade their state <i>eagerly</i>
/// when they decide the break (see <c>InMemoryOplockManager.RequestOplock</c>), so a timeout has no
/// state left to force — it only releases the waiter. There is deliberately no second downgrade here;
/// the manager stays the single authority over caching state.</para>
/// </summary>
internal sealed class BreakWaitTracker
{
    private readonly TimeProvider _time;
    private readonly TimeSpan _timeout;
    private readonly SmbServerMetrics _metrics;
    private readonly object _gate = new();
    private readonly Dictionary<BreakKey, Entry> _pending = [];

    public BreakWaitTracker(TimeProvider time, TimeSpan timeout, SmbServerMetrics metrics)
    {
        _time = time;
        _timeout = timeout;
        _metrics = metrics;
    }

    /// <summary>
    /// Registers a break that is about to be sent to <paramref name="holder"/> and returns the wait for
    /// its OPLOCK_BREAK acknowledgment (§2.2.24.1). The caller must send the notification <i>after</i>
    /// this call, so an immediate acknowledgment cannot race ahead of the registration. The clock starts
    /// here rather than at the send, so a notification the transport never delivers still times out.
    /// </summary>
    public Task<BreakOutcome> RegisterOplockBreak(SmbOpen holder) => Register(BreakKey.ForOplock(holder));

    /// <summary>
    /// Registers a break that is about to be sent for the lease <paramref name="key"/> and returns the
    /// wait for its LEASE_BREAK acknowledgment (§2.2.24.2).
    /// </summary>
    public Task<BreakOutcome> RegisterLeaseBreak(LeaseKey key) => Register(BreakKey.ForLease(key));

    /// <summary>Completes the wait for an oplock break whose holder just acknowledged. No-op if none is pending.</summary>
    public void CompleteOplockBreak(SmbOpen holder) => Complete(BreakKey.ForOplock(holder), BreakOutcome.Acknowledged);

    /// <summary>Completes the wait for a lease break that was just acknowledged. No-op if none is pending.</summary>
    public void CompleteLeaseBreak(LeaseKey key) => Complete(BreakKey.ForLease(key), BreakOutcome.Acknowledged);

    /// <summary>
    /// Completes the wait for an oplock break whose holder's open was <b>closed instead of
    /// acknowledged</b> (§3.3.5.9.8: the server waits for the acknowledgment OR the Open being closed).
    /// The Windows redirector answers a batch break on a deferred-close handle with exactly that CLOSE —
    /// it never sends an ack for a handle it only kept alive for the deferred close (the Explorer
    /// .lnk-creation freeze). No-op if none is pending.
    /// </summary>
    public void CompleteOplockBreakOnClose(SmbOpen holder) => Complete(BreakKey.ForOplock(holder), BreakOutcome.HolderClosed);

    /// <summary>
    /// Completes the wait for a lease break whose <b>last</b> holding open was closed (§3.3.5.9.8 — a
    /// lease survives until all opens sharing its key are gone; the caller asserts that just happened,
    /// see <c>ILeaseManager.ReleaseOwner</c>). No-op if none is pending.
    /// </summary>
    public void CompleteLeaseBreakOnClose(LeaseKey key) => Complete(BreakKey.ForLease(key), BreakOutcome.HolderClosed);

    private Task<BreakOutcome> Register(BreakKey key)
    {
        var entry = new Entry();
        lock (_gate)
        {
            // A break is already outstanding for this holder (the managers only re-break after an
            // acknowledgment, so this is rare): the new waiter joins the existing wait instead of
            // replacing it — replacing would leave the first waiter with a task nobody completes.
            if (_pending.TryGetValue(key, out Entry? existing))
                return existing.Completion.Task;

            _pending[key] = entry;
            _metrics.OnOplockBreakSent();

            // Publish the entry, count it, and arm its clock all under one lock. Complete() can then never
            // observe a half-built break: not one whose timer does not exist yet (it would leave the timer
            // running), and not one whose "sent" was not counted yet (the gauge would go negative). Both are
            // reachable — a client may send an unsolicited acknowledgment at any moment, and a test clock can
            // fire the timeout instantly. The timeout is positive by construction (the tracker is not created
            // otherwise), so no callback can fire *inside* this lock.
            entry.Timer = _time.CreateTimer(
                static state => { (BreakWaitTracker self, BreakKey k) = ((BreakWaitTracker, BreakKey))state!; self.Complete(k, BreakOutcome.TimedOut); },
                (this, key), _timeout, Timeout.InfiniteTimeSpan);
        }

        return entry.Completion.Task;
    }

    private void Complete(BreakKey key, BreakOutcome outcome)
    {
        Entry? entry;
        lock (_gate)
        {
            if (!_pending.Remove(key, out entry))
                return;     // already acknowledged, already timed out, or never registered → nothing to do
        }

        entry.Timer?.Dispose();
        _metrics.OnOplockBreakResolved(outcome == BreakOutcome.TimedOut);
        entry.Completion.TrySetResult(outcome);
    }

    /// <summary>
    /// Identifies an outstanding break. Exactly one of the two halves is meaningful:
    /// <paramref name="Open"/> for a classic oplock break (the acknowledgment names a FileId),
    /// <paramref name="Lease"/> for a lease break (the acknowledgment names a lease key).
    /// <see cref="SmbOpen"/> has reference identity, <see cref="LeaseKey"/> value equality — both are
    /// valid dictionary keys.
    /// </summary>
    private readonly record struct BreakKey(SmbOpen? Open, LeaseKey Lease)
    {
        public static BreakKey ForOplock(SmbOpen holder) => new(holder, default);
        public static BreakKey ForLease(LeaseKey key) => new(null, key);
    }

    private sealed class Entry
    {
        // RunContinuationsAsynchronously: the acknowledgment's dispatch must not end up running the
        // parked CREATE's continuation (backend I/O + response assembly) inline on its own frame.
        public readonly TaskCompletionSource<BreakOutcome> Completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ITimer? Timer;
    }
}

/// <summary>How an awaited oplock/lease break ended (W1).</summary>
internal enum BreakOutcome
{
    /// <summary>The holder acknowledged — its cached data is flushed and the waiter may proceed.</summary>
    Acknowledged,

    /// <summary>
    /// No acknowledgment within <c>SmbServerOptions.OplockBreakTimeout</c>. The waiter proceeds anyway
    /// (the holder's caching state was already downgraded when the break was decided); a client that
    /// stops acknowledging degrades coherency for itself, it does not stall anyone else indefinitely.
    /// </summary>
    TimedOut,

    /// <summary>
    /// The holder closed its open (leases: the last open of the key) instead of acknowledging —
    /// there is no cached state left to flush and the waiter may proceed (§3.3.5.9.8 counts the close
    /// as the end of the wait). The Windows redirector's standard reply to a batch break on a
    /// deferred-close handle is this close, so this outcome is the <i>common</i> one against Explorer.
    /// </summary>
    HolderClosed,
}
