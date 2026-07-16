using Smb.Protocol.Enums;
using Smb.Protocol.Messages;

namespace Smb.Server.Notification;

/// <summary>
/// [W3.1] Per-open CHANGE_NOTIFY state. Where the pre-W3 handler created a fresh watcher for every
/// CHANGE_NOTIFY request and disposed it the moment that request completed, the watch now lives on the
/// directory <c>Open</c>: it is established on the first CHANGE_NOTIFY and torn down at CLOSE. Changes that
/// arrive while no request is parked are buffered in a bounded FIFO, so the next request delivers them
/// instead of losing them — closing the gap MS-SMB2 §3.3.5.19 leaves to the server. A real client
/// (Explorer) re-registers only <i>after</i> each notification, so anything that happened in the window
/// between two requests used to be dropped permanently, and the Explorer view went stale until F5.
/// <para>Overflow is a defined protocol state, not a failure: once the buffer exceeds its cap the queued
/// events are dropped and an overflow flag is latched; the next request is answered with
/// <c>STATUS_NOTIFY_ENUM_DIR</c> and an empty body, which tells the client to re-enumerate the directory
/// itself. This bounds memory against a rename/create storm.</para>
/// <para><b>Thread-safety.</b> The watcher callback (<see cref="OnChanges"/>) runs on a thread-pool thread
/// while CHANGE_NOTIFY/CLOSE run on the dispatch path; a single lock serializes all access to the buffer,
/// the parked slot and the watch handle. The out-of-band send of a completed request runs after the lock
/// is released (fire-and-forget, as the pre-W3 code did).</para>
/// </summary>
public sealed class ChangeNotifyRegistration : IDisposable
{
    private readonly object _gate = new();
    private readonly int _maxBufferedEvents;
    private readonly Queue<FileNotifyEvent> _buffer = new();
    private bool _overflow;

    private IDisposable? _watch;
    private bool _hasWatch;
    private ChangeNotifyFilter _filter;
    private bool _watchTree;

    private Parked? _parked;
    private bool _closed;

    public ChangeNotifyRegistration(int maxBufferedEvents)
        => _maxBufferedEvents = maxBufferedEvents > 0 ? maxBufferedEvents : int.MaxValue;

    /// <summary>A CHANGE_NOTIFY that has sent its STATUS_PENDING interim and awaits an out-of-band final.
    /// <paramref name="Send"/> removes the pending entry and writes the final (status, body) out-of-band.</summary>
    private sealed record Parked(ulong MessageId, uint OutputBufferLength, Func<NtStatus, byte[], Task> Send);

    /// <summary>How a CHANGE_NOTIFY request is answered.</summary>
    public enum Disposition
    {
        /// <summary>No change is pending: an interim STATUS_PENDING was returned and the final follows out-of-band.</summary>
        Park,
        /// <summary>A change (or overflow) was already pending: answer in-band now with <see cref="RequestOutcome.Status"/>.</summary>
        Immediate,
        /// <summary>The path cannot be watched (no watcher / not a real path) → <c>STATUS_NOT_SUPPORTED</c>.</summary>
        WatcherUnavailable,
    }

    /// <summary>Result of <see cref="HandleRequest"/>. <see cref="Body"/>/<see cref="Status"/> are only meaningful for <see cref="Disposition.Immediate"/>.</summary>
    public readonly record struct RequestOutcome(Disposition Disposition, NtStatus Status, byte[] Body);

    /// <summary>
    /// Processes one CHANGE_NOTIFY. (Re)establishes the watch for (<paramref name="filter"/>,
    /// <paramref name="watchTree"/>) if it is not already running for that exact pair, then either answers
    /// immediately from the buffer/overflow state or parks the request. <paramref name="send"/> is invoked
    /// (once) when a parked request is later completed by a change.
    /// </summary>
    public RequestOutcome HandleRequest(
        string watchPath, ChangeNotifyFilter filter, bool watchTree, uint outputBufferLength,
        ulong messageId, IDirectoryWatcher watcher, Func<NtStatus, byte[], Task> send)
    {
        lock (_gate)
        {
            if (_closed)
                return new RequestOutcome(Disposition.WatcherUnavailable, default, []);

            // The CompletionFilter and WatchTree are per request, but the watch lives on the open. Explorer
            // re-registers with the same pair, so a mismatch is the rare path — restart the watch rather than
            // silently serve the wrong filter (that would be a correctness bug).
            if (!_hasWatch || _filter != filter || _watchTree != watchTree)
            {
                _watch?.Dispose();
                _hasWatch = false;
                _watch = watcher.Watch(watchPath, watchTree, filter, OnChanges);
                if (_watch is null)
                    return new RequestOutcome(Disposition.WatcherUnavailable, default, []);
                _hasWatch = true;
                _filter = filter;
                _watchTree = watchTree;
            }

            // Overflow latched → tell the client to re-enumerate; drop the (already-cleared) buffer state.
            if (_overflow)
            {
                _overflow = false;
                _buffer.Clear();
                return new RequestOutcome(Disposition.Immediate, NtStatus.NotifyEnumDir, ChangeNotifyMessage.BuildEmptyResponseBody());
            }

            // Changes arrived between two requests → deliver them now, in-band (§3.3.5.19 permits a direct
            // response when data is already available; no interim/async round trip needed).
            if (_buffer.Count > 0)
            {
                (byte[] body, bool overflow) = BuildBody(DrainLocked(), outputBufferLength);
                return new RequestOutcome(Disposition.Immediate, overflow ? NtStatus.NotifyEnumDir : NtStatus.Success, body);
            }

            // Nothing pending → park. Note: theoretically a change can arrive in the µs window between
            // watcher.Watch() above and the caller writing the interim, in which case the final may reach the
            // wire just before the interim. In practice filesystem watchers deliver events ms later; the
            // client tolerates it. The between-requests gap this class exists to close is a different, real one.
            _parked = new Parked(messageId, outputBufferLength, send);
            return new RequestOutcome(Disposition.Park, default, []);
        }
    }

    /// <summary>
    /// [W3.2] Completes a parked CHANGE_NOTIFY at CLOSE with <c>STATUS_NOTIFY_CLEANUP</c> (MS-SMB2
    /// §3.3.5.10) and tears the watch down. Idempotent: once the parked slot is taken, later cancels/teardown
    /// are no-ops. Called before the generic pending-cancellation so the client sees NOTIFY_CLEANUP rather
    /// than the generic STATUS_CANCELLED.
    /// </summary>
    public void CompleteAtClose()
    {
        Parked? toComplete;
        lock (_gate)
        {
            _closed = true;
            _watch?.Dispose();
            _watch = null;
            _hasWatch = false;
            _buffer.Clear();
            _overflow = false;
            toComplete = _parked;
            _parked = null;
        }
        if (toComplete is { } p)
            _ = p.Send(NtStatus.NotifyCleanup, ErrorResponse.BuildBody());
    }

    /// <summary>
    /// Cancels the parked request identified by <paramref name="messageId"/> with <c>STATUS_CANCELLED</c>
    /// (CANCEL / connection teardown). The watch itself survives — the directory handle is still open and
    /// the client may re-register. Returns <c>true</c> if a parked request was taken.
    /// </summary>
    public bool TryCancel(ulong messageId)
    {
        Parked? toComplete = null;
        lock (_gate)
        {
            if (_parked is { } p && p.MessageId == messageId)
            {
                _parked = null;
                toComplete = p;
            }
        }
        if (toComplete is { } c)
        {
            _ = c.Send(NtStatus.Cancelled, ErrorResponse.BuildBody());
            return true;
        }
        return false;
    }

    /// <summary>
    /// Tears the watch down without completing any parked request (connection teardown, where
    /// CancelNonSurvivingPending completes the parked request separately, and durable-handle scavenging).
    /// </summary>
    public void Dispose()
    {
        lock (_gate)
        {
            _closed = true;
            _watch?.Dispose();
            _watch = null;
            _hasWatch = false;
            _buffer.Clear();
            _overflow = false;
        }
    }

    /// <summary>Watcher callback: complete a parked request, or buffer the changes for the next request.</summary>
    private void OnChanges(IReadOnlyList<FileNotifyEvent> changes)
    {
        Parked? toComplete = null;
        NtStatus status = NtStatus.Success;
        byte[] body = [];
        lock (_gate)
        {
            if (_closed) return;

            if (_parked is { } p)
            {
                _parked = null;
                (body, bool overflow) = BuildBody(changes, p.OutputBufferLength);
                status = overflow ? NtStatus.NotifyEnumDir : NtStatus.Success;
                toComplete = p;
            }
            else if (!_overflow)
            {
                foreach (FileNotifyEvent e in changes)
                    _buffer.Enqueue(e);
                if (_buffer.Count > _maxBufferedEvents)
                {
                    _overflow = true;
                    _buffer.Clear();
                }
            }
            // else: overflow already latched — drop until a request clears it (STATUS_NOTIFY_ENUM_DIR).
        }
        if (toComplete is { } done)
            _ = done.Send(status, body);
    }

    /// <summary>Drains the buffer into a list (caller holds <see cref="_gate"/>).</summary>
    private List<FileNotifyEvent> DrainLocked()
    {
        var list = new List<FileNotifyEvent>(_buffer.Count);
        while (_buffer.TryDequeue(out FileNotifyEvent e))
            list.Add(e);
        return list;
    }

    private static (byte[] body, bool overflow) BuildBody(IReadOnlyList<FileNotifyEvent> changes, uint outputBufferLength)
    {
        var list = new List<(uint Action, string Name)>(changes.Count);
        foreach (FileNotifyEvent c in changes)
            list.Add(((uint)c.Action, c.RelativeName));
        return ChangeNotifyMessage.BuildResponseBody(list, outputBufferLength);
    }
}
