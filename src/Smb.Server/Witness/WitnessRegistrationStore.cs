using System.Collections.Concurrent;

namespace Smb.Server.Witness;

/// <summary>A single pending witness notification (one RESP_ASYNC_NOTIFY worth of messages).</summary>
public sealed class WitnessNotification
{
    public required WitnessNotifyType Type { get; init; }
    public required int MessageCount { get; init; }
    public required byte[] MessageBuffer { get; init; }
}

/// <summary>
/// The async-notify rendezvous for one registration: at most one outstanding <c>WitnessrAsyncNotify</c>
/// waiter at a time, plus a small buffer so a notification pushed <em>between</em> two AsyncNotify calls is
/// not lost. A buffered notification is delivered on a pooled thread (never inline in <see cref="Wait"/>) so
/// the caller can emit its <c>STATUS_PENDING</c> interim response before the out-of-band final is sent —
/// preserving SMB2 interim-before-final ordering.
/// </summary>
public sealed class WitnessNotificationChannel
{
    private const int MaxBuffered = 64; // bound the queue against a runaway trigger

    private readonly object _gate = new();
    private readonly Queue<WitnessNotification> _pending = new();
    private Action<WitnessNotification>? _waiter;

    /// <summary>
    /// Arms a one-shot waiter for the next notification. If one is already buffered it is delivered
    /// asynchronously (pooled) and the returned handle is a no-op; otherwise the returned handle detaches
    /// the waiter on dispose (cancellation / teardown).
    /// </summary>
    public IDisposable Wait(Action<WitnessNotification> onNotify)
    {
        lock (_gate)
        {
            if (_pending.Count == 0)
            {
                _waiter = onNotify;
                return new Detacher(this, onNotify);
            }

            WitnessNotification n = _pending.Dequeue();
            ThreadPool.QueueUserWorkItem(_ => onNotify(n));
            return NoopDisposable.Instance;
        }
    }

    /// <summary>Delivers a notification to the current waiter, or buffers it (bounded) if none is armed.</summary>
    public void Push(WitnessNotification notification)
    {
        Action<WitnessNotification>? waiter;
        lock (_gate)
        {
            if (_waiter is not null)
            {
                waiter = _waiter;
                _waiter = null;
            }
            else
            {
                if (_pending.Count < MaxBuffered) _pending.Enqueue(notification);
                return;
            }
        }
        waiter(notification);
    }

    private void Detach(Action<WitnessNotification> waiter)
    {
        lock (_gate)
            if (ReferenceEquals(_waiter, waiter)) _waiter = null;
    }

    private sealed class Detacher(WitnessNotificationChannel owner, Action<WitnessNotification> waiter) : IDisposable
    {
        public void Dispose() => owner.Detach(waiter);
    }

    private sealed class NoopDisposable : IDisposable
    {
        public static readonly NoopDisposable Instance = new();
        public void Dispose() { }
    }
}

/// <summary>
/// A live witness registration (MS-SWN): a client that called <c>WitnessrRegister(Ex)</c> and holds a
/// context handle, awaiting async failover notifications for a monitored net name / share. Its lifetime
/// is bound to the RPC connection that created it (dropped on that connection's teardown, C1.4).
/// The notification channel is added in C1.3.
/// </summary>
public sealed class WitnessRegistration
{
    /// <summary>UUID portion of the 20-byte RPC context handle; the store key.</summary>
    public required Guid Id { get; init; }

    /// <summary>Owning connection (lifetime + notification routing).</summary>
    public required Guid ConnectionId { get; init; }

    public required uint Version { get; init; }
    public string? NetName { get; init; }
    public string? ShareName { get; init; }
    public string? IpAddress { get; init; }
    public string? ClientComputerName { get; init; }

    /// <summary>Async-notify rendezvous for this registration's outstanding <c>WitnessrAsyncNotify</c> (C1.3).</summary>
    public WitnessNotificationChannel Notifications { get; } = new();

    /// <summary>The 20-byte RPC context handle: <c>attributes(4)=0</c> + <c>UUID(16)</c>.</summary>
    public byte[] ContextHandle()
    {
        var h = new byte[20];
        Id.TryWriteBytes(h.AsSpan(4));
        return h;
    }
}

/// <summary>
/// Server-global table of active witness registrations, keyed by the context-handle UUID. Thread-safe;
/// shared by all <c>WitnessEndpoint</c> instances so a server-side failover trigger (C1.4) can reach a
/// registration regardless of which pipe/connection created it.
/// </summary>
public sealed class WitnessRegistrationStore
{
    private readonly ConcurrentDictionary<Guid, WitnessRegistration> _byId = new();

    public WitnessRegistration Add(
        Guid connectionId, uint version, string? netName, string? shareName, string? ipAddress, string? clientComputerName)
    {
        var reg = new WitnessRegistration
        {
            Id = Guid.NewGuid(),
            ConnectionId = connectionId,
            Version = version,
            NetName = netName,
            ShareName = shareName,
            IpAddress = ipAddress,
            ClientComputerName = clientComputerName,
        };
        _byId[reg.Id] = reg;
        return reg;
    }

    public bool TryGet(Guid id, out WitnessRegistration registration) => _byId.TryGetValue(id, out registration!);

    public bool Remove(Guid id) => _byId.TryRemove(id, out _);

    /// <summary>Snapshot of all registrations (safe under concurrent mutation) — used by the failover trigger (C1.4).</summary>
    public IReadOnlyList<WitnessRegistration> Snapshot() => _byId.Values.ToArray();

    /// <summary>
    /// [C1.4] Server-side failover trigger: delivers a RESOURCE_CHANGE notification to every registration
    /// monitoring <paramref name="netName"/> (case-insensitive; null/empty matches all registrations). A
    /// waiting <c>WitnessrAsyncNotify</c> completes immediately; otherwise the notification is buffered for
    /// the client's next AsyncNotify. Returns the number of registrations notified.
    /// </summary>
    public int NotifyResourceChange(string? netName, WitnessResourceChange change, string resourceName)
    {
        byte[] buffer = WitnessWire.EncodeResourceChange(change, resourceName);
        int notified = 0;
        foreach (WitnessRegistration reg in _byId.Values)
        {
            if (!string.IsNullOrEmpty(netName) && !string.Equals(reg.NetName, netName, StringComparison.OrdinalIgnoreCase))
                continue;
            reg.Notifications.Push(new WitnessNotification
            {
                Type = WitnessNotifyType.ResourceChange,
                MessageCount = 1,
                MessageBuffer = buffer,
            });
            notified++;
        }
        return notified;
    }

    /// <summary>Drops every registration owned by <paramref name="connectionId"/>; returns the count removed (teardown, C1.4).</summary>
    public int RemoveAllForConnection(Guid connectionId)
    {
        int removed = 0;
        foreach (WitnessRegistration reg in _byId.Values)
            if (reg.ConnectionId == connectionId && _byId.TryRemove(reg.Id, out _))
                removed++;
        return removed;
    }

    /// <summary>Reads the context-handle UUID from the first 20 bytes of an RPC request stub.</summary>
    public static bool TryReadContextHandle(ReadOnlySpan<byte> stub, out Guid id)
    {
        if (stub.Length < 20) { id = default; return false; }
        id = new Guid(stub.Slice(4, 16));
        return true;
    }
}
