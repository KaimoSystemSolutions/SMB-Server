namespace Smb.Server.State;

/// <summary>
/// An asynchronously pending operation (e.g. a blocking LOCK) for which an interim
/// response (<c>STATUS_PENDING</c>) has already been sent and whose final response will
/// follow out-of-band. Referenced by MessageId (CANCEL, Context §19, MS-SMB2
/// §3.3.5.16) and cancelled when the associated open is closed or the connection tears down.
/// </summary>
public sealed class PendingAsyncRequest
{
    public required ulong MessageId { get; init; }
    public required ulong AsyncId { get; init; }

    /// <summary>The open that the operation belongs to (for cancellation at CLOSE). Optional.</summary>
    public SmbOpen? Owner { get; init; }

    private readonly CancellationTokenSource _cts = new();

    /// <summary>Token that is triggered when the operation should be cancelled.</summary>
    public CancellationToken Token => _cts.Token;

    /// <summary>Cancels the operation (CANCEL / CLOSE / teardown).</summary>
    public void Cancel()
    {
        try { _cts.Cancel(); } catch (ObjectDisposedException) { /* already completed */ }
    }
}
