namespace Smb.Server.State;

/// <summary>
/// Eine asynchron ausstehende Operation (z.B. ein blockierender LOCK), für die bereits eine
/// Interim-Antwort (<c>STATUS_PENDING</c>) gesendet wurde und deren finale Antwort später
/// out-of-band folgt. Wird über die MessageId referenziert (CANCEL, Context §19, MS-SMB2
/// §3.3.5.16) und beim Schließen des zugehörigen Open bzw. beim Connection-Teardown abgebrochen.
/// </summary>
public sealed class PendingAsyncRequest
{
    public required ulong MessageId { get; init; }
    public required ulong AsyncId { get; init; }

    /// <summary>Das Open, zu dem die Operation gehört (für Abbruch beim CLOSE). Optional.</summary>
    public SmbOpen? Owner { get; init; }

    private readonly CancellationTokenSource _cts = new();

    /// <summary>Token, das ausgelöst wird, wenn die Operation abgebrochen werden soll.</summary>
    public CancellationToken Token => _cts.Token;

    /// <summary>Bricht die Operation ab (CANCEL / CLOSE / Teardown).</summary>
    public void Cancel()
    {
        try { _cts.Cancel(); } catch (ObjectDisposedException) { /* bereits abgeschlossen */ }
    }
}
