using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.State;

namespace Smb.Server.Leases;

/// <summary>
/// A pending lease break: the lease identified by <see cref="Key"/> currently caches at
/// <see cref="FromState"/> and must be downgraded to <see cref="ToState"/> because of a new,
/// conflicting access. The dispatcher sends a LEASE_BREAK_NOTIFICATION (§2.2.23.2) to the holder;
/// <see cref="Holder"/> is a representative open used to route the notification to the right
/// connection.
/// </summary>
public readonly record struct LeaseBreak(
    LeaseKey Key, LeaseState FromState, LeaseState ToState, ushort Epoch, SmbOpen Holder);

/// <summary>
/// Result of a lease request at CREATE: the granted caching state, the (possibly incremented) epoch
/// and the breaks this open triggered against <i>other</i> leases on the same file.
/// </summary>
public readonly record struct LeaseGrant(LeaseState GrantedState, ushort Epoch, IReadOnlyList<LeaseBreak> Breaks)
{
    public static readonly LeaseGrant None = new(LeaseState.None, 0, Array.Empty<LeaseBreak>());
}

/// <summary>
/// <b>Lease seam (SMB 2.1+, MS-SMB2 §2.2.13.2.8/§3.3.5.9.8).</b> Leases replace classic oplocks on
/// modern clients: the server delegates every lease decision here. Like <see cref="Oplocks.IOplockManager"/>
/// this interface is <b>pure state</b> (Parse↔State↔Effect): it <i>decides</i> which breaks are
/// pending but does not send them — the dispatcher delivers LEASE_BREAK notifications out-of-band.
/// The default <see cref="InMemoryLeaseManager"/> manages granted leases process-locally per file;
/// a custom implementation can delegate to a cluster coordinator. Wiring:
/// <c>SmbServerOptions.LeaseManager</c>.
/// </summary>
public interface ILeaseManager
{
    /// <summary>
    /// Registers <paramref name="open"/> under the lease from <paramref name="request"/> and grants
    /// the appropriate caching state (§3.3.5.9.8). Opens sharing the same <see cref="LeaseKey"/>
    /// share one lease; a request from a different key that conflicts with existing leases returns
    /// the resulting breaks in <see cref="LeaseGrant.Breaks"/>.
    /// </summary>
    LeaseGrant RequestLease(SmbOpen open, LeaseRequest request);

    /// <summary>
    /// Processes a LEASE_BREAK acknowledgment from a client (§3.3.5.22.2): the holder confirms the
    /// downgrade of the lease <paramref name="key"/> to <paramref name="newState"/>. Returns the now
    /// active caching state.
    /// </summary>
    LeaseState Acknowledge(LeaseKey key, LeaseState newState);

    /// <summary>At CLOSE, detaches <paramref name="open"/> from its lease; when the last open of a
    /// lease closes, the lease is released (§3.3.5.10).</summary>
    void ReleaseOwner(SmbOpen open);
}

/// <summary>
/// <see cref="ILeaseManager"/> that never grants a lease — CREATE always returns
/// <see cref="LeaseState.None"/>. Use to disable leasing entirely (clients then fall back to
/// classic oplocks or no caching). Wiring:
/// <c>SmbServerOptions.LeaseManager = new NullLeaseManager()</c>.
/// </summary>
public sealed class NullLeaseManager : ILeaseManager
{
    public LeaseGrant RequestLease(SmbOpen open, LeaseRequest request) => LeaseGrant.None;
    public LeaseState Acknowledge(LeaseKey key, LeaseState newState) => LeaseState.None;
    public void ReleaseOwner(SmbOpen open) { }
}
