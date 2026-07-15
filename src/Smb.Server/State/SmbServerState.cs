using System.Collections.Concurrent;
using Smb.Auth;
using Smb.FileSystem;
using Smb.Server.Authorization;
using Smb.Server.Durable;
using Smb.Server.Witness;

namespace Smb.Server.State;

/// <summary>
/// Global server state (Context §19, §3.3.1.5): GUID, shares and global tables.
/// Thread-safe, as it is shared by multiple connection loops.
/// </summary>
public sealed class SmbServerState
{
    private long _sessionIdCounter;
    private long _sessionGlobalIdCounter;
    private long _persistentIdCounter;

    public SmbServerState(SmbServerOptions options)
    {
        Options = options;
        Shares = options.Shares;

        // [C2] Seed the persistent-id counter past any handle recovered from a persistent durable store so a
        // freshly allocated durable FileId cannot collide with a rehydrated persistent handle after a restart.
        if (options.DurableHandleStore is IPersistentHandleStore persistent)
            _persistentIdCounter = (long)(persistent.HighestPersistentId & 0x7FFF_FFFF_FFFF_FFFF);
    }

    public SmbServerOptions Options { get; }
    public ShareCollection Shares { get; }

    /// <summary>SessionId → session (global across all connections, Context §19).</summary>
    public ConcurrentDictionary<ulong, SmbSession> SessionGlobalList { get; } = new();

    /// <summary>Active connections.</summary>
    public ConcurrentDictionary<Guid, SmbConnection> Connections { get; } = new();

    /// <summary>Server-global witness (MS-SWN) registrations, shared by all <c>\PIPE\witness</c> endpoints (C1).</summary>
    public WitnessRegistrationStore WitnessRegistrations { get; } = new();

    /// <summary>
    /// Returns the shares visible to <paramref name="identity"/> according to
    /// <see cref="SmbServerOptions.ShareAccessPolicy"/> (access-based enumeration, Context §12).
    /// <para>
    /// Synchronous variant — kept for callers/policies that are synchronous. The server's own
    /// <c>srvsvc</c> enumeration path uses <see cref="GetVisibleSharesAsync"/> since W6.2b, so an
    /// I/O-bound policy is awaited rather than blocked.
    /// </para>
    /// </summary>
    public IReadOnlyList<IShare> GetVisibleShares(SecurityIdentity identity, SmbConnection? connection = null)
    {
        var result = new List<IShare>();
        foreach (IShare share in Shares.All)
        {
            var ctx = new ShareAccessContext { Identity = identity, Share = share, Connection = connection };
            if (Options.ShareAccessPolicy.IsVisible(ctx))
                result.Add(share);
        }
        return result;
    }

    /// <summary>
    /// [W6.2b] Async counterpart of <see cref="GetVisibleShares"/>: consults
    /// <see cref="IShareAccessPolicy.IsVisibleAsync"/> so an I/O-bound visibility check (DB/LDAP) is awaited
    /// instead of blocking a thread. Shares are evaluated in <see cref="Shares"/> order, so the resulting
    /// list is identical to the synchronous variant for any synchronous policy (whose async default simply
    /// delegates) — this milestone is behaviour-neutral for existing policies.
    /// </summary>
    public async ValueTask<IReadOnlyList<IShare>> GetVisibleSharesAsync(SecurityIdentity identity, SmbConnection? connection = null)
    {
        var result = new List<IShare>();
        foreach (IShare share in Shares.All)
        {
            var ctx = new ShareAccessContext { Identity = identity, Share = share, Connection = connection };
            if (await Options.ShareAccessPolicy.IsVisibleAsync(ctx).ConfigureAwait(false))
                result.Add(share);
        }
        return result;
    }

    /// <summary>Allocates a new, unique SessionId (never 0, Context §8.1).</summary>
    public ulong AllocateSessionId()
    {
        ulong id;
        do { id = (ulong)Interlocked.Increment(ref _sessionIdCounter); }
        while (id == 0);
        return id;
    }

    public ulong AllocateSessionGlobalId() => (ulong)Interlocked.Increment(ref _sessionGlobalIdCounter);

    /// <summary>
    /// Allocates a stable, server-unique non-zero persistent FileId for a durable/persistent open
    /// (Phase 4). The high bit is set so it never collides with a per-connection volatile id space.
    /// </summary>
    public ulong AllocatePersistentId() => 0x8000_0000_0000_0000UL | (ulong)Interlocked.Increment(ref _persistentIdCounter);
}
