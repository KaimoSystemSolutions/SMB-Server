using System.Collections.Concurrent;
using Smb.Auth;
using Smb.FileSystem;
using Smb.Server.Authorization;

namespace Smb.Server.State;

/// <summary>
/// Global server state (Context §19, §3.3.1.5): GUID, shares and global tables.
/// Thread-safe, as it is shared by multiple connection loops.
/// </summary>
public sealed class SmbServerState
{
    private long _sessionIdCounter;
    private long _sessionGlobalIdCounter;

    public SmbServerState(SmbServerOptions options)
    {
        Options = options;
        Shares = options.Shares;
    }

    public SmbServerOptions Options { get; }
    public ShareCollection Shares { get; }

    /// <summary>SessionId → session (global across all connections, Context §19).</summary>
    public ConcurrentDictionary<ulong, SmbSession> SessionGlobalList { get; } = new();

    /// <summary>Active connections.</summary>
    public ConcurrentDictionary<Guid, SmbConnection> Connections { get; } = new();

    /// <summary>
    /// Returns the shares visible to <paramref name="identity"/> according to
    /// <see cref="SmbServerOptions.ShareAccessPolicy"/> (access-based enumeration, Context §12).
    /// This is the source for a future <c>srvsvc</c> NetShareEnum handler over IPC$.
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

    /// <summary>Allocates a new, unique SessionId (never 0, Context §8.1).</summary>
    public ulong AllocateSessionId()
    {
        ulong id;
        do { id = (ulong)Interlocked.Increment(ref _sessionIdCounter); }
        while (id == 0);
        return id;
    }

    public ulong AllocateSessionGlobalId() => (ulong)Interlocked.Increment(ref _sessionGlobalIdCounter);
}
