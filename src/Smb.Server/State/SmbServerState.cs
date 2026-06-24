using System.Collections.Concurrent;
using Smb.Auth;
using Smb.FileSystem;
using Smb.Server.Authorization;

namespace Smb.Server.State;

/// <summary>
/// Globaler Server-Zustand (Context §19, §3.3.1.5): GUID, Shares und globale Tabellen.
/// Threadsicher, da von mehreren Connection-Loops geteilt.
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

    /// <summary>SessionId → Session (global über alle Connections, Context §19).</summary>
    public ConcurrentDictionary<ulong, SmbSession> SessionGlobalList { get; } = new();

    /// <summary>Aktive Connections.</summary>
    public ConcurrentDictionary<Guid, SmbConnection> Connections { get; } = new();

    /// <summary>
    /// Liefert die für <paramref name="identity"/> sichtbaren Shares gemäß
    /// <see cref="SmbServerOptions.ShareAccessPolicy"/> (Access-Based Enumeration, Context §12).
    /// Das ist die Quelle für einen künftigen <c>srvsvc</c>-NetShareEnum-Handler über IPC$.
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

    /// <summary>Vergibt eine neue, eindeutige SessionId (nie 0, Context §8.1).</summary>
    public ulong AllocateSessionId()
    {
        ulong id;
        do { id = (ulong)Interlocked.Increment(ref _sessionIdCounter); }
        while (id == 0);
        return id;
    }

    public ulong AllocateSessionGlobalId() => (ulong)Interlocked.Increment(ref _sessionGlobalIdCounter);
}
