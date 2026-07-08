namespace Smb.Server.Dfs;

/// <summary>
/// A stand-alone (single-server) DFS namespace with a static link table (MS-DFSC §3.2). Each link
/// maps a namespace path (<c>\SERVER\DfsRoot\Link</c>) to one or more UNC targets
/// (<c>\Server2\Share</c>). A request is resolved to the <b>longest matching link prefix</b>, so
/// nested links and sub-paths below a link both resolve correctly. Path matching is
/// case-insensitive (SMB paths are); comparison is per whole path component.
/// </summary>
public sealed class StandaloneDfsNamespace : IDfsNamespace
{
    private readonly List<Link> _links = new();
    private readonly uint _defaultTtlSeconds;

    /// <param name="defaultTtlSeconds">Referral lifetime advertised to clients (default 300 s).</param>
    public StandaloneDfsNamespace(uint defaultTtlSeconds = 300) => _defaultTtlSeconds = defaultTtlSeconds;

    private sealed record Link(string Path, IReadOnlyList<string> Targets, bool IsRoot);

    /// <summary>
    /// Publishes a DFS link. <paramref name="dfsPath"/> is the namespace path
    /// (<c>\SERVER\DfsRoot\Link</c>); <paramref name="targets"/> are the UNC targets the client is
    /// redirected to (in preference order).
    /// </summary>
    public StandaloneDfsNamespace AddLink(string dfsPath, params string[] targets)
    {
        if (targets is null || targets.Length == 0)
            throw new ArgumentException("A DFS link needs at least one target.", nameof(targets));
        _links.Add(new Link(Normalize(dfsPath), targets, IsRoot: false));
        return this;
    }

    /// <summary>
    /// Publishes the DFS root referral (<c>\SERVER\DfsRoot</c> → root target servers). Optional; a
    /// stand-alone root points at itself. Root targets are advertised as such (ServerType root).
    /// </summary>
    public StandaloneDfsNamespace AddRoot(string dfsRootPath, params string[] targets)
    {
        if (targets is null || targets.Length == 0)
            throw new ArgumentException("A DFS root needs at least one target.", nameof(targets));
        _links.Add(new Link(Normalize(dfsRootPath), targets, IsRoot: true));
        return this;
    }

    public DfsReferralResult? Resolve(string requestFileName)
    {
        if (string.IsNullOrEmpty(requestFileName))
            return null;

        string path = Normalize(requestFileName);
        Link? best = null;
        foreach (Link link in _links)
        {
            if (IsPrefix(path, link.Path) && (best is null || link.Path.Length > best.Path.Length))
                best = link;
        }
        if (best is null)
            return null;

        return new DfsReferralResult
        {
            ConsumedPath = best.Path,
            Targets = best.Targets.Select(t => new DfsTarget(t)).ToArray(),
            TimeToLiveSeconds = _defaultTtlSeconds,
            IsRootReferral = best.IsRoot,
        };
    }

    /// <summary>True when <paramref name="path"/> equals <paramref name="prefix"/> or continues below
    /// it on a component boundary (case-insensitive).</summary>
    private static bool IsPrefix(string path, string prefix)
    {
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return false;
        return path.Length == prefix.Length || path[prefix.Length] == '\\';
    }

    /// <summary>Ensures a single leading backslash and strips any trailing backslashes.</summary>
    private static string Normalize(string path)
    {
        string p = path.Trim();
        p = p.TrimEnd('\\');
        if (!p.StartsWith('\\'))
            p = "\\" + p;
        return p;
    }
}
