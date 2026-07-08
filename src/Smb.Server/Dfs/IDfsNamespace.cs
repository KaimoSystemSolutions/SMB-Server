namespace Smb.Server.Dfs;

/// <summary>
/// Resolves a DFS path to one or more target shares (MS-DFSC, Phase 7). The server hosts a DFS
/// namespace by supplying an implementation via <c>SmbServerOptions.DfsNamespace</c>; the dispatcher
/// then answers FSCTL_DFS_GET_REFERRALS from it. Behind a seam so the core stays dependency-free and
/// testable, and a deployment can back the namespace with a static map, a database, or a real DFS
/// coordinator.
/// </summary>
public interface IDfsNamespace
{
    /// <summary>
    /// Resolves a requested UNC path (as received in REQ_GET_DFS_REFERRAL, e.g.
    /// <c>\SERVER\DfsRoot\Link\sub</c>) to its DFS targets. Returns <c>null</c> when the path is not
    /// part of any namespace this server hosts — the dispatcher then answers <c>STATUS_NOT_FOUND</c>
    /// and the client falls back to the literal path (§3.3.5.15.2).
    /// </summary>
    DfsReferralResult? Resolve(string requestFileName);

    /// <summary>
    /// [M7.2] True when <paramref name="dfsPath"/> lies at or below a DFS <b>link</b> (not the root),
    /// so accessing it should yield a referral (<c>STATUS_PATH_NOT_COVERED</c>) instead of local I/O.
    /// The default derives this from <see cref="Resolve"/> returning a non-root referral; a namespace
    /// whose <c>Resolve</c> only produces root referrals can leave this untouched.
    /// </summary>
    bool IsLinkCovered(string dfsPath) => Resolve(dfsPath) is { IsRootReferral: false };
}

/// <summary>The outcome of a successful DFS referral lookup.</summary>
public sealed class DfsReferralResult
{
    /// <summary>
    /// The namespace-path prefix that was matched (e.g. <c>\SERVER\DfsRoot\Link</c>). Its UTF-16 byte
    /// length is reported to the client as <c>PathConsumed</c>; the client appends the unconsumed
    /// remainder of its request to the chosen target.
    /// </summary>
    public required string ConsumedPath { get; init; }

    /// <summary>The targets the client may use (in preference order). Must be non-empty.</summary>
    public required IReadOnlyList<DfsTarget> Targets { get; init; }

    /// <summary>How long (seconds) the client may cache this referral. Default 300.</summary>
    public uint TimeToLiveSeconds { get; init; } = 300;

    /// <summary>
    /// <c>true</c> when this is a referral to a DFS root (root targets); <c>false</c> (default) for a
    /// link referral to storage targets — the common case.
    /// </summary>
    public bool IsRootReferral { get; init; }
}

/// <summary>A single DFS target: the UNC path a client should redirect to (e.g. <c>\Server2\Share</c>).</summary>
public sealed record DfsTarget(string TargetPath);
