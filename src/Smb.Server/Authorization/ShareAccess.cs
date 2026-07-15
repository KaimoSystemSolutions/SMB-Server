using Smb.Auth;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Server.State;

namespace Smb.Server.Authorization;

/// <summary>
/// Context of a share authorization decision. Contains the authenticated identity,
/// the affected share and (if present) the connection — allowing a policy to distinguish by
/// user, group SID, dialect, ClientGuid, etc.
/// </summary>
public sealed class ShareAccessContext
{
    public required SecurityIdentity Identity { get; init; }
    public required IShare Share { get; init; }

    /// <summary>Connection (for dialect/ClientGuid/encryption status). May be null for pure enumeration.</summary>
    public SmbConnection? Connection { get; init; }

    /// <summary>Convenient access to the share name.</summary>
    public string ShareName => Share.Name;
}

/// <summary>Result of a connection authorization (Context §12: check access, return MaximalAccess).</summary>
public sealed class ShareAccessResult
{
    public bool Allowed { get; private init; }

    /// <summary>Granted access mask (only relevant when <see cref="Allowed"/>). Also limits subsequent file access.</summary>
    public SmbAccessMask MaximalAccess { get; private init; }

    /// <summary>NTSTATUS on denial (default <c>STATUS_ACCESS_DENIED</c>, Context §12).</summary>
    public NtStatus DenyStatus { get; private init; }

    /// <summary>Allows the connection with the specified (default: full) access mask.</summary>
    public static ShareAccessResult Grant(SmbAccessMask maximalAccess = SmbAccessMask.FullAccess)
        => new() { Allowed = true, MaximalAccess = maximalAccess };

    /// <summary>Denies the connection.</summary>
    public static ShareAccessResult Deny(NtStatus status = NtStatus.AccessDenied)
        => new() { Allowed = false, DenyStatus = status };
}

/// <summary>
/// <b>Authorization seam.</b> Consulted by the server to
/// (a) filter the share listing (<see cref="IsVisible"/>, access-based enumeration)
/// and (b) determine access + access mask at TREE_CONNECT
/// (<see cref="AuthorizeConnect"/>, Context §12). Set a custom implementation to grant access only
/// to specific users/groups.
/// </summary>
public interface IShareAccessPolicy
{
    /// <summary>True if the share may be shown to the user in a listing.</summary>
    bool IsVisible(ShareAccessContext context);

    /// <summary>Decides the TREE_CONNECT connection and returns the granted access mask.</summary>
    ShareAccessResult AuthorizeConnect(ShareAccessContext context);

    /// <summary>
    /// [W6.1] Async visibility check for share enumeration. The default delegates to
    /// <see cref="IsVisible"/>, so a synchronous policy needs no change. Override this (and
    /// <see cref="AuthorizeConnectAsync"/>) for I/O-bound authorization (DB/LDAP): the server awaits it
    /// instead of blocking a thread pool thread sync-over-async. See
    /// docs/WINDOWS_COMPATIBILITY_ROADMAP.md Phase W6.
    /// </summary>
    ValueTask<bool> IsVisibleAsync(ShareAccessContext context) => new(IsVisible(context));

    /// <summary>
    /// [W6.1] Async connect authorization. The default delegates to <see cref="AuthorizeConnect"/>, so a
    /// synchronous policy needs no change. Override for I/O-bound authorization so the dispatcher can await
    /// it. Note (verified against the read loop): awaiting alone avoids the sync-over-async thread block but
    /// does <b>not</b> by itself unfreeze unrelated I/O — TREE_CONNECT must also leave the read-loop barrier
    /// (roadmap W6.3). See docs/WINDOWS_COMPATIBILITY_ROADMAP.md Phase W6.
    /// </summary>
    ValueTask<ShareAccessResult> AuthorizeConnectAsync(ShareAccessContext context) => new(AuthorizeConnect(context));
}

/// <summary>Default policy: all shares visible, full access for every valid session (previous behaviour).</summary>
public sealed class AllowAllSharePolicy : IShareAccessPolicy
{
    public bool IsVisible(ShareAccessContext context) => true;
    public ShareAccessResult AuthorizeConnect(ShareAccessContext context) => ShareAccessResult.Grant();
}

/// <summary>
/// Delegate-based policy — allows hooking in via lambda without writing a class:
/// <code>
/// new DelegateSharePolicy(
///     isVisible:  ctx => ctx.Identity.UserName == "alice" || ctx.ShareName != "Secret",
///     authorize:  ctx => ctx.Identity.GroupSids.Contains(AdminSid)
///                         ? ShareAccessResult.Grant()
///                         : ShareAccessResult.Grant(SmbAccessMask.ReadOnly));
/// </code>
/// </summary>
public sealed class DelegateSharePolicy : IShareAccessPolicy
{
    private readonly Func<ShareAccessContext, bool> _isVisible;
    private readonly Func<ShareAccessContext, ShareAccessResult> _authorize;

    public DelegateSharePolicy(
        Func<ShareAccessContext, ShareAccessResult> authorize,
        Func<ShareAccessContext, bool>? isVisible = null)
    {
        _authorize = authorize;
        _isVisible = isVisible ?? (_ => true);
    }

    public bool IsVisible(ShareAccessContext context) => _isVisible(context);
    public ShareAccessResult AuthorizeConnect(ShareAccessContext context) => _authorize(context);
}

/// <summary>
/// [W6.4] Async delegate-based policy — register I/O-bound authorization (DB/LDAP) via lambda without writing
/// a class. The <b>async</b> members (<see cref="AuthorizeConnectAsync"/>/<see cref="IsVisibleAsync"/>) run the
/// delegates directly and are what the TREE_CONNECT hot path awaits (roadmap W6.2/W6.3), so an awaited lookup
/// never blocks a thread and — with <see cref="SmbServerOptions.ConcurrentMetadataOps"/> on — never freezes the
/// connection. The synchronous interface members remain because share <i>enumeration</i>
/// (<c>GetVisibleShares</c>) is still a synchronous path (roadmap W6.2b); there they block on the async
/// delegate, so keep an <c>isVisible</c> lookup cheap (or accept the block until W6.2b lands).
/// <code>
/// builder.UseShareAuthorizationAsync(
///     authorizeConnect: async ctx => await _acl.CanConnectAsync(ctx.Identity, ctx.ShareName)
///                                    ? ShareAccessResult.Grant() : ShareAccessResult.Deny());
/// </code>
/// </summary>
public sealed class AsyncDelegateSharePolicy : IShareAccessPolicy
{
    private readonly Func<ShareAccessContext, ValueTask<ShareAccessResult>> _authorize;
    private readonly Func<ShareAccessContext, ValueTask<bool>> _isVisible;

    public AsyncDelegateSharePolicy(
        Func<ShareAccessContext, ValueTask<ShareAccessResult>> authorizeConnect,
        Func<ShareAccessContext, ValueTask<bool>>? isVisible = null)
    {
        _authorize = authorizeConnect ?? throw new ArgumentNullException(nameof(authorizeConnect));
        _isVisible = isVisible ?? (_ => new ValueTask<bool>(true));
    }

    public ValueTask<ShareAccessResult> AuthorizeConnectAsync(ShareAccessContext context) => _authorize(context);
    public ValueTask<bool> IsVisibleAsync(ShareAccessContext context) => _isVisible(context);

    // Synchronous fallbacks for the still-synchronous paths (enumeration, W6.2b). The awaited hot path
    // (TREE_CONNECT) uses the async members above; these block on the delegate — see the type remarks.
    public ShareAccessResult AuthorizeConnect(ShareAccessContext context) => _authorize(context).AsTask().GetAwaiter().GetResult();
    public bool IsVisible(ShareAccessContext context) => _isVisible(context).AsTask().GetAwaiter().GetResult();
}
