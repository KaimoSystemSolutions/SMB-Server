using Smb.Auth;
using Smb.FileSystem;
using Smb.Server.Authorization;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// docs/WINDOWS_COMPATIBILITY_ROADMAP.md W6.1 — the async authorization seam. The two async default-interface
/// methods (<see cref="IShareAccessPolicy.IsVisibleAsync"/>/<see cref="IShareAccessPolicy.AuthorizeConnectAsync"/>)
/// delegate to the synchronous ones so existing policies keep working unchanged, and a policy may override the
/// async variant for I/O-bound authorization (DB/LDAP). Purely additive — this milestone does not yet wire the
/// seam into the dispatcher (that is W6.2).
/// </summary>
public class ShareAccessPolicyAsyncTests
{
    private static ShareAccessContext Context(string shareName = "Files") => new()
    {
        Identity = new SecurityIdentity { UserName = "alice", DomainName = "DOM" },
        Share = new Share { Name = shareName, Type = ShareType.Disk },
    };

    [Fact]
    public async Task SyncPolicy_AsyncDefaults_DelegateToSyncResult()
    {
        IShareAccessPolicy policy = new AllowAllSharePolicy();

        Assert.True(await policy.IsVisibleAsync(Context()));
        ShareAccessResult result = await policy.AuthorizeConnectAsync(Context());
        Assert.True(result.Allowed);
        Assert.Equal(SmbAccessMask.FullAccess, result.MaximalAccess);
    }

    [Fact]
    public async Task DelegatePolicy_AsyncDefault_ReflectsSyncDecision()
    {
        // A sync deny decision must surface identically through the async default path.
        IShareAccessPolicy policy = new DelegateSharePolicy(
            authorize: ctx => ctx.ShareName == "Secret"
                ? ShareAccessResult.Deny()
                : ShareAccessResult.Grant(SmbAccessMask.ReadOnly));

        Assert.False((await policy.AuthorizeConnectAsync(Context("Secret"))).Allowed);
        ShareAccessResult open = await policy.AuthorizeConnectAsync(Context("Files"));
        Assert.True(open.Allowed);
        Assert.Equal(SmbAccessMask.ReadOnly, open.MaximalAccess);
    }

    [Fact]
    public async Task AsyncOverride_IsAwaited_WithoutBlockingSyncPath()
    {
        // A policy that only implements the async method (its sync method is a trivial guard) is driven purely
        // through the async seam — modelling an I/O-bound (DB/LDAP) authorization.
        var policy = new AsyncOnlyPolicy();

        ShareAccessResult result = await policy.AuthorizeConnectAsync(Context());
        Assert.True(result.Allowed);
        Assert.True(policy.AsyncPathTaken);
    }

    [Fact]
    public async Task AsyncDelegatePolicy_RunsDelegateOnAsyncPath()
    {
        IShareAccessPolicy policy = new AsyncDelegateSharePolicy(
            authorizeConnect: async ctx =>
            {
                await Task.Yield();
                return ctx.ShareName == "Secret" ? ShareAccessResult.Deny() : ShareAccessResult.Grant(SmbAccessMask.ReadOnly);
            },
            isVisible: async ctx => { await Task.Yield(); return ctx.ShareName != "Secret"; });

        Assert.True(await policy.IsVisibleAsync(Context("Files")));
        Assert.False(await policy.IsVisibleAsync(Context("Secret")));
        Assert.False((await policy.AuthorizeConnectAsync(Context("Secret"))).Allowed);
        Assert.Equal(SmbAccessMask.ReadOnly, (await policy.AuthorizeConnectAsync(Context("Files"))).MaximalAccess);
    }

    [Fact]
    public async Task AsyncDelegatePolicy_SyncFallback_BlocksAndReturnsSameDecision()
    {
        // The sync interface members (used by the still-synchronous enumeration path, W6.2b) must surface the
        // same decision as the async delegate — they block on it.
        IShareAccessPolicy policy = new AsyncDelegateSharePolicy(
            authorizeConnect: async ctx => { await Task.Yield(); return ShareAccessResult.Deny(); });

        Assert.False(policy.AuthorizeConnect(Context()).Allowed); // sync fallback
        Assert.True(policy.IsVisible(Context()));                 // default isVisible → true
        Assert.True(await policy.IsVisibleAsync(Context()));      // async default matches
    }

    /// <summary>Overrides only the async method; the sync one is the mandated interface member (never hit here).</summary>
    private sealed class AsyncOnlyPolicy : IShareAccessPolicy
    {
        public bool AsyncPathTaken { get; private set; }

        public bool IsVisible(ShareAccessContext context) => true;
        public ShareAccessResult AuthorizeConnect(ShareAccessContext context) => ShareAccessResult.Grant();

        public async ValueTask<ShareAccessResult> AuthorizeConnectAsync(ShareAccessContext context)
        {
            await Task.Yield(); // stand-in for an awaited I/O lookup
            AsyncPathTaken = true;
            return ShareAccessResult.Grant();
        }
    }
}
