using System.Net;
using Smb.Auth;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.FileSystem.Versioning;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.Authorization;
using Smb.Server.Locking;
using Smb.Server.Notification;
using Smb.Server.Sharing;

namespace Smb.Host;

/// <summary>
/// Fluent builder for a <see cref="SmbServer"/> with secure defaults (Context §20).
/// Makes the library "simple and dynamic" to use: endpoint, auth provider and shares
/// are assembled declaratively.
/// </summary>
public sealed class SmbServerBuilder
{
    private readonly SmbServerOptions _options = new();
    private IPEndPoint _endpoint = new(IPAddress.Any, 445);
    private Action<string>? _log;

    public static SmbServerBuilder Create() => new();

    /// <summary>Sets the listen endpoint (default 0.0.0.0:445).</summary>
    public SmbServerBuilder WithEndpoint(IPAddress address, int port)
    {
        _endpoint = new IPEndPoint(address, port);
        return this;
    }

    public SmbServerBuilder WithEndpoint(IPEndPoint endpoint)
    {
        _endpoint = endpoint;
        return this;
    }

    /// <summary>Sets the server name (display/NETNAME).</summary>
    public SmbServerBuilder WithServerName(string name)
    {
        _options.ServerName = name;
        return this;
    }

    /// <summary>Limits the dialect range (default 2.0.2 … 3.1.1).</summary>
    public SmbServerBuilder WithDialectRange(SmbDialect min, SmbDialect max)
    {
        _options.MinDialect = min;
        _options.MaxDialect = max;
        return this;
    }

    /// <summary>Require signing (default true) or relax it.</summary>
    public SmbServerBuilder RequireSigning(bool require = true)
    {
        _options.RequireMessageSigning = require;
        return this;
    }

    /// <summary>Require encryption globally (default false; can be enabled per share).</summary>
    public SmbServerBuilder RequireEncryption(bool require = true)
    {
        _options.RequireEncryption = require;
        return this;
    }

    /// <summary>Sets the auth provider (SPNEGO/GSS) — e.g. NTLM/Kerberos (Context §9).</summary>
    public SmbServerBuilder UseAuthentication(ISpnegoNegotiator negotiator)
    {
        _options.SpnegoNegotiator = negotiator;
        return this;
    }

    /// <summary><b>Nur Test/Dev:</b> akzeptiert jede Auth anonym. In Produktion nicht verwenden (Context §8.4).</summary>
    public SmbServerBuilder UseDevAuthentication()
    {
        _options.SpnegoNegotiator = new DevSpnegoNegotiator();
        _options.AllowAnonymousAccess = true;
        _options.RequireMessageSigning = false;
        return this;
    }

    /// <summary>Adds a share.</summary>
    public SmbServerBuilder AddShare(IShare share)
    {
        _options.Shares.Add(share);
        return this;
    }

    /// <summary>
    /// Adds a writable disk share with versioning ("Previous Versions"): a
    /// <see cref="LocalFileStore"/> over <paramref name="directory"/>, wrapped by a
    /// <see cref="VersioningFileStore"/>. Overwritten file contents remain available as snapshots
    /// via <c>@GMT-…</c> paths and FSCTL_SRV_ENUMERATE_SNAPSHOTS.
    /// </summary>
    public SmbServerBuilder AddVersionedShare(
        string name, string directory, bool encrypt = false, string remark = "", int maxVersionsPerFile = 64)
    {
        var store = new VersioningFileStore(new LocalFileStore(directory, readOnly: false), maxVersionsPerFile);
        _options.Shares.Add(new Share
        {
            Name = name,
            Type = ShareType.Disk,
            FileStore = store,
            EncryptData = encrypt,
            Remark = remark,
        });
        return this;
    }

    /// <summary>
    /// Sets the authorization policy (share visibility + access check at TREE_CONNECT).
    /// </summary>
    public SmbServerBuilder UseShareAuthorization(IShareAccessPolicy policy)
    {
        _options.ShareAccessPolicy = policy;
        return this;
    }

    /// <summary>
    /// Hooks in authorization via lambda — ideal for custom file server logic:
    /// <paramref name="authorizeConnect"/> decides access + access mask at TREE_CONNECT,
    /// <paramref name="isVisible"/> filters share visibility (default: all visible).
    /// </summary>
    public SmbServerBuilder UseShareAuthorization(
        Func<ShareAccessContext, ShareAccessResult> authorizeConnect,
        Func<ShareAccessContext, bool>? isVisible = null)
    {
        _options.ShareAccessPolicy = new DelegateSharePolicy(authorizeConnect, isVisible);
        return this;
    }

    /// <summary>
    /// Sets the byte-range lock management (SMB2 LOCK, Context §15). Default is process-local
    /// (<see cref="InMemoryLockManager"/>); a custom <see cref="ILockManager"/> implementation
    /// can delegate locking to the OS or a cluster, for example.
    /// </summary>
    public SmbServerBuilder UseLockManager(ILockManager lockManager)
    {
        _options.LockManager = lockManager;
        return this;
    }

    /// <summary>
    /// Sets the source for CHANGE_NOTIFY (Context §16). Default monitors real directories via
    /// <see cref="FileSystemWatcher"/>; a custom <see cref="IDirectoryWatcher"/> implementation
    /// can hook into inotify, ZFS events, etc., or <see cref="NullDirectoryWatcher"/> disables it.
    /// </summary>
    public SmbServerBuilder UseDirectoryWatcher(IDirectoryWatcher watcher)
    {
        _options.DirectoryWatcher = watcher;
        return this;
    }

    /// <summary>
    /// Sets share-mode (sharing-violation) management for CREATE ShareAccess (Context §13). Default
    /// is process-local (<see cref="InMemoryShareModeManager"/>); a custom <see cref="IShareModeManager"/>
    /// can delegate to a cluster/cross-protocol coordinator (e.g. TrueNAS SMB+NFS).
    /// </summary>
    public SmbServerBuilder UseShareModeManager(IShareModeManager manager)
    {
        _options.ShareModeManager = manager;
        return this;
    }

    /// <summary>Configures options directly (for fine-grained settings).</summary>
    public SmbServerBuilder Configure(Action<SmbServerOptions> configure)
    {
        configure(_options);
        return this;
    }

    /// <summary>Sets a log callback (e.g. console).</summary>
    public SmbServerBuilder WithLogger(Action<string> log)
    {
        _log = log;
        return this;
    }

    public SmbServer Build() => new(_options, _endpoint, _log);
}
