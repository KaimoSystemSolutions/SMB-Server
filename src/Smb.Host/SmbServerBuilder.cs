using System.Net;
using System.Security.Cryptography.X509Certificates;
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
    private SmbTlsOptions? _tls;
    private SmbQuicOptions? _quic;
    private int _quicPort = 443;

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

    /// <summary><b>Test/Dev only:</b> accepts any auth anonymously. Do not use in production (Context §8.4).</summary>
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

    /// <summary>
    /// [M10.1] Wraps the transport in TLS (SMB over TLS): every connection completes a TLS handshake
    /// before any SMB2 bytes are exchanged, using <paramref name="serverCertificate"/> (which must
    /// carry a private key). Layer this beneath SMB3 signing/encryption on a dedicated port (e.g.
    /// <c>.WithEndpoint(IPAddress.Any, 8445)</c>). Use <paramref name="configure"/> for mutual TLS
    /// (client certificates), protocol versions, or the handshake timeout.
    /// </summary>
    public SmbServerBuilder UseTls(X509Certificate2 serverCertificate, Action<SmbTlsOptions>? configure = null)
    {
        var tls = new SmbTlsOptions { ServerCertificate = serverCertificate };
        configure?.Invoke(tls);
        _tls = tls;
        return this;
    }

    /// <summary>
    /// [M10.3] Advertises SMB2 compression: a 3.1.1 client that offers a supported algorithm negotiates
    /// it, and the server then compresses large enough responses and decodes compressed requests.
    /// <paramref name="minSize"/> is the smallest response (bytes) worth compressing (default 4096);
    /// <paramref name="preference"/> overrides the algorithm preference (default LZ77).
    /// </summary>
    public SmbServerBuilder UseCompression(int minSize = 4096, IReadOnlyList<SmbCompressionAlgorithm>? preference = null)
    {
        _options.EnableCompression = true;
        _options.CompressionMinSize = minSize;
        if (preference is not null) _options.CompressionPreference = preference;
        return this;
    }

    /// <summary>
    /// [M10.2] Adds an SMB-over-QUIC listener (UDP, conventionally port 443) alongside TCP. Every QUIC
    /// connection completes a mandatory TLS 1.3 handshake using <paramref name="serverCertificate"/>
    /// (which must carry a private key), and each inbound bidirectional stream is served as one SMB2
    /// connection. QUIC needs the platform's MsQuic (Windows 11 / Server 2022+ built-in; <c>libmsquic</c>
    /// on Linux) — the listener throws at start if it is unavailable, while TCP keeps working. Use
    /// <paramref name="configure"/> for mutual TLS (client certificates), stream limits or the idle timeout.
    /// </summary>
    public SmbServerBuilder UseQuic(X509Certificate2 serverCertificate, int port = 443, Action<SmbQuicOptions>? configure = null)
    {
        var quic = new SmbQuicOptions { ServerCertificate = serverCertificate };
        configure?.Invoke(quic);
        _quic = quic;
        _quicPort = port;
        return this;
    }

    /// <summary>
    /// [M11.1] Sets the disk-quota provider (QUERY/SET_QUOTA_INFO + per-owner write enforcement). Default
    /// is no quotas (<see cref="Smb.Server.Quota.NullQuotaProvider"/>); supply an
    /// <see cref="Smb.Server.Quota.InMemoryQuotaProvider"/> or a custom
    /// <see cref="Smb.Server.Quota.IQuotaProvider"/> that delegates to NTFS/ZFS quotas.
    /// </summary>
    public SmbServerBuilder UseQuotaProvider(Smb.Server.Quota.IQuotaProvider provider)
    {
        _options.QuotaProvider = provider;
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

    public SmbServer Build() => new(_options, _endpoint, _log, _tls, _quic, _quicPort);
}
