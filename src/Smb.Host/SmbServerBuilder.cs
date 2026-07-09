using System.Net;
using System.Security.Cryptography.X509Certificates;
using Smb.Auth;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.FileSystem.Versioning;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.Authorization;
using Smb.Server.Dfs;
using Smb.Server.Diagnostics;
using Smb.Server.Durable;
using Smb.Server.Leases;
using Smb.Server.Locking;
using Smb.Server.Multichannel;
using Smb.Server.Notification;
using Smb.Server.Oplocks;
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
    private WsDiscoveryOptions? _wsDiscovery;

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

    /// <summary>
    /// Reject unencrypted requests against an encryption-required session/tree with
    /// <c>STATUS_ACCESS_DENIED</c> (secure default: on, like Windows since Server 2022/24H2). Only relax
    /// it if clients that cannot encrypt must still reach encryption-required shares.
    /// </summary>
    public SmbServerBuilder RejectUnencryptedAccess(bool reject = true)
    {
        _options.RejectUnencryptedAccess = reject;
        return this;
    }

    /// <summary>Reject guest fallback logins (secure default: on, Context §8.4/§20).</summary>
    public SmbServerBuilder RejectGuestAccess(bool reject = true)
    {
        _options.RejectGuestAccess = reject;
        return this;
    }

    /// <summary>Allow anonymous (NULL-session) access (default off; Context §20).</summary>
    public SmbServerBuilder AllowAnonymousAccess(bool allow = true)
    {
        _options.AllowAnonymousAccess = allow;
        return this;
    }

    /// <summary>
    /// Pins a stable 16-byte server GUID (NEGOTIATE / durable-handle identity). By default a random GUID
    /// is generated per process; set a persisted value so clients recognize the same server across restarts.
    /// </summary>
    public SmbServerBuilder WithServerGuid(Guid guid)
    {
        _options.ServerGuid = guid.ToByteArray();
        return this;
    }

    /// <summary>Overrides the AES cipher preference (descending) advertised for SMB3 encryption.</summary>
    public SmbServerBuilder WithCipherPreference(params SmbCipherId[] ciphers)
    {
        _options.CipherPreference = ciphers;
        return this;
    }

    /// <summary>Overrides the signing-algorithm preference (descending) advertised for SMB3 signing.</summary>
    public SmbServerBuilder WithSigningPreference(params SmbSigningAlgorithmId[] algorithms)
    {
        _options.SigningPreference = algorithms;
        return this;
    }

    /// <summary>
    /// Sets the maximum negotiated READ / WRITE / TRANSACT payload sizes (bytes). Larger values raise
    /// throughput at the cost of per-request buffers; defaults are 8&#160;MiB each.
    /// </summary>
    public SmbServerBuilder WithMaxIoSizes(uint maxReadSize, uint maxWriteSize, uint maxTransactSize)
    {
        _options.MaxReadSize = maxReadSize;
        _options.MaxWriteSize = maxWriteSize;
        _options.MaxTransactSize = maxTransactSize;
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
    /// Adds a disk share backed by a <see cref="LocalFileStore"/> over <paramref name="directory"/> —
    /// the common case, without hand-building a <see cref="Share"/>. <paramref name="remark"/> is the
    /// share description shown to clients (net view / Explorer), <paramref name="encrypt"/> forces
    /// per-share SMB3 encryption, and <paramref name="continuousAvailability"/> grants persistent handles
    /// (SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY).
    /// </summary>
    public SmbServerBuilder AddDiskShare(
        string name,
        string directory,
        bool readOnly = false,
        string remark = "",
        bool encrypt = false,
        bool continuousAvailability = false)
    {
        _options.Shares.Add(new Share
        {
            Name = name,
            Type = ShareType.Disk,
            FileStore = new LocalFileStore(directory, readOnly),
            Remark = remark,
            EncryptData = encrypt,
            ContinuousAvailability = continuousAvailability,
        });
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
    /// Sets oplock management (SMB2 oplocks, Context §15). Default is process-local
    /// (<see cref="InMemoryOplockManager"/>); pass <see cref="NullOplockManager"/> to disable oplocks
    /// (CREATE then always grants <c>None</c>), or a custom <see cref="IOplockManager"/> to delegate to a
    /// cluster coordinator.
    /// </summary>
    public SmbServerBuilder UseOplockManager(IOplockManager manager)
    {
        _options.OplockManager = manager;
        return this;
    }

    /// <summary>
    /// Sets lease management (SMB 2.1+ leases, Context §15). Default is process-local
    /// (<see cref="InMemoryLeaseManager"/>); pass <see cref="NullLeaseManager"/> to disable leasing
    /// (clients fall back to classic oplocks), or a custom <see cref="ILeaseManager"/>.
    /// </summary>
    public SmbServerBuilder UseLeaseManager(ILeaseManager manager)
    {
        _options.LeaseManager = manager;
        return this;
    }

    /// <summary>
    /// Sets the durable/persistent-handle store (Phase 4) and optionally the post-drop retention window.
    /// Default is <see cref="InMemoryDurableHandleStore"/> (survives transport drops but not a process
    /// restart); supply a serializable store to also survive restarts for persistent (CA) handles.
    /// </summary>
    public SmbServerBuilder UseDurableHandleStore(IDurableHandleStore store, TimeSpan? timeout = null)
    {
        _options.DurableHandleStore = store;
        if (timeout is { } t)
            _options.DurableHandleTimeout = t;
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

    /// <summary>
    /// Publishes a DFS namespace served via FSCTL_DFS_GET_REFERRALS (Phase 7). Advertises
    /// <c>SMB2_GLOBAL_CAP_DFS</c> at NEGOTIATE so clients issue referral requests; mark the DFS-root share
    /// <see cref="Share.IsDfs"/> so its TREE_CONNECT response carries the DFS flags. Default is no namespace
    /// (referrals answered with <c>STATUS_NOT_FOUND</c>).
    /// </summary>
    public SmbServerBuilder UseDfsNamespace(IDfsNamespace dfsNamespace)
    {
        _options.DfsNamespace = dfsNamespace;
        return this;
    }

    /// <summary>
    /// Toggles multichannel (Phase 6): whether <c>SMB2_GLOBAL_CAP_MULTICHANNEL</c> is advertised and
    /// FSCTL_QUERY_NETWORK_INTERFACE_INFO served so clients open additional channels. On by default.
    /// </summary>
    public SmbServerBuilder EnableMultichannel(bool enable = true)
    {
        _options.EnableMultichannel = enable;
        return this;
    }

    /// <summary>
    /// Overrides the interfaces reported by FSCTL_QUERY_NETWORK_INTERFACE_INFO (multichannel). Default
    /// <see cref="SystemNetworkInterfaceProvider"/> (operational, non-loopback NICs); supply a custom
    /// provider to control exactly which interfaces and capabilities are advertised.
    /// </summary>
    public SmbServerBuilder UseNetworkInterfaceProvider(INetworkInterfaceProvider provider)
    {
        _options.NetworkInterfaceProvider = provider;
        return this;
    }

    /// <summary>
    /// Sets the structured audit-log sink for security-relevant events (Phase 8 / M8.1: auth, share
    /// access, file open/close/delete, permission change, session/connection lifecycle). Default is off
    /// (<see cref="NullSmbAuditLogger"/>).
    /// </summary>
    public SmbServerBuilder UseAuditLogger(ISmbAuditLogger logger)
    {
        _options.AuditLogger = logger;
        return this;
    }

    /// <summary>
    /// Forwards audit events at or above <paramref name="minLevel"/> to <paramref name="sink"/> — the
    /// simplest way to wire auditing to a console/logger/SIEM.
    /// </summary>
    public SmbServerBuilder UseAuditLogger(Action<SmbAuditEvent> sink, SmbLogLevel minLevel = SmbLogLevel.Information)
    {
        _options.AuditLogger = new DelegatingSmbAuditLogger(sink, minLevel);
        return this;
    }

    /// <summary>
    /// Supplies the health/performance counters instance (Phase 8 / M8.5) so the caller can read
    /// <see cref="SmbServerMetrics.Snapshot"/> for a health endpoint or bridge it to OpenTelemetry.
    /// A default instance is used when not set.
    /// </summary>
    public SmbServerBuilder UseMetrics(SmbServerMetrics metrics)
    {
        _options.Metrics = metrics;
        return this;
    }

    /// <summary>
    /// Caps concurrent TCP connections (Phase 8 / M8.3): <paramref name="max"/> total and
    /// <paramref name="perClient"/> per source IP. Excess connections are closed without allocating state;
    /// pass <c>0</c> to disable a cap. Defaults are 1024 / 64.
    /// </summary>
    public SmbServerBuilder WithConnectionLimits(int max, int perClient)
    {
        _options.MaxConnections = max;
        _options.MaxConnectionsPerClient = perClient;
        return this;
    }

    /// <summary>
    /// Sets the idle/auth timeouts (Phase 8 / M8.2): a session idle for <paramref name="session"/> or a
    /// connection idle for <paramref name="connection"/> is torn down, and a connection that has not
    /// authenticated within <paramref name="authentication"/> of being accepted is dropped.
    /// <see cref="TimeSpan.Zero"/> disables the respective timeout. Defaults 15&#160;min / 5&#160;min / 30&#160;s.
    /// </summary>
    public SmbServerBuilder WithIdleTimeouts(TimeSpan session, TimeSpan connection, TimeSpan authentication)
    {
        _options.SessionIdleTimeout = session;
        _options.ConnectionIdleTimeout = connection;
        _options.AuthenticationTimeout = authentication;
        return this;
    }

    /// <summary>
    /// Sets the time source for durable-handle deadlines/scavenging and idle timeouts. Default
    /// <see cref="System.TimeProvider.System"/>; inject a fake for deterministic tests.
    /// </summary>
    public SmbServerBuilder WithTimeProvider(TimeProvider timeProvider)
    {
        _options.TimeProvider = timeProvider;
        return this;
    }

    /// <summary>
    /// [M11.3] Enables the WS-Discovery responder so the server appears in Windows Explorer's Network view:
    /// a UDP listener on port 3702 joins the multicast group, answers Probe messages with a ProbeMatches
    /// reply, and announces Hello/Bye. Use <paramref name="configure"/> to set a stable
    /// <see cref="WsDiscoveryOptions.EndpointId"/>, the advertised <see cref="WsDiscoveryOptions.XAddrs"/>
    /// (host/IP), or device types.
    /// </summary>
    public SmbServerBuilder UseWsDiscovery(Action<WsDiscoveryOptions>? configure = null)
    {
        var wsd = new WsDiscoveryOptions();
        configure?.Invoke(wsd);
        _wsDiscovery = wsd;
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

    public SmbServer Build() => new(_options, _endpoint, _log, _tls, _quic, _quicPort, _wsDiscovery);
}
