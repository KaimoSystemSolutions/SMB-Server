using Smb.Auth;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Server.Authorization;
using Smb.Server.Dfs;
using Smb.Server.Diagnostics;
using Smb.Server.Durable;
using Smb.Server.Leases;
using Smb.Server.Locking;
using Smb.Server.Multichannel;
using Smb.Server.Notification;
using Smb.Server.Oplocks;
using Smb.Server.Quota;
using Smb.Server.Sharing;

namespace Smb.Server;

/// <summary>
/// Server configuration with secure defaults matching Windows Server 2025/Win11-24H2
/// (Context §20). Deliberately restrictive: signing required, 3.1.1 preferred, guest/anonymous
/// rejected, modern cipher/signing preference.
/// </summary>
public sealed class SmbServerOptions
{
    /// <summary>Server name (for NETNAME context / display).</summary>
    public string ServerName { get; set; } = Environment.MachineName;

    /// <summary>Stable server GUID (16 bytes). Generated randomly if not set.</summary>
    public byte[] ServerGuid { get; set; } = Guid.NewGuid().ToByteArray();

    /// <summary>Highest dialect supported by the server (Context §6, §20: prefer 3.1.1).</summary>
    public SmbDialect MaxDialect { get; set; } = SmbDialect.Smb311;

    /// <summary>Lowest accepted dialect. SMB1 file access is excluded (Context §1).</summary>
    public SmbDialect MinDialect { get; set; } = SmbDialect.Smb202;

    /// <summary>Require signing (Context §20: default since 24H2).</summary>
    public bool RequireMessageSigning { get; set; } = true;

    /// <summary>Require encryption globally (additionally configurable per share, Context §11).</summary>
    public bool RequireEncryption { get; set; }

    /// <summary>
    /// Reject unencrypted requests to an encryption-required session or
    /// encryption-required tree with <c>STATUS_ACCESS_DENIED</c>
    /// (MS-SMB2 <c>RejectUnencryptedAccess</c>, §3.3.5.2.11). Secure default (on, like Windows
    /// since Server 2022/24H2). Only disable if clients without encryption must access.
    /// </summary>
    public bool RejectUnencryptedAccess { get; set; } = true;

    /// <summary>Reject guest access (Context §8.4, §20).</summary>
    public bool RejectGuestAccess { get; set; } = true;

    /// <summary>Allow anonymous (NULL) access? Off by default (Context §20).</summary>
    public bool AllowAnonymousAccess { get; set; }

    /// <summary>Cipher preference (descending). Default: AES-128-GCM &gt; AES-256-GCM &gt; AES-128-CCM &gt; AES-256-CCM.</summary>
    public IReadOnlyList<SmbCipherId> CipherPreference { get; set; } =
    [
        SmbCipherId.Aes128Gcm, SmbCipherId.Aes256Gcm, SmbCipherId.Aes128Ccm, SmbCipherId.Aes256Ccm,
    ];

    /// <summary>Signing preference (descending). Default: AES-GMAC &gt; AES-CMAC &gt; HMAC-SHA256 (Context §20).</summary>
    public IReadOnlyList<SmbSigningAlgorithmId> SigningPreference { get; set; } =
    [
        SmbSigningAlgorithmId.AesGmac, SmbSigningAlgorithmId.AesCmac, SmbSigningAlgorithmId.HmacSha256,
    ];

    public uint MaxTransactSize { get; set; } = 8 * 1024 * 1024;
    public uint MaxReadSize { get; set; } = 8 * 1024 * 1024;
    public uint MaxWriteSize { get; set; } = 8 * 1024 * 1024;

    /// <summary>
    /// Advertise SMB2 compression (Phase 10 / M10.3): when on, a 3.1.1 NEGOTIATE that carries a
    /// COMPRESSION_CAPABILITIES context is answered with the server's chosen algorithm, and the host
    /// then compresses large enough responses and decodes compressed requests. Off by default —
    /// compression is a throughput optimization and is opt-in until validated against the target
    /// clients; the negotiated algorithm is always taken from <see cref="CompressionPreference"/>
    /// intersected with the client list and the codecs this build implements
    /// (<see cref="Smb.Protocol.Compression.SmbCompressor.SupportedAlgorithms"/>).
    /// </summary>
    public bool EnableCompression { get; set; }

    /// <summary>
    /// Compression algorithm preference (descending) when <see cref="EnableCompression"/> is on. Only
    /// algorithms with a codec in this build take effect (currently
    /// <see cref="SmbCompressionAlgorithm.Lz77"/>). Default: LZ77.
    /// </summary>
    public IReadOnlyList<SmbCompressionAlgorithm> CompressionPreference { get; set; } =
    [
        SmbCompressionAlgorithm.Lz77,
    ];

    /// <summary>
    /// Minimum plaintext size (bytes) before a response is compressed (Phase 10 / M10.3). Small frames
    /// do not benefit and only add header overhead, so they are sent uncompressed regardless of the
    /// negotiated algorithm. Default 4096.
    /// </summary>
    public int CompressionMinSize { get; set; } = 4096;

    /// <summary>Maximum credits granted per response (cap, Context §7).</summary>
    public ushort MaxCreditsPerResponse { get; set; } = 512;

    /// <summary>
    /// [AUDIT-2026-06] Upper limit of concurrently outstanding asynchronous operations per connection
    /// (blocking LOCKs, CHANGE_NOTIFY). Protects against resource exhaustion (each outstanding
    /// operation holds a <c>PendingRequest</c> and potentially a filesystem watcher). When the
    /// limit is reached the server rejects further async requests with
    /// <c>STATUS_INSUFFICIENT_RESOURCES</c>. See docs/SECURITY_AUDIT.md (Finding H1).
    /// </summary>
    public int MaxOutstandingRequests { get; set; } = 512;

    /// <summary>
    /// Maximum concurrently processed READ/WRITE frames per connection (docs/ASYNC_IO_ROADMAP.md, A4).
    /// SMB2 clients pipeline multiple file I/Os via credits; from 2 onwards their backend accesses overlap —
    /// responses may go out-of-order (allowed; matched via MessageId, §3.3.4.1).
    /// All other commands act as a barrier (pending I/Os are drained first) and remain
    /// strictly sequential. <c>1</c> = legacy fully sequential behavior.
    /// </summary>
    public int MaxConcurrentFileOpsPerConnection { get; set; } = 8;

    /// <summary>SPNEGO negotiator (auth). Required — e.g. NTLM-based or (test) <see cref="DevSpnegoNegotiator"/>.</summary>
    public ISpnegoNegotiator? SpnegoNegotiator { get; set; }

    /// <summary>Provided shares. <c>IPC$</c> is ensured at startup (Context §12, §23).</summary>
    public ShareCollection Shares { get; set; } = new();

    /// <summary>
    /// Authorization hook for share visibility (enumeration) and access (TREE_CONNECT),
    /// Context §12. Default <see cref="AllowAllSharePolicy"/> (all visible, full access).
    /// Set a custom policy to filter per user/group and restrict permissions.
    /// </summary>
    public IShareAccessPolicy ShareAccessPolicy { get; set; } = new AllowAllSharePolicy();

    /// <summary>
    /// Byte-range lock management (SMB2 LOCK, Context §15). Default
    /// <see cref="InMemoryLockManager"/> (process-local). Set a custom implementation to delegate
    /// to the OS or a cluster, for example.
    /// </summary>
    public ILockManager LockManager { get; set; } = new InMemoryLockManager();

    /// <summary>
    /// Source for directory changes (SMB2 CHANGE_NOTIFY, Context §16). Default
    /// <see cref="FileSystemDirectoryWatcher"/> (monitors real paths). Set to
    /// <see cref="NullDirectoryWatcher"/> to disable CHANGE_NOTIFY
    /// (→ <c>STATUS_NOT_SUPPORTED</c>), or hook in a custom source (inotify, ZFS events …).
    /// </summary>
    public IDirectoryWatcher DirectoryWatcher { get; set; } = new FileSystemDirectoryWatcher();

    /// <summary>
    /// Oplock management (SMB2 oplocks, Context §15). Default <see cref="InMemoryOplockManager"/>
    /// (process-local). Set to <see cref="NullOplockManager"/> to disable oplocks (CREATE
    /// then always grants <c>OplockLevel.None</c>), or hook in a custom implementation to
    /// delegate to a cluster coordinator, for example.
    /// </summary>
    public IOplockManager OplockManager { get; set; } = new InMemoryOplockManager();

    /// <summary>
    /// Lease management (SMB 2.1+ leases, Context §15). Default <see cref="InMemoryLeaseManager"/>
    /// (process-local). Set to <see cref="NullLeaseManager"/> to disable leasing (CREATE then always
    /// grants <see cref="LeaseState.None"/> and clients fall back to classic oplocks), or hook in a
    /// custom implementation to delegate to a cluster coordinator, for example.
    /// </summary>
    public ILeaseManager LeaseManager { get; set; } = new InMemoryLeaseManager();

    /// <summary>
    /// Share-mode / sharing-violation management (CREATE ShareAccess, Context §13). Default
    /// <see cref="InMemoryShareModeManager"/> (process-local, portable). Set a custom implementation
    /// to delegate to a cluster/cross-protocol coordinator (e.g. TrueNAS SMB+NFS).
    /// </summary>
    public IShareModeManager ShareModeManager { get; set; } = new InMemoryShareModeManager();

    /// <summary>
    /// Durable/persistent handle storage (Phase 4). Default <see cref="InMemoryDurableHandleStore"/>
    /// (survives transport drops but not a process restart). Replace with a serializable store to also
    /// survive server restarts for persistent (CA) handles.
    /// </summary>
    public IDurableHandleStore DurableHandleStore { get; set; } = new InMemoryDurableHandleStore();

    /// <summary>
    /// How long a durable open is preserved after a transport drop before it is scavenged (MS-SMB2
    /// §3.3.5.9.6 durable v1 default; a durable-v2 client can request a shorter/longer value). Windows
    /// caps this around 16 minutes; the library default is a conservative 60 seconds.
    /// </summary>
    public TimeSpan DurableHandleTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Upper bound the server clamps a durable-v2 client's requested timeout to (§2.2.13.2.11). Windows
    /// caps around 16 minutes; a client value of 0 means "server decides" → <see cref="DurableHandleTimeout"/>.
    /// </summary>
    public TimeSpan MaxDurableHandleTimeout { get; set; } = TimeSpan.FromMinutes(16);

    /// <summary>
    /// Time source for durable-handle deadlines/scavenging (and future timeouts). Default
    /// <see cref="System.TimeProvider.System"/>; inject a fake in tests for deterministic expiry.
    /// </summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>
    /// Advertise multichannel (Phase 6): set <c>SMB2_GLOBAL_CAP_MULTICHANNEL</c> on 3.x NEGOTIATE and
    /// serve FSCTL_QUERY_NETWORK_INTERFACE_INFO so clients open and bind additional channels. On by
    /// default; session binding itself (§3.3.5.5.2) is always accepted when a valid signed request
    /// arrives, independently of this flag.
    /// </summary>
    public bool EnableMultichannel { get; set; } = true;

    /// <summary>
    /// Source of the interfaces reported by FSCTL_QUERY_NETWORK_INTERFACE_INFO (multichannel). Default
    /// <see cref="SystemNetworkInterfaceProvider"/> (enumerates operational, non-loopback NICs). Supply
    /// a custom provider to control exactly which interfaces (and capabilities) are advertised.
    /// </summary>
    public INetworkInterfaceProvider NetworkInterfaceProvider { get; set; } = new SystemNetworkInterfaceProvider();

    /// <summary>
    /// Optional DFS namespace served via FSCTL_DFS_GET_REFERRALS (Phase 7). <c>null</c> (default) → the
    /// server hosts no DFS namespace and answers referral requests with <c>STATUS_NOT_FOUND</c>, so
    /// clients use the literal path. Set a <see cref="StandaloneDfsNamespace"/> (or a custom
    /// <see cref="IDfsNamespace"/>) to publish DFS links; <c>SMB2_GLOBAL_CAP_DFS</c> is then advertised
    /// at NEGOTIATE so clients issue referral requests. Mark the DFS-root share
    /// <see cref="Smb.FileSystem.Share.IsDfs"/> so its TREE_CONNECT response carries the DFS flags.
    /// </summary>
    public IDfsNamespace? DfsNamespace { get; set; }

    /// <summary>
    /// Structured audit logging for security-relevant events (Phase 8 / M8.1): authentication,
    /// share access, file open/close/delete, permission change, session/connection lifecycle. Default
    /// <see cref="NullSmbAuditLogger"/> (off). Set a <see cref="DelegatingSmbAuditLogger"/> or a custom
    /// <see cref="ISmbAuditLogger"/> to forward events to a log framework or SIEM.
    /// </summary>
    public ISmbAuditLogger AuditLogger { get; set; } = NullSmbAuditLogger.Instance;

    /// <summary>
    /// Health &amp; performance counters (Phase 8 / M8.5): active connections/sessions/handles, bytes
    /// read/written (total and per share), auth attempts, lock contention and request-latency
    /// percentiles. Always collected (cheap Interlocked counters); read <see cref="SmbServerMetrics.Snapshot"/>
    /// for a health endpoint or subclass it to fan out to OpenTelemetry.
    /// </summary>
    public SmbServerMetrics Metrics { get; set; } = new();

    /// <summary>
    /// Idle-session timeout (Phase 8 / M8.2): a valid session with no request for this long is torn down
    /// (its opens/locks/oplocks/share-modes released). Default 15 min; <see cref="TimeSpan.Zero"/> disables it.
    /// </summary>
    public TimeSpan SessionIdleTimeout { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Idle-connection timeout (Phase 8 / M8.2): a TCP connection with no SMB frame for this long is
    /// closed. Default 5 min; <see cref="TimeSpan.Zero"/> disables it.
    /// </summary>
    public TimeSpan ConnectionIdleTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Authentication timeout (Phase 8 / M8.2): a connection that has not established a valid session
    /// within this window of being accepted is dropped (slow-loris / half-open auth protection). Default
    /// 30 s; <see cref="TimeSpan.Zero"/> disables it.
    /// </summary>
    public TimeSpan AuthenticationTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How often the host runs the idle/auth-timeout sweep (Phase 8 / M8.2). Default 30 s;
    /// <see cref="TimeSpan.Zero"/> disables the background sweeper entirely.
    /// </summary>
    public TimeSpan TimeoutSweepInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Maximum concurrent TCP connections the host accepts (Phase 8 / M8.3). Excess connections are
    /// closed immediately without allocating state. Default 1024; ≤ 0 disables the global cap.
    /// </summary>
    public int MaxConnections { get; set; } = 1024;

    /// <summary>
    /// Maximum concurrent TCP connections per client IP (Phase 8 / M8.3). Protects against a single
    /// client exhausting the connection budget. Default 64; ≤ 0 disables the per-client cap.
    /// </summary>
    public int MaxConnectionsPerClient { get; set; } = 64;

    /// <summary>
    /// Grace period a graceful <c>StopAsync</c> allows in-flight operations to finish before connections
    /// are force-closed (Phase 8 / M8.4). Default 30 s. During drain no new frames are read; caching
    /// holders are sent an oplock/lease break first.
    /// </summary>
    public TimeSpan ShutdownDrainTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Disk-quota provider (Phase 11 / M11.1): serves QUERY_QUOTA_INFO / SET_QUOTA_INFO and enforces
    /// per-owner limits on write (over-limit → <c>STATUS_DISK_FULL</c>). Default
    /// <see cref="NullQuotaProvider"/> (no quotas: QUERY/SET report not-supported, writes are never
    /// limited). Set an <see cref="InMemoryQuotaProvider"/> or a custom <see cref="IQuotaProvider"/> that
    /// delegates to the OS quota system (NTFS/ZFS).
    /// </summary>
    public IQuotaProvider QuotaProvider { get; set; } = NullQuotaProvider.Instance;

    /// <summary>Validates the configuration and throws on misconfiguration.</summary>
    public void Validate()
    {
        if (ServerGuid is not { Length: 16 })
            throw new InvalidOperationException("ServerGuid must be 16 bytes.");
        if (MaxDialect < MinDialect)
            throw new InvalidOperationException("MaxDialect must not be less than MinDialect.");
        if (SpnegoNegotiator is null)
            throw new InvalidOperationException("SpnegoNegotiator is required (auth provider).");
    }
}
