using Smb.Auth;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Server.Authorization;
using Smb.Server.Durable;
using Smb.Server.Leases;
using Smb.Server.Locking;
using Smb.Server.Multichannel;
using Smb.Server.Notification;
using Smb.Server.Oplocks;
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
