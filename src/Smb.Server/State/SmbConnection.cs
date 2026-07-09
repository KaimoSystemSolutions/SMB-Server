using System.Collections.Concurrent;
using Smb.Auth;
using Smb.Crypto;
using Smb.Protocol.Enums;

namespace Smb.Server.State;

/// <summary>
/// Transient state of an in-progress channel binding (§3.3.5.5.2): the fresh SPNEGO context the
/// binding connection re-authenticates through, plus its own preauth integrity hash (3.1.1) which
/// seeds the channel signing key. Discarded once the channel is established or the binding fails.
/// </summary>
public sealed class ChannelBindInProgress
{
    public required ISpnegoServerContext AuthContext { get; init; }

    /// <summary>Per-channel preauth hash (3.1.1 only), seeded from the connection's NEGOTIATE hash.</summary>
    public PreauthIntegrityHash? PreauthHash { get; init; }
}

/// <summary>
/// State of a TCP connection (Context §19, §3.3.1.7). One TCP connection = one
/// SMB2 connection; multiple sessions can share it. Holds the sequence/credit window,
/// the negotiated dialect/crypto parameters and (3.1.1) the preauth hash.
/// </summary>
public sealed class SmbConnection
{
    private long _treeIdCounter;

    public Guid ConnectionId { get; } = Guid.NewGuid();

    /// <summary>Remote client endpoint (<c>ip:port</c>), set by the host at accept. Used for audit
    /// logging and per-IP rate limiting (Phase 8). Null when hosted outside the TCP listener (tests).</summary>
    public string? ClientAddress { get; set; }

    /// <summary>[M10.1] True when the transport is wrapped in TLS (SMB over TLS); the whole SMB
    /// conversation runs inside a TLS tunnel underneath any SMB3 signing/encryption. Set by the host
    /// after the TLS handshake succeeds. Informational (audit/diagnostics); does not by itself relax
    /// the SMB3 encryption policy.</summary>
    public bool IsTransportSecured { get; set; }

    /// <summary>[M10.1] The validated client certificate presented during a mutual-TLS handshake, or
    /// <c>null</c> when none was presented (or the transport is not TLS). Surfaced by the host so the
    /// authorization/audit layer and a consumer's <c>IIdentityBackend</c> can use it. Only ever set
    /// after the transport has accepted the certificate per its validation callback. This is an
    /// independent copy owned by the host, which disposes it when the connection tears down — do not
    /// dispose it or retain it past the connection's lifetime.</summary>
    public System.Security.Cryptography.X509Certificates.X509Certificate2? ClientCertificate { get; set; }

    /// <summary>[M10.1] Identity the transport mapped from <see cref="ClientCertificate"/> via an
    /// <c>ITlsClientIdentityMapper</c>, or <c>null</c> when unmapped. This is a transport assertion made
    /// available to the SMB layer (audit/authorization); it does not by itself authenticate an SMB
    /// session — SPNEGO still runs — so no session key or signing decision is derived from it here.</summary>
    public SecurityIdentity? TransportAssertedIdentity { get; set; }

    /// <summary>Timestamp (UTC ticks from the server's TimeProvider) of the last frame received on this
    /// connection. Drives the idle-connection timeout (Phase 8 / M8.2).</summary>
    public long LastActivityTicks { get; set; }

    /// <summary>Timestamp (UTC ticks) at which this connection was accepted. Drives the authentication
    /// timeout — a connection with no valid session by <c>CreatedTicks + AuthenticationTimeout</c> is
    /// dropped (Phase 8 / M8.2).</summary>
    public long CreatedTicks { get; set; }

    /// <summary>Host-supplied callback that tears the transport connection down out-of-band (cancels the
    /// read loop). Set by the host; invoked by the timeout sweeper. Null when hosted outside the TCP
    /// listener (tests) — the sweep then only marks state.</summary>
    public Action? RequestClose { get; set; }

    /// <summary>Negotiated dialect (None until NEGOTIATE completes).</summary>
    public SmbDialect Dialect { get; set; } = SmbDialect.None;

    public bool NegotiateDone { get; set; }

    /// <summary>
    /// Set by the dispatcher when the protocol demands the transport connection be torn down
    /// (Context §3.3.5.15.12): e.g. a failed FSCTL_VALIDATE_NEGOTIATE_INFO signalling a downgrade
    /// attack. The host closes the connection after the current message instead of replying.
    /// </summary>
    public bool MustTerminate { get; set; }

    public byte[] ClientGuid { get; set; } = new byte[16];
    public Smb2Capabilities ClientCapabilities { get; set; }
    public Smb2Capabilities ServerCapabilities { get; set; }
    public SmbSecurityMode ClientSecurityMode { get; set; }
    public SmbSecurityMode ServerSecurityMode { get; set; }

    /// <summary>Whether this connection should be signed (Context §10).</summary>
    public bool ShouldSign { get; set; }

    public bool SupportsEncryption { get; set; }

    /// <summary>
    /// Large-MTU / multi-credit negotiated (client AND server, from 2.1, Context §7).
    /// Controls whether large READ/WRITE/TRANSACT buffers are permitted.
    /// </summary>
    public bool SupportsMultiCredit { get; set; }

    /// <summary>Maximum sizes effectively negotiated for this connection (Context §6).
    /// Capped at 64 KiB without large MTU — otherwise response frames exceed the
    /// 17-bit NBSS boundary of older clients (e.g. pysmb).</summary>
    public uint MaxReadSize { get; set; } = 0x10000;
    public uint MaxWriteSize { get; set; } = 0x10000;
    public uint MaxTransactSize { get; set; } = 0x10000;

    // Negotiated 3.1.1 parameters (Context §6.4).
    public PreauthHashAlgorithm PreauthIntegrityHashId { get; set; } = PreauthHashAlgorithm.Sha512;
    public SmbCipherId CipherId { get; set; } = SmbCipherId.None;
    public SmbSigningAlgorithmId SigningAlgorithmId { get; set; } = SmbSigningAlgorithmId.HmacSha256;

    /// <summary>
    /// Negotiated SMB2 compression algorithm (3.1.1, Phase 10 / M10.3).
    /// <see cref="SmbCompressionAlgorithm.None"/> = compression not negotiated; the host then neither
    /// compresses responses nor expects a compressed request. Set to the server's preferred algorithm
    /// (from the intersection of the client's list, the server preference and the codecs this build
    /// implements) when a COMPRESSION_CAPABILITIES context is exchanged.
    /// </summary>
    public SmbCompressionAlgorithm CompressionAlgorithm { get; set; } = SmbCompressionAlgorithm.None;

    /// <summary>Running preauth integrity hash (3.1.1 only, Context §6.4, §8.2).</summary>
    public PreauthIntegrityHash PreauthHash { get; } = new();

    /// <summary>Sessions on this connection (SessionId → session).</summary>
    public ConcurrentDictionary<ulong, SmbSession> Sessions { get; } = new();

    /// <summary>
    /// In-progress channel bindings on this connection (SessionId → transient GSS state), used only
    /// during a <c>SESSION_SETUP</c> with <c>SMB2_SESSION_FLAG_BINDING</c> until the channel is
    /// established (§3.3.5.5.2). Removed on success or failure.
    /// </summary>
    public ConcurrentDictionary<ulong, ChannelBindInProgress> PendingBindings { get; } = new();

    public DateTimeOffset CreationTime { get; } = DateTimeOffset.UtcNow;

    // --- Credit / sequence window (Context §7, §3.3.1.7) ---

    /// <summary>Lower bound of the valid MessageId window.</summary>
    public ulong SequenceWindowStart { get; set; }

    /// <summary>Size of the valid MessageId window (= granted credits).</summary>
    public ulong SequenceWindowSize { get; set; } = 1;

    public ushort OutstandingRequestCount { get; set; }

    public ulong AllocateTreeId() => (ulong)Interlocked.Increment(ref _treeIdCounter);

    private long _fileIdCounter;

    /// <summary>Allocates a new, unique (volatile) FileId for an open (Context §13).</summary>
    public ulong AllocateFileId() => (ulong)Interlocked.Increment(ref _fileIdCounter);

    // --- Asynchronous (out-of-band) responses: blocking locks, later ChangeNotify/oplocks ---

    private long _asyncIdCounter;

    /// <summary>Allocates a new, per-connection unique AsyncId (Context §4, ASYNC header).</summary>
    public ulong AllocateAsyncId() => (ulong)Interlocked.Increment(ref _asyncIdCounter);

    /// <summary>
    /// Serialized send channel set by the host for a completed (header+body, optionally signed)
    /// SMB2 response. Encryption and NBSS framing are handled by the host. Allows sending the
    /// <i>final</i> response of an asynchronously pending operation out-of-band.
    /// The <c>bool</c> argument forces encryption — needed for ASYNC responses whose header
    /// carries no TreeId and where the host would otherwise not detect the per-share requirement.
    /// </summary>
    public Func<byte[], bool, Task>? SendRawAsync { get; set; }

    /// <summary>Outstanding asynchronous operations (MessageId → entry), for CANCEL/teardown.</summary>
    public ConcurrentDictionary<ulong, PendingAsyncRequest> PendingRequests { get; } = new();

    /// <summary>Cancels all outstanding asynchronous operations (connection teardown).</summary>
    public void CancelAllPending()
    {
        foreach (PendingAsyncRequest p in PendingRequests.Values) p.Cancel();
        PendingRequests.Clear();
    }
}
