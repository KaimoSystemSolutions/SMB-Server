using System.Collections.Concurrent;
using Smb.Auth;
using Smb.Crypto;
using Smb.Protocol.Enums;

namespace Smb.Server.State;

/// <summary>
/// State of a TCP connection (Context §19, §3.3.1.7). One TCP connection = one
/// SMB2 connection; multiple sessions can share it. Holds the sequence/credit window,
/// the negotiated dialect/crypto parameters and (3.1.1) the preauth hash.
/// </summary>
public sealed class SmbConnection
{
    private long _treeIdCounter;

    public Guid ConnectionId { get; } = Guid.NewGuid();

    /// <summary>Negotiated dialect (None until NEGOTIATE completes).</summary>
    public SmbDialect Dialect { get; set; } = SmbDialect.None;

    public bool NegotiateDone { get; set; }

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

    /// <summary>Running preauth integrity hash (3.1.1 only, Context §6.4, §8.2).</summary>
    public PreauthIntegrityHash PreauthHash { get; } = new();

    /// <summary>Sessions on this connection (SessionId → session).</summary>
    public ConcurrentDictionary<ulong, SmbSession> Sessions { get; } = new();

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
