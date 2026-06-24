using System.Collections.Concurrent;
using Smb.Auth;
using Smb.Crypto;
using Smb.Protocol.Enums;

namespace Smb.Server.State;

/// <summary>
/// Zustand einer TCP-Verbindung (Context §19, §3.3.1.7). Eine TCP-Verbindung = eine
/// SMB2-Connection; mehrere Sessions können sie teilen. Hält das Sequenz-/Credit-Fenster,
/// die ausgehandelten Dialekt-/Krypto-Parameter und (3.1.1) den Preauth-Hash.
/// </summary>
public sealed class SmbConnection
{
    private long _treeIdCounter;

    public Guid ConnectionId { get; } = Guid.NewGuid();

    /// <summary>Ausgehandelter Dialekt (None bis NEGOTIATE abgeschlossen).</summary>
    public SmbDialect Dialect { get; set; } = SmbDialect.None;

    public bool NegotiateDone { get; set; }

    public byte[] ClientGuid { get; set; } = new byte[16];
    public Smb2Capabilities ClientCapabilities { get; set; }
    public Smb2Capabilities ServerCapabilities { get; set; }
    public SmbSecurityMode ClientSecurityMode { get; set; }
    public SmbSecurityMode ServerSecurityMode { get; set; }

    /// <summary>Soll auf dieser Connection signiert werden (Context §10).</summary>
    public bool ShouldSign { get; set; }

    public bool SupportsEncryption { get; set; }

    /// <summary>
    /// Large-MTU / Multi-Credit ausgehandelt (Client UND Server, ab 2.1, Context §7).
    /// Steuert, ob große READ/WRITE/TRANSACT-Puffer erlaubt sind.
    /// </summary>
    public bool SupportsMultiCredit { get; set; }

    /// <summary>Effektiv für diese Connection ausgehandelte Maximalgrößen (Context §6).
    /// Ohne Large-MTU auf 64 KiB gedeckelt — sonst überschreiten Antwort-Frames die
    /// 17-Bit-NBSS-Grenze älterer Clients (z.B. pysmb).</summary>
    public uint MaxReadSize { get; set; } = 0x10000;
    public uint MaxWriteSize { get; set; } = 0x10000;
    public uint MaxTransactSize { get; set; } = 0x10000;

    // Ausgehandelte 3.1.1-Parameter (Context §6.4).
    public PreauthHashAlgorithm PreauthIntegrityHashId { get; set; } = PreauthHashAlgorithm.Sha512;
    public SmbCipherId CipherId { get; set; } = SmbCipherId.None;
    public SmbSigningAlgorithmId SigningAlgorithmId { get; set; } = SmbSigningAlgorithmId.HmacSha256;

    /// <summary>Laufender Preauth-Integrity-Hash (nur 3.1.1, Context §6.4, §8.2).</summary>
    public PreauthIntegrityHash PreauthHash { get; } = new();

    /// <summary>Sessions auf dieser Connection (SessionId → Session).</summary>
    public ConcurrentDictionary<ulong, SmbSession> Sessions { get; } = new();

    public DateTimeOffset CreationTime { get; } = DateTimeOffset.UtcNow;

    // --- Credit-/Sequenzfenster (Context §7, §3.3.1.7) ---

    /// <summary>Untere Grenze des gültigen MessageId-Fensters.</summary>
    public ulong SequenceWindowStart { get; set; }

    /// <summary>Größe des gültigen MessageId-Fensters (= erteilte Credits).</summary>
    public ulong SequenceWindowSize { get; set; } = 1;

    public ushort OutstandingRequestCount { get; set; }

    public ulong AllocateTreeId() => (ulong)Interlocked.Increment(ref _treeIdCounter);

    private long _fileIdCounter;

    /// <summary>Vergibt eine neue, eindeutige (volatile) FileId für ein Open (Context §13).</summary>
    public ulong AllocateFileId() => (ulong)Interlocked.Increment(ref _fileIdCounter);

    // --- Asynchrone (out-of-band) Antworten: blockierende Locks, später ChangeNotify/Oplocks ---

    private long _asyncIdCounter;

    /// <summary>Vergibt eine neue, pro Connection eindeutige AsyncId (Context §4, ASYNC-Header).</summary>
    public ulong AllocateAsyncId() => (ulong)Interlocked.Increment(ref _asyncIdCounter);

    /// <summary>
    /// Vom Host gesetzter, serialisierter Sendekanal für eine bereits fertige (Header+Body, ggf.
    /// signierte) SMB2-Antwort. Verschlüsselung und NBSS-Rahmung übernimmt der Host. Erlaubt es,
    /// die <i>finale</i> Antwort einer asynchron ausstehenden Operation out-of-band zu senden.
    /// </summary>
    public Func<byte[], Task>? SendRawAsync { get; set; }

    /// <summary>Ausstehende asynchrone Operationen (MessageId → Eintrag), für CANCEL/Teardown.</summary>
    public ConcurrentDictionary<ulong, PendingAsyncRequest> PendingRequests { get; } = new();

    /// <summary>Bricht alle ausstehenden asynchronen Operationen ab (Connection-Teardown).</summary>
    public void CancelAllPending()
    {
        foreach (PendingAsyncRequest p in PendingRequests.Values) p.Cancel();
        PendingRequests.Clear();
    }
}
