using System.Collections.Concurrent;
using Smb.Auth;
using Smb.Crypto;

namespace Smb.Server.State;

/// <summary>Lebenszyklus-Zustand einer Session (Context §8.1).</summary>
public enum SessionState
{
    InProgress,
    Valid,
    Expired,
}

/// <summary>
/// Zustand einer authentifizierten (oder in Authentifizierung befindlichen) Session
/// (Context §19, §3.3.1.8). Hält Identität, abgeleitete Keys und die Tabellen für
/// TreeConnects/Opens.
/// </summary>
public sealed class SmbSession
{
    public required ulong SessionId { get; init; }
    public required ulong SessionGlobalId { get; init; }
    public required SmbConnection Connection { get; init; }

    public SessionState State { get; set; } = SessionState.InProgress;

    /// <summary>Zustandsbehafteter SPNEGO-Kontext für den laufenden Auth-Flow.</summary>
    public ISpnegoServerContext? AuthContext { get; set; }

    public SecurityIdentity? Identity { get; set; }
    public bool IsAnonymous { get; set; }
    public bool IsGuest { get; set; }
    public bool SigningRequired { get; set; }
    public bool EncryptData { get; set; }

    /// <summary>
    /// Voller GSS-Session-Key. Hinweis (§3.1.4.2): KDK für ALLE abgeleiteten Schlüssel ist die auf
    /// 16 Byte gekürzte <see cref="SessionKey"/> — auch für AES-256-Cipher-Keys. Dieses Feld wird
    /// daher aktuell nicht als KDK verwendet (siehe [AUDIT-2026-06] in Smb3KeyDerivation).
    /// </summary>
    public byte[] FullSessionKey { get; set; } = [];

    /// <summary>Erste 16 Byte des GSS-Session-Keys (KDK für Signing/App/AES-128).</summary>
    public byte[] SessionKey { get; set; } = [];

    // Abgeleitete Keys (3.x; bei 2.x ist SigningKey = voller GSS-Key, Context §8.3).
    public byte[] SigningKey { get; set; } = [];
    public byte[] EncryptionKey { get; set; } = [];
    public byte[] DecryptionKey { get; set; } = [];
    public byte[] ApplicationKey { get; set; } = [];

    /// <summary>Preauth-Integrity-Hash der Session (3.1.1; von der Connection übernommen, Context §8.2).</summary>
    public PreauthIntegrityHash? PreauthHash { get; set; }

    public ConcurrentDictionary<ulong, SmbTreeConnect> TreeConnects { get; } = new();
    public ConcurrentDictionary<(ulong Persistent, ulong Volatile), SmbOpen> Opens { get; } = new();

    private long _encryptionNonce;

    /// <summary>
    /// [AUDIT-2026-06] Liefert den nächsten monoton steigenden AEAD-Nonce-Zähler (beginnt bei 1).
    /// MS-SMB2 §3.3.4.1.4 verlangt einen je <see cref="EncryptionKey"/> eindeutigen, NICHT zufälligen
    /// Nonce-Wert (Nonce-Wiederverwendung bricht AES-GCM/CCM). Da der EncryptionKey pro Session gilt,
    /// genügt ein Session-lokaler Zähler. Siehe docs/SECURITY_AUDIT.md (Finding M1).
    /// </summary>
    public ulong NextEncryptionNonce() => (ulong)Interlocked.Increment(ref _encryptionNonce);

    public DateTimeOffset CreationTime { get; } = DateTimeOffset.UtcNow;
}
