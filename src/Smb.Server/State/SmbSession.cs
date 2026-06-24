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

    /// <summary>Voller GSS-Session-Key (KDK für AES-256-Cipher-Keys, Context §8.3).</summary>
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

    public DateTimeOffset CreationTime { get; } = DateTimeOffset.UtcNow;
}
