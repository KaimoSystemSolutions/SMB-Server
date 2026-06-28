using System.Collections.Concurrent;
using Smb.Auth;
using Smb.Crypto;

namespace Smb.Server.State;

/// <summary>Lifecycle state of a session (Context §8.1).</summary>
public enum SessionState
{
    InProgress,
    Valid,
    Expired,
}

/// <summary>
/// State of an authenticated (or authenticating) session
/// (Context §19, §3.3.1.8). Holds identity, derived keys and the tables for
/// tree connects/opens.
/// </summary>
public sealed class SmbSession
{
    public required ulong SessionId { get; init; }
    public required ulong SessionGlobalId { get; init; }
    public required SmbConnection Connection { get; init; }

    public SessionState State { get; set; } = SessionState.InProgress;

    /// <summary>Stateful SPNEGO context for the running auth flow.</summary>
    public ISpnegoServerContext? AuthContext { get; set; }

    public SecurityIdentity? Identity { get; set; }
    public bool IsAnonymous { get; set; }
    public bool IsGuest { get; set; }
    public bool SigningRequired { get; set; }
    public bool EncryptData { get; set; }

    /// <summary>
    /// Full GSS session key. Note (§3.1.4.2): the KDK for ALL derived keys is
    /// <see cref="SessionKey"/> truncated to 16 bytes — even for AES-256 cipher keys.
    /// This field is therefore not currently used as the KDK (see [AUDIT-2026-06] in
    /// Smb3KeyDerivation).
    /// </summary>
    public byte[] FullSessionKey { get; set; } = [];

    /// <summary>First 16 bytes of the GSS session key (KDK for signing/app/AES-128).</summary>
    public byte[] SessionKey { get; set; } = [];

    // Derived keys (3.x; for 2.x SigningKey = full GSS key, Context §8.3).
    public byte[] SigningKey { get; set; } = [];
    public byte[] EncryptionKey { get; set; } = [];
    public byte[] DecryptionKey { get; set; } = [];
    public byte[] ApplicationKey { get; set; } = [];

    /// <summary>Preauth integrity hash of the session (3.1.1; taken from the connection, Context §8.2).</summary>
    public PreauthIntegrityHash? PreauthHash { get; set; }

    public ConcurrentDictionary<ulong, SmbTreeConnect> TreeConnects { get; } = new();
    public ConcurrentDictionary<(ulong Persistent, ulong Volatile), SmbOpen> Opens { get; } = new();

    private long _encryptionNonce;

    /// <summary>
    /// [AUDIT-2026-06] Returns the next monotonically increasing AEAD nonce counter (starts at 1).
    /// MS-SMB2 §3.3.4.1.4 requires a unique, NON-random nonce value per <see cref="EncryptionKey"/>
    /// (nonce reuse breaks AES-GCM/CCM). Since the encryption key is per-session, a session-local
    /// counter suffices. See docs/SECURITY_AUDIT.md (Finding M1).
    /// </summary>
    public ulong NextEncryptionNonce() => (ulong)Interlocked.Increment(ref _encryptionNonce);

    public DateTimeOffset CreationTime { get; } = DateTimeOffset.UtcNow;
}
