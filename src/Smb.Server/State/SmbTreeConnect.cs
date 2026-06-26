using Smb.FileSystem;

namespace Smb.Server.State;

/// <summary>Zustand eines TREE_CONNECT (Context §19, §3.3.1.9).</summary>
public sealed class SmbTreeConnect
{
    public required ulong TreeId { get; init; }
    public required SmbSession Session { get; init; }
    public required IShare Share { get; init; }

    /// <summary>Effektive Rechte des Users auf dem Share (MaximalAccess, Context §12).</summary>
    public uint MaximalAccess { get; set; }

    /// <summary>
    /// Erzwingt Verschlüsselung für alle Nachrichten dieses Tree (SMB2_SHAREFLAG_ENCRYPT_DATA,
    /// MS-SMB2 §3.3.1.9 / Context §11). Wird beim TREE_CONNECT gesetzt, wenn der Share
    /// Verschlüsselung verlangt und die Connection 3.x-Encryption ausgehandelt hat.
    /// </summary>
    public bool EncryptData { get; set; }

    public int OpenCount;
    public DateTimeOffset CreationTime { get; } = DateTimeOffset.UtcNow;
}
