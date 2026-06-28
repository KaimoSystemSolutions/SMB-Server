using Smb.FileSystem;

namespace Smb.Server.State;

/// <summary>State of a TREE_CONNECT (Context §19, §3.3.1.9).</summary>
public sealed class SmbTreeConnect
{
    public required ulong TreeId { get; init; }
    public required SmbSession Session { get; init; }
    public required IShare Share { get; init; }

    /// <summary>Effective rights of the user on the share (MaximalAccess, Context §12).</summary>
    public uint MaximalAccess { get; set; }

    /// <summary>
    /// Enforces encryption for all messages of this tree (SMB2_SHAREFLAG_ENCRYPT_DATA,
    /// MS-SMB2 §3.3.1.9 / Context §11). Set at TREE_CONNECT when the share requires
    /// encryption and the connection has negotiated 3.x encryption.
    /// </summary>
    public bool EncryptData { get; set; }

    public int OpenCount;
    public DateTimeOffset CreationTime { get; } = DateTimeOffset.UtcNow;
}
