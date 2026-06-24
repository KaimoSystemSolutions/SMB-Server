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

    public int OpenCount;
    public DateTimeOffset CreationTime { get; } = DateTimeOffset.UtcNow;
}
