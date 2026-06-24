using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Server.Rpc;

namespace Smb.Server.State;

/// <summary>
/// Zustand eines offenen Handles (Context §19, §3.3.1.10). FileId = {Persistent, Volatile}
/// (Context §13). Verknüpft Session/TreeConnect mit dem Backend-Handle.
/// </summary>
public sealed class SmbOpen
{
    public required ulong PersistentFileId { get; init; }
    public required ulong VolatileFileId { get; init; }
    public required SmbSession Session { get; init; }
    public required SmbTreeConnect TreeConnect { get; init; }

    /// <summary>Backend-Handle (<c>Open.LocalOpen</c>).</summary>
    public IFileHandle? LocalOpen { get; set; }

    public uint GrantedAccess { get; set; }
    public SmbFileAttributes FileAttributes { get; set; }
    public string PathName { get; set; } = string.Empty;
    public bool DeleteOnClose { get; set; }

    /// <summary>Wurde dieses (Verzeichnis-)Open bereits via QUERY_DIRECTORY aufgelistet? (Context §14)</summary>
    public bool DirectoryEnumStarted { get; set; }

    /// <summary>Bei Named-Pipe-Opens (IPC$, z.B. \PIPE\srvsvc): der DCERPC-Pipe-Zustand. Sonst null.</summary>
    public RpcPipe? Pipe { get; set; }

    /// <summary>True, wenn dies ein Named-Pipe-Open (DCERPC) ist.</summary>
    public bool IsPipe => Pipe is not null;

    public (ulong Persistent, ulong Volatile) Key => (PersistentFileId, VolatileFileId);
}
