using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Rpc;

namespace Smb.Server.State;

/// <summary>
/// State of an open handle (Context §19, §3.3.1.10). FileId = {Persistent, Volatile}
/// (Context §13). Links session/tree connect with the backend handle.
/// </summary>
public sealed class SmbOpen
{
    public required ulong PersistentFileId { get; init; }
    public required ulong VolatileFileId { get; init; }
    public required SmbSession Session { get; init; }
    public required SmbTreeConnect TreeConnect { get; init; }

    /// <summary>Backend handle (<c>Open.LocalOpen</c>).</summary>
    public IFileHandle? LocalOpen { get; set; }

    public uint GrantedAccess { get; set; }
    public SmbFileAttributes FileAttributes { get; set; }
    public string PathName { get; set; } = string.Empty;
    public bool DeleteOnClose { get; set; }

    /// <summary>
    /// Oplock level currently granted for this open (Context §15). Set at CREATE and
    /// downgraded on a break. The <c>IOplockManager</c> is authoritative; this value mirrors
    /// the last level granted to this open (for tests/diagnostics).
    /// </summary>
    public OplockLevel OplockLevel { get; set; } = OplockLevel.None;

    /// <summary>
    /// Lease key of this open (SMB 2.1+, Context §15). Zero (default) when the open holds no lease.
    /// Opens sharing the same key share one lease in the <c>ILeaseManager</c>; set at CREATE from the
    /// lease CREATE context.
    /// </summary>
    public LeaseKey LeaseKey { get; set; }

    /// <summary>
    /// Lease caching state currently granted for this open's lease (Context §15). The
    /// <c>ILeaseManager</c> is authoritative; this value mirrors the last granted state (for
    /// tests/diagnostics), analogous to <see cref="OplockLevel"/>.
    /// </summary>
    public LeaseState LeaseState { get; set; } = LeaseState.None;

    /// <summary>Lease epoch last granted to this open (lease V2; used to order state changes).</summary>
    public ushort LeaseEpoch { get; set; }

    /// <summary>Parent directory lease key (lease V2 / directory leasing). Zero when unused.</summary>
    public LeaseKey ParentLeaseKey { get; set; }

    /// <summary>
    /// Snapshot of the directory listing taken at the start of a QUERY_DIRECTORY scan (Context §14).
    /// Served in pages across multiple QUERY_DIRECTORY calls; reset on SL_RESTART_SCAN. <c>null</c>
    /// until the first query (O2).
    /// </summary>
    public IReadOnlyList<FileEntryInfo>? DirectoryListing { get; set; }

    /// <summary>Index of the next entry to return from <see cref="DirectoryListing"/> (paging cursor).</summary>
    public int DirectoryCursor { get; set; }

    /// <summary>Share-mode reservation key (share + path) for release at CLOSE/teardown (O5). Null = none.</summary>
    public string? ShareModeKey { get; set; }

    /// <summary>For named-pipe opens (IPC$, e.g. \PIPE\srvsvc): the DCERPC pipe state. Otherwise null.</summary>
    public RpcPipe? Pipe { get; set; }

    /// <summary>True if this is a named-pipe open (DCERPC).</summary>
    public bool IsPipe => Pipe is not null;

    public (ulong Persistent, ulong Volatile) Key => (PersistentFileId, VolatileFileId);
}
