using Smb.FileSystem;

namespace Smb.Server.Sharing;

/// <summary>Requested file-sharing mode (CREATE ShareAccess, MS-SMB2 §2.2.13).</summary>
[Flags]
public enum FileShareMode
{
    None = 0,
    Read = 1,    // FILE_SHARE_READ
    Write = 2,   // FILE_SHARE_WRITE
    Delete = 4,  // FILE_SHARE_DELETE
}

/// <summary>
/// <b>Share-mode / sharing-violation seam (SMB2 CREATE ShareAccess, MS-SMB2 §3.3.5.9).</b>
/// On every file CREATE the server asks whether a new open with a given desired access and share
/// mode is compatible with the opens already held on the same file; an incompatibility →
/// <c>STATUS_SHARING_VIOLATION</c>. Without this, two clients could both open a file with
/// "exclusive" intent and silently corrupt each other's data (O5).
/// <para>
/// The default <see cref="InMemoryShareModeManager"/> enforces this process-locally and
/// <b>portably</b> — unlike OS <c>FileShare</c>, which Unix/ZFS (TrueNAS) does not enforce. A custom
/// implementation can delegate to a cluster coordinator for cross-node or cross-protocol (SMB+NFS)
/// sharing. Wiring: <c>SmbServerBuilder.UseShareModeManager(...)</c>.
/// </para>
/// </summary>
public interface IShareModeManager
{
    /// <summary>
    /// Registers an open on <paramref name="fileKey"/> if its <paramref name="access"/> /
    /// <paramref name="share"/> combination is compatible with all opens already held on the same
    /// file. Returns <c>false</c> (and registers nothing) on a sharing violation.
    /// <paramref name="owner"/> identifies the open (by reference) for the matching <see cref="Close"/>.
    /// </summary>
    bool TryOpen(string fileKey, object owner, FileAccessIntent access, FileShareMode share);

    /// <summary>Releases the open's share-mode reservation (CLOSE / connection teardown).</summary>
    void Close(string fileKey, object owner);
}
