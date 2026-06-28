using Smb.Protocol.Enums;
using Smb.Server.State;

namespace Smb.Server.Oplocks;

/// <summary>
/// A pending oplock break: the <see cref="Holder"/> currently holds an oplock that must be
/// downgraded to <see cref="NewLevel"/> due to a new, conflicting access. The dispatcher
/// then sends an OPLOCK_BREAK notification to the holder.
/// </summary>
public readonly record struct OplockBreak(SmbOpen Holder, OplockLevel NewLevel);

/// <summary>
/// Result of an oplock request at CREATE: the actually granted level plus the breaks
/// triggered by this open against <i>other</i> holders.
/// </summary>
public readonly record struct OplockGrant(OplockLevel GrantedLevel, IReadOnlyList<OplockBreak> Breaks)
{
    public static readonly OplockGrant None = new(OplockLevel.None, Array.Empty<OplockBreak>());
}

/// <summary>
/// <b>Oplock seam (SMB2, Context §15, MS-SMB2 §3.3.5.9/§3.3.4.6).</b> The server delegates
/// every oplock decision here; the default implementation
/// <see cref="InMemoryOplockManager"/> manages granted oplocks process-locally per file.
/// <para>
/// The interface is <b>pure state</b> (Parse↔State↔Effect, Context §2): it <i>decides</i>
/// which breaks are pending but does not send them — the dispatcher handles that out-of-band
/// via <see cref="SmbConnection.SendRawAsync"/>. This keeps the oplock policy free of I/O
/// and testable; a custom implementation can delegate to a cluster coordinator, for example.
/// </para>
/// Wiring: <c>SmbServerOptions.OplockManager</c>.
/// </summary>
public interface IOplockManager
{
    /// <summary>
    /// Registers a new open and grants — depending on already open handles for the same file —
    /// the appropriate oplock level (MS-SMB2 §3.3.5.9). If the request conflicts with existing
    /// oplocks of other opens, <see cref="OplockGrant.Breaks"/> contains the pending downgrades;
    /// their holders are notified by the dispatcher.
    /// </summary>
    OplockGrant RequestOplock(SmbOpen open, OplockLevel requested);

    /// <summary>
    /// Processes an OPLOCK_BREAK acknowledgment from a client (§3.3.5.22.1): the holder
    /// confirms the downgrade of its oplock to <paramref name="newLevel"/>. Returns the now
    /// active level (typically <paramref name="newLevel"/>) for the response.
    /// </summary>
    OplockLevel Acknowledge(SmbOpen open, OplockLevel newLevel);

    /// <summary>At CLOSE, releases the oplock of this open (MS-SMB2 §3.3.5.10).</summary>
    void ReleaseOwner(SmbOpen open);
}

/// <summary>
/// <see cref="IOplockManager"/> that never grants an oplock — CREATE always returns
/// <see cref="OplockLevel.None"/>. Use this to disable oplocks entirely
/// (wiring: <c>SmbServerOptions.OplockManager = new NullOplockManager()</c>).
/// </summary>
public sealed class NullOplockManager : IOplockManager
{
    public OplockGrant RequestOplock(SmbOpen open, OplockLevel requested) => OplockGrant.None;
    public OplockLevel Acknowledge(SmbOpen open, OplockLevel newLevel) => OplockLevel.None;
    public void ReleaseOwner(SmbOpen open) { }
}
