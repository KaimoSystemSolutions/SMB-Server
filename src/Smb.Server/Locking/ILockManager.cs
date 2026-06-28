using Smb.Server.State;

namespace Smb.Server.Locking;

/// <summary>A normalized byte-range lock/unlock element (derived from the LOCK request).</summary>
public readonly record struct LockElement(ulong Offset, ulong Length, bool Exclusive, bool Unlock);

/// <summary>Result of a lock/unlock request (maps 1:1 to NTSTATUS in the dispatcher).</summary>
public enum LockOutcome
{
    /// <summary>All elements granted or released → <c>STATUS_SUCCESS</c>.</summary>
    Granted,
    /// <summary>Range conflicts with a lock held by another open → <c>STATUS_LOCK_NOT_GRANTED</c>.</summary>
    Conflict,
    /// <summary>Unlock of a range not currently locked → <c>STATUS_RANGE_NOT_LOCKED</c>.</summary>
    RangeNotLocked,
    /// <summary>A waiting (blocking) lock was cancelled via CANCEL/Close → <c>STATUS_CANCELLED</c>.</summary>
    Cancelled,
}

/// <summary>
/// <b>Byte-range locking seam (SMB2 LOCK, Context §15).</b> The server delegates every
/// locking decision here; the default implementation <see cref="InMemoryLockManager"/>
/// holds locks process-locally. A custom implementation can delegate locking to the OS
/// (<c>FileStream.Lock</c>) or a cluster coordinator — relevant when the same file can also
/// be locked via other protocols (NFS, local).
/// Wiring: <c>SmbServerBuilder.UseLockManager(...)</c>.
/// </summary>
public interface ILockManager
{
    /// <summary>
    /// Applies (or releases) all elements of a LOCK request <b>atomically</b> for an open
    /// (MS-SMB2 §3.3.5.14). The elements are either exclusively locks or exclusively
    /// unlocks (verified by the caller).
    /// <para>
    /// If a single lock cannot be granted immediately and <paramref name="failImmediately"/>
    /// is <c>false</c>, the returned task continues <b>asynchronously</b> until the range
    /// becomes free (→ <see cref="LockOutcome.Granted"/>) or <paramref name="ct"/> is triggered
    /// (CANCEL/Close → <see cref="LockOutcome.Cancelled"/>). When the decision is immediate,
    /// the task is already completed (synchronous fast path).
    /// </para>
    /// </summary>
    Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> elements, bool failImmediately, CancellationToken ct);

    /// <summary>
    /// Fast, never-blocking conflict check for READ/WRITE (MS-SMB2 §3.3.5.10/§3.3.5.12):
    /// is the range accessible from the perspective of <paramref name="owner"/>? <paramref name="forWrite"/>
    /// =true also checks against <i>shared</i> locks of other opens, =false only against exclusive.
    /// The owner's own locks never block its own access.
    /// </summary>
    bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool forWrite);

    /// <summary>
    /// At CLOSE, releases all locks of this open and thereby wakes any waiting locks
    /// of other opens (MS-SMB2 §3.3.5.10: close releases all locks).
    /// </summary>
    void ReleaseOwner(SmbOpen owner);
}
