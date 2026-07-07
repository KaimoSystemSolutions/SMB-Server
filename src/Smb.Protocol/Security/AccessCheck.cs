namespace Smb.Protocol.Security;

/// <summary>
/// Evaluates a discretionary ACL against a caller's SIDs (MS-DTYP §2.5.3.2, the access-check
/// algorithm). Pure and side-effect free.
/// <list type="bullet">
/// <item><b>No DACL present</b> (<see cref="SecurityDescriptorControl.DaclPresent"/> clear) — the object
/// is unprotected → all access granted.</item>
/// <item><b>NULL DACL</b> (present flag set, <see cref="SecurityDescriptor.Dacl"/> null) → all access
/// granted (explicit "everyone, everything").</item>
/// <item><b>Present DACL</b> — ACEs are processed in order; the first ACE that mentions a requested bit
/// decides it (an <c>ACCESS_DENIED</c> ACE removes the bit, an <c>ACCESS_ALLOWED</c> ACE grants it), so a
/// deny ordered before an allow wins.</item>
/// </list>
/// </summary>
public static class AccessCheck
{
    private const uint AllAccess = 0xFFFFFFFF;

    /// <summary>
    /// Returns the maximal access mask the descriptor grants to <paramref name="callerSids"/> (the
    /// effective rights, as used for <c>MAXIMUM_ALLOWED</c> and to cap an open's granted access).
    /// </summary>
    public static uint MaximalAccess(SecurityDescriptor descriptor, IReadOnlyCollection<Sid> callerSids)
    {
        // Unprotected or NULL DACL → full access.
        if (!descriptor.Control.HasFlag(SecurityDescriptorControl.DaclPresent) || descriptor.Dacl is null)
            return AllAccess;

        uint granted = 0;
        uint decided = 0; // bits already settled by an earlier (allow or deny) ACE
        foreach (Ace ace in descriptor.Dacl.Aces)
        {
            if (ace.Sid is null || !Contains(callerSids, ace.Sid)) continue;

            uint fresh = ace.AccessMask & ~decided; // only bits not yet decided
            if (fresh == 0) continue;

            if (ace.Type == AceType.AccessAllowed)
                granted |= fresh;
            // AccessDenied: leave those bits ungranted.
            if (ace.Type is AceType.AccessAllowed or AceType.AccessDenied)
                decided |= ace.AccessMask;
        }
        return granted;
    }

    /// <summary>
    /// True if the descriptor grants <b>every</b> bit of <paramref name="desiredAccess"/> to the caller.
    /// <paramref name="grantedAccess"/> receives the effective granted mask (with
    /// <c>MAXIMUM_ALLOWED</c> resolved to the maximal access).
    /// </summary>
    public static bool IsGranted(
        SecurityDescriptor descriptor, IReadOnlyCollection<Sid> callerSids, uint desiredAccess, out uint grantedAccess)
    {
        uint maximal = MaximalAccess(descriptor, callerSids);

        if ((desiredAccess & AccessMask.MaximumAllowed) != 0)
        {
            grantedAccess = maximal;                 // MAXIMUM_ALLOWED → grant everything available
            return maximal != 0;
        }

        grantedAccess = desiredAccess & maximal;
        return grantedAccess == desiredAccess;
    }

    private static bool Contains(IReadOnlyCollection<Sid> sids, Sid target)
    {
        foreach (Sid s in sids)
            if (s.Equals(target)) return true;
        return false;
    }
}
