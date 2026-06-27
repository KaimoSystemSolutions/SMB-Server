namespace Smb.Auth;

/// <summary>
/// Authenticated identity after a successful auth flow (Context §9.1). Source for access checks
/// (SID/groups) and display (Domain\User).
/// </summary>
public sealed class SecurityIdentity
{
    public required string DomainName { get; init; }
    public required string UserName { get; init; }

    /// <summary>String form of the primary user SID (e.g. S-1-5-21-…). Optional in phase 1.</summary>
    public string? UserSid { get; init; }

    /// <summary>Group SIDs (for ACL evaluation). Optional in phase 1.</summary>
    public IReadOnlyList<string> GroupSids { get; init; } = [];

    /// <summary>True for the anonymous (NULL) session (Context §8.4).</summary>
    public bool IsAnonymous { get; init; }

    /// <summary>True for guest access (Context §8.4) — rejected by default.</summary>
    public bool IsGuest { get; init; }

    public override string ToString() =>
        IsAnonymous ? "<anonymous>" : $"{DomainName}\\{UserName}";
}
