namespace Smb.Auth;

/// <summary>
/// Authentifizierte Identität nach erfolgreichem Auth-Flow (Context §9.1). Quelle für
/// Access-Checks (SID/Gruppen) und Anzeige (Domain\User).
/// </summary>
public sealed class SecurityIdentity
{
    public required string DomainName { get; init; }
    public required string UserName { get; init; }

    /// <summary>String-Form der primären User-SID (z.B. S-1-5-21-…). Optional in Phase 1.</summary>
    public string? UserSid { get; init; }

    /// <summary>Gruppen-SIDs (für ACL-Auswertung). Optional in Phase 1.</summary>
    public IReadOnlyList<string> GroupSids { get; init; } = [];

    /// <summary>True für die anonyme (NULL-)Session (Context §8.4).</summary>
    public bool IsAnonymous { get; init; }

    /// <summary>True für Gast-Zugriff (Context §8.4) — per Default abzulehnen.</summary>
    public bool IsGuest { get; init; }

    public override string ToString() =>
        IsAnonymous ? "<anonymous>" : $"{DomainName}\\{UserName}";
}
