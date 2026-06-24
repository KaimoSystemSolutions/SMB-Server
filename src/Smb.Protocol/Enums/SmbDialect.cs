namespace Smb.Protocol.Enums;

/// <summary>SMB-Dialekt-Revisionen (Context §6, MS-SMB2 §1.7 / §2.2.3–2.2.4).</summary>
public enum SmbDialect : ushort
{
    /// <summary>Kein Dialekt ausgehandelt (Connection-Initialzustand).</summary>
    None = 0x0000,

    /// <summary>SMB 2.0.2 — keine CreditCharge, HMAC-SHA256-Signing.</summary>
    Smb202 = 0x0202,

    /// <summary>SMB 2.1 — Large MTU (Multi-Credit), Leasing.</summary>
    Smb210 = 0x0210,

    /// <summary>SMB 3.0 — AES-128-CCM Encryption, AES-128-CMAC Signing, Secure Negotiate.</summary>
    Smb300 = 0x0300,

    /// <summary>SMB 3.0.2 — wie 3.0 plus kleinere Verbesserungen.</summary>
    Smb302 = 0x0302,

    /// <summary>SMB 3.1.1 — Preauth-Integrity (SHA-512), Negotiate Contexts, AES-GCM, AES-GMAC.</summary>
    Smb311 = 0x0311,

    /// <summary>Wildcard — nur in der Multi-Protocol-Negotiate-Antwort ("spreche ≥2.1").</summary>
    Wildcard2FF = 0x02FF,
}

/// <summary>Hilfsfunktionen für Dialekt-bezogene Fallunterscheidungen.</summary>
public static class SmbDialectExtensions
{
    /// <summary>True für SMB 3.x (3.0, 3.0.2, 3.1.1) — Encryption/abgeleitete Keys verfügbar.</summary>
    public static bool IsSmb3OrLater(this SmbDialect dialect)
        => dialect is SmbDialect.Smb300 or SmbDialect.Smb302 or SmbDialect.Smb311;

    /// <summary>True ab SMB 2.1 — Large MTU / Multi-Credit / CreditCharge aktiv.</summary>
    public static bool SupportsLargeMtu(this SmbDialect dialect)
        => dialect != SmbDialect.None && dialect != SmbDialect.Smb202;

    /// <summary>True für 3.1.1 — Negotiate Contexts und Preauth-Integrity sind Pflicht.</summary>
    public static bool UsesNegotiateContexts(this SmbDialect dialect)
        => dialect == SmbDialect.Smb311;
}
