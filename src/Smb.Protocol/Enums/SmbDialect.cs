namespace Smb.Protocol.Enums;

/// <summary>SMB dialect revisions (Context §6, MS-SMB2 §1.7 / §2.2.3–2.2.4).</summary>
public enum SmbDialect : ushort
{
    /// <summary>No dialect negotiated (connection initial state).</summary>
    None = 0x0000,

    /// <summary>SMB 2.0.2 — no CreditCharge, HMAC-SHA256 signing.</summary>
    Smb202 = 0x0202,

    /// <summary>SMB 2.1 — Large MTU (multi-credit), leasing.</summary>
    Smb210 = 0x0210,

    /// <summary>SMB 3.0 — AES-128-CCM encryption, AES-128-CMAC signing, secure negotiate.</summary>
    Smb300 = 0x0300,

    /// <summary>SMB 3.0.2 — like 3.0 plus minor improvements.</summary>
    Smb302 = 0x0302,

    /// <summary>SMB 3.1.1 — preauth integrity (SHA-512), negotiate contexts, AES-GCM, AES-GMAC.</summary>
    Smb311 = 0x0311,

    /// <summary>Wildcard — only in the multi-protocol negotiate response ("I speak ≥2.1").</summary>
    Wildcard2FF = 0x02FF,
}

/// <summary>Helpers for dialect-based case distinctions.</summary>
public static class SmbDialectExtensions
{
    /// <summary>True for SMB 3.x (3.0, 3.0.2, 3.1.1) — encryption/derived keys available.</summary>
    public static bool IsSmb3OrLater(this SmbDialect dialect)
        => dialect is SmbDialect.Smb300 or SmbDialect.Smb302 or SmbDialect.Smb311;

    /// <summary>True from SMB 2.1 onward — Large MTU / multi-credit / CreditCharge active.</summary>
    public static bool SupportsLargeMtu(this SmbDialect dialect)
        => dialect != SmbDialect.None && dialect != SmbDialect.Smb202;

    /// <summary>True for 3.1.1 — negotiate contexts and preauth integrity are mandatory.</summary>
    public static bool UsesNegotiateContexts(this SmbDialect dialect)
        => dialect == SmbDialect.Smb311;
}
