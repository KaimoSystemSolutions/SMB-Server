using Smb.Auth;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Server.Authorization;

namespace Smb.Server;

/// <summary>
/// Server-Konfiguration mit sicheren Defaults nach Windows-Server-2025/Win11-24H2-Stand
/// (Context §20). Bewusst restriktiv: Signing erforderlich, 3.1.1 bevorzugt, Guest/Anonymous
/// abgelehnt, moderne Cipher/Signing-Präferenz.
/// </summary>
public sealed class SmbServerOptions
{
    /// <summary>Servername (für NETNAME-Context / Anzeige).</summary>
    public string ServerName { get; set; } = Environment.MachineName;

    /// <summary>Stabiler Server-GUID (16 Byte). Wird bei Bedarf zufällig erzeugt.</summary>
    public byte[] ServerGuid { get; set; } = Guid.NewGuid().ToByteArray();

    /// <summary>Höchster vom Server unterstützter Dialekt (Context §6, §20: 3.1.1 bevorzugen).</summary>
    public SmbDialect MaxDialect { get; set; } = SmbDialect.Smb311;

    /// <summary>Niedrigster akzeptierter Dialekt. SMB1-Dateizugriff bleibt aus (Context §1).</summary>
    public SmbDialect MinDialect { get; set; } = SmbDialect.Smb202;

    /// <summary>Signing erzwingen (Context §20: seit 24H2 Default).</summary>
    public bool RequireMessageSigning { get; set; } = true;

    /// <summary>Verschlüsselung global verlangen (zusätzlich per-Share möglich, Context §11).</summary>
    public bool RequireEncryption { get; set; }

    /// <summary>Gast-Zugriff ablehnen (Context §8.4, §20).</summary>
    public bool RejectGuestAccess { get; set; } = true;

    /// <summary>Anonymen (NULL-)Zugriff erlauben? Per Default aus (Context §20).</summary>
    public bool AllowAnonymousAccess { get; set; }

    /// <summary>Cipher-Präferenz (absteigend). Default: AES-128-GCM &gt; AES-256-GCM &gt; AES-128-CCM &gt; AES-256-CCM.</summary>
    public IReadOnlyList<SmbCipherId> CipherPreference { get; set; } =
    [
        SmbCipherId.Aes128Gcm, SmbCipherId.Aes256Gcm, SmbCipherId.Aes128Ccm, SmbCipherId.Aes256Ccm,
    ];

    /// <summary>Signing-Präferenz (absteigend). Default: AES-GMAC &gt; AES-CMAC &gt; HMAC-SHA256 (Context §20).</summary>
    public IReadOnlyList<SmbSigningAlgorithmId> SigningPreference { get; set; } =
    [
        SmbSigningAlgorithmId.AesGmac, SmbSigningAlgorithmId.AesCmac, SmbSigningAlgorithmId.HmacSha256,
    ];

    public uint MaxTransactSize { get; set; } = 8 * 1024 * 1024;
    public uint MaxReadSize { get; set; } = 8 * 1024 * 1024;
    public uint MaxWriteSize { get; set; } = 8 * 1024 * 1024;

    /// <summary>Maximal pro Antwort gewährte Credits (Cap, Context §7).</summary>
    public ushort MaxCreditsPerResponse { get; set; } = 512;

    /// <summary>SPNEGO-Negotiator (Auth). Pflicht — z.B. NTLM-basiert oder (Test) <see cref="DevSpnegoNegotiator"/>.</summary>
    public ISpnegoNegotiator? SpnegoNegotiator { get; set; }

    /// <summary>Bereitgestellte Shares. <c>IPC$</c> wird beim Start sichergestellt (Context §12, §23).</summary>
    public ShareCollection Shares { get; set; } = new();

    /// <summary>
    /// Autorisierungs-Hook für Share-Sichtbarkeit (Enumeration) und -Zugriff (TREE_CONNECT),
    /// Context §12. Default <see cref="AllowAllSharePolicy"/> (alle sichtbar, Vollzugriff).
    /// Eigene Policy setzen, um pro User/Gruppe zu filtern und Rechte zu begrenzen.
    /// </summary>
    public IShareAccessPolicy ShareAccessPolicy { get; set; } = new AllowAllSharePolicy();

    /// <summary>Validiert die Konfiguration und wirft bei Fehlkonfiguration.</summary>
    public void Validate()
    {
        if (ServerGuid is not { Length: 16 })
            throw new InvalidOperationException("ServerGuid muss 16 Byte sein.");
        if (MaxDialect < MinDialect)
            throw new InvalidOperationException("MaxDialect darf nicht kleiner als MinDialect sein.");
        if (SpnegoNegotiator is null)
            throw new InvalidOperationException("SpnegoNegotiator ist erforderlich (Auth-Provider).");
    }
}
