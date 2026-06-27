namespace Smb.Auth.Oids;

/// <summary>Mechanism OIDs for SPNEGO <c>mechTypes</c> (Context §9.2, MS-SPNG / RFC 4178).</summary>
public static class GssOids
{
    /// <summary>SPNEGO itself (1.3.6.1.5.5.2).</summary>
    public const string Spnego = "1.3.6.1.5.5.2";

    /// <summary>Kerberos V5 (GSS) — 1.2.840.113554.1.2.2.</summary>
    public const string KerberosV5 = "1.2.840.113554.1.2.2";

    /// <summary>Kerberos (MS-Legacy) — 1.2.840.48018.1.2.2.</summary>
    public const string KerberosLegacy = "1.2.840.48018.1.2.2";

    /// <summary>NTLM (NTLMSSP) — 1.3.6.1.4.1.311.2.2.10.</summary>
    public const string Ntlm = "1.3.6.1.4.1.311.2.2.10";
}
