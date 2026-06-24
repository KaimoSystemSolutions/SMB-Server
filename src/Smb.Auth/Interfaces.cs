namespace Smb.Auth;

/// <summary>
/// Ein einzelner GSS-Auth-Mechanismus (NTLM, Kerberos, …), Context §9.1. Verarbeitet
/// eingehende Mech-Tokens und liefert ggf. Antwort-Tokens, bis <see cref="GssResult.Status"/>
/// Success oder einen Fehler meldet. Eine Instanz bedient genau einen Auth-Vorgang
/// (eine Session) und hält dessen Zustand.
/// </summary>
public interface IGssMechanism
{
    /// <summary>OID des Mechanismus (z.B. NTLM 1.3.6.1.4.1.311.2.2.10), Context §9.2.</summary>
    string MechOid { get; }

    /// <summary>True, sobald der Mechanismus abgeschlossen ist (Erfolg oder endgültiger Fehler).</summary>
    bool IsComplete { get; }

    /// <summary>Verarbeitet ein eingehendes Mech-Token und liefert das nächste Ergebnis.</summary>
    GssResult Accept(ReadOnlySpan<byte> inToken);
}

/// <summary>
/// Fabrik für mechanismus-spezifische Auth-Vorgänge. Pro Session wird genau eine
/// <see cref="IGssMechanism"/>-Instanz erzeugt.
/// </summary>
public interface IGssMechanismFactory
{
    string MechOid { get; }
    IGssMechanism Create();
}

/// <summary>
/// SPNEGO-Wrapper (Context §9.1): wählt den Mechanismus, kapselt NegTokenInit2/NegTokenResp.
/// Der SESSION_SETUP-Code spricht ausschließlich mit dieser Schnittstelle.
/// </summary>
public interface ISpnegoNegotiator
{
    /// <summary>Erzeugt das initiale Server-Token (NegTokenInit2) für die NEGOTIATE-Response.</summary>
    byte[] CreateInitialServerToken();

    /// <summary>Erzeugt einen neuen, zustandsbehafteten SPNEGO-Kontext für eine Session.</summary>
    ISpnegoServerContext CreateServerContext();
}

/// <summary>Zustandsbehafteter SPNEGO-Server-Kontext für genau eine Session.</summary>
public interface ISpnegoServerContext
{
    /// <summary>Verarbeitet ein eingehendes SPNEGO-Token (aus dem SESSION_SETUP-Security-Buffer).</summary>
    GssResult Accept(ReadOnlySpan<byte> spnegoToken);
}

/// <summary>
/// Backend zur Verifikation/Identitätsauflösung (Context §9.1). <b>Hier</b> docken später
/// LDAP/AD an — NTLM und Kerberos teilen sich dieselbe Identitätsquelle.
/// </summary>
public interface IIdentityBackend
{
    /// <summary>Liefert den NT-Hash (MD4 des UTF-16LE-Passworts) für lokale NTLM-Verifikation.</summary>
    bool TryGetNtHash(string domain, string user, out byte[] ntHash);

    /// <summary>Löst Domain\User zu einer vollständigen Identität (SID + Gruppen) auf.</summary>
    SecurityIdentity Resolve(string domain, string user);
}
