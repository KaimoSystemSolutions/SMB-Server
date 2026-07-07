using Smb.Auth.Oids;

namespace Smb.Auth.Kerberos;

/// <summary>
/// <see cref="IGssMechanismFactory"/> for Kerberos V5. Register it with the composite
/// <see cref="SpnegoNegotiator"/> — typically before <see cref="Ntlm.NtlmMechanismFactory"/> so Kerberos
/// is preferred and NTLM stays as fallback. The same <see cref="IKerberosTicketValidator"/> serves every
/// session; a fresh <see cref="KerberosServerMechanism"/> is created per session.
/// <para>
/// The advertised OID defaults to the standard krb5 mech OID; pass <see cref="GssOids.KerberosLegacy"/>
/// (or register a second factory) to also offer the Microsoft legacy Kerberos OID some clients send.
/// </para>
/// </summary>
public sealed class KerberosMechanismFactory : IGssMechanismFactory
{
    private readonly IKerberosTicketValidator _validator;
    private readonly string _mechOid;

    public KerberosMechanismFactory(IKerberosTicketValidator validator, string mechOid = GssOids.KerberosV5)
    {
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        _mechOid = mechOid;
    }

    public string MechOid => _mechOid;

    public IGssMechanism Create() => new KerberosServerMechanism(_validator, _mechOid);
}
