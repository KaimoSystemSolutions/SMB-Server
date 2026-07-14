using Smb.Auth.Kerberos;

namespace Smb.Auth.Sspi;

/// <summary>
/// Convenience composition for SSPI-backed Kerberos (docs/ENTERPRISE_HARDENING_ROADMAP.md, B1). Wire the
/// result into the server with <c>SmbServerBuilder.UseAuthentication(...)</c>:
/// <code>
/// var backend = /* your IIdentityBackend for the NTLM fallback */;
/// builder.UseAuthentication(SspiKerberos.CreateNegotiator(
///     new SspiKerberosTicketValidator(),
///     new NtlmMechanismFactory(backend)));   // Kerberos preferred, NTLM fallback
/// </code>
/// </summary>
public static class SspiKerberos
{
    /// <summary>
    /// Builds a SPNEGO negotiator that offers SSPI Kerberos first, then the supplied
    /// <paramref name="fallbacks"/> (typically an <c>NtlmMechanismFactory</c>) in order.
    /// </summary>
    public static SpnegoNegotiator CreateNegotiator(IKerberosTicketValidator kerberos, params IGssMechanismFactory[] fallbacks)
    {
        ArgumentNullException.ThrowIfNull(kerberos);
        var factories = new List<IGssMechanismFactory>(1 + fallbacks.Length) { new KerberosMechanismFactory(kerberos) };
        factories.AddRange(fallbacks);
        return new SpnegoNegotiator(factories);
    }
}
