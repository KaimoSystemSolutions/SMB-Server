namespace Smb.Auth.Ntlm;

/// <summary>
/// <see cref="IGssMechanismFactory"/> for NTLMv2. Register it with the composite
/// <see cref="SpnegoNegotiator"/> to offer NTLM as an SPNEGO mechanism (typically as the fallback
/// after Kerberos). Each session gets its own <see cref="NtlmServerMechanism"/> instance.
/// </summary>
public sealed class NtlmMechanismFactory : IGssMechanismFactory
{
    private readonly IIdentityBackend _backend;
    private readonly NtlmServerOptions _options;

    public NtlmMechanismFactory(IIdentityBackend backend, NtlmServerOptions? options = null)
    {
        _backend = backend ?? throw new ArgumentNullException(nameof(backend));
        _options = options ?? new NtlmServerOptions();
    }

    public string MechOid => Oids.GssOids.Ntlm;

    public IGssMechanism Create() => new NtlmServerMechanism(_backend, _options);
}
