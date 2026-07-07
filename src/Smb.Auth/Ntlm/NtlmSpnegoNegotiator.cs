namespace Smb.Auth.Ntlm;

/// <summary>
/// Convenience SPNEGO negotiator offering NTLMv2 as the only mechanism (Context §9). Accepts both
/// SPNEGO-wrapped tokens (NegTokenInit/NegTokenResp, as Windows sends them) and raw NTLMSSP tokens
/// (simple clients).
/// <para>
/// This is a thin wrapper over the composable <see cref="SpnegoNegotiator"/> configured with a single
/// <see cref="NtlmMechanismFactory"/>. To offer additional mechanisms (Kerberos, custom
/// <see cref="IGssMechanism"/> implementations), use <see cref="SpnegoNegotiator"/> directly, e.g.:
/// <code>
/// new SpnegoNegotiator(
///     new KerberosMechanismFactory(ticketValidator),
///     new NtlmMechanismFactory(identityBackend));
/// </code>
/// </para>
/// </summary>
public sealed class NtlmSpnegoNegotiator : ISpnegoNegotiator
{
    private readonly SpnegoNegotiator _inner;

    public NtlmSpnegoNegotiator(IIdentityBackend backend, NtlmServerOptions? options = null)
        => _inner = new SpnegoNegotiator(new NtlmMechanismFactory(backend, options));

    public byte[] CreateInitialServerToken() => _inner.CreateInitialServerToken();

    public ISpnegoServerContext CreateServerContext() => _inner.CreateServerContext();
}
