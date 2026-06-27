using Smb.Auth.Oids;
using Smb.Protocol.Enums;

namespace Smb.Auth.Ntlm;

/// <summary>
/// Production SPNEGO negotiator with NTLMv2 as the only mechanism (Context §9). Accepts both
/// SPNEGO-wrapped tokens (NegTokenInit/NegTokenResp, as Windows sends them) and raw NTLMSSP tokens
/// (simple clients). Later mechanisms (Kerberos) are added additively as further
/// <see cref="IGssMechanism"/> implementations, without changing the SMB layer.
/// </summary>
public sealed class NtlmSpnegoNegotiator : ISpnegoNegotiator
{
    private readonly IIdentityBackend _backend;
    private readonly NtlmServerOptions _options;

    public NtlmSpnegoNegotiator(IIdentityBackend backend, NtlmServerOptions? options = null)
    {
        _backend = backend;
        _options = options ?? new NtlmServerOptions();
    }

    public byte[] CreateInitialServerToken()
        => SpnegoTokens.CreateNegTokenInit2([GssOids.Ntlm]);

    public ISpnegoServerContext CreateServerContext()
        => new Context(new NtlmServerMechanism(_backend, _options));

    private sealed class Context : ISpnegoServerContext
    {
        private readonly NtlmServerMechanism _mech;
        private bool _rawMode;
        private bool _modeKnown;

        public Context(NtlmServerMechanism mech) => _mech = mech;

        public GssResult Accept(ReadOnlySpan<byte> token)
        {
            // Determine mode: raw NTLMSSP or SPNEGO?
            byte[] mechToken;
            if (!_modeKnown)
            {
                _rawMode = NtlmConstants.IsNtlmSsp(token);
                _modeKnown = true;
            }

            if (_rawMode)
            {
                mechToken = token.ToArray();
            }
            else
            {
                SpnegoParseResult parsed;
                try { parsed = SpnegoTokens.Parse(token); }
                catch (Exception) { return GssResult.Failed(NtStatus.InvalidParameter); }
                mechToken = parsed.MechToken ?? [];
            }

            GssResult inner = _mech.Accept(mechToken);
            return _rawMode ? inner : WrapSpnego(inner);
        }

        private static GssResult WrapSpnego(GssResult inner)
        {
            if (inner.NeedsMoreProcessing)
            {
                byte[] wrapped = SpnegoTokens.CreateNegTokenResp(
                    SpnegoTokens.NegStateAcceptIncomplete, GssOids.Ntlm, inner.OutToken);
                return GssResult.Continue(wrapped);
            }

            if (inner.IsSuccess)
            {
                byte[] wrapped = SpnegoTokens.CreateNegTokenResp(
                    SpnegoTokens.NegStateAcceptCompleted, responseToken: inner.OutToken);
                return GssResult.Succeeded(inner.SessionKey!, inner.Identity!, wrapped);
            }

            byte[] reject = SpnegoTokens.CreateNegTokenResp(SpnegoTokens.NegStateReject);
            return new GssResult { Status = inner.Status, OutToken = reject };
        }
    }
}
