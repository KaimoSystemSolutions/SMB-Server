using Smb.Auth.Oids;
using Smb.Protocol.Enums;

namespace Smb.Auth.Ntlm;

/// <summary>
/// Produktiver SPNEGO-Negotiator mit NTLMv2 als einzigem Mechanismus (Context §9). Akzeptiert
/// sowohl SPNEGO-verpackte Tokens (NegTokenInit/NegTokenResp, wie Windows sie sendet) als auch
/// rohe NTLMSSP-Tokens (einfache Clients). Spätere Mechanismen (Kerberos) werden additiv als
/// weitere <see cref="IGssMechanism"/> ergänzt, ohne die SMB-Schicht zu ändern.
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
            // Modus bestimmen: rohes NTLMSSP oder SPNEGO?
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
