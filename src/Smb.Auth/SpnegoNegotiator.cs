using Smb.Auth.Ntlm;
using Smb.Auth.Oids;
using Smb.Protocol.Enums;

namespace Smb.Auth;

/// <summary>
/// Composable SPNEGO negotiator (Context §9, RFC 4178 / MS-SPNG). It is built from an ordered list of
/// <see cref="IGssMechanismFactory"/> — the server's mechanism preference, most preferred first. The
/// negotiator advertises every mechanism's OID in the initial NegTokenInit2 and, per session, selects
/// the mechanism the client actually uses, wrapping/unwrapping the SPNEGO envelope around it. The SMB
/// layer only ever talks to <see cref="ISpnegoNegotiator"/>, so authentication mechanisms are fully
/// pluggable:
/// <code>
/// options.SpnegoNegotiator = new SpnegoNegotiator(
///     new KerberosMechanismFactory(myTicketValidator),   // preferred
///     new NtlmMechanismFactory(myIdentityBackend));      // fallback
/// </code>
/// A library user can register any number of mechanisms — including their own <see cref="IGssMechanism"/>
/// implementations — without touching the protocol layer.
/// <para>
/// Selection follows SPNEGO's optimistic model: if the mechanism the client put first (and for which it
/// sent an optimistic <c>mechToken</c>) is supported, it is used immediately; otherwise the first
/// mutually-supported mechanism from the client's list is selected and the client is asked to resend a
/// token for it (<c>supportedMech</c> + accept-incomplete). Raw NTLMSSP tokens (clients that skip the
/// SPNEGO wrapper) are detected and routed to the NTLM mechanism unwrapped, exactly as before.
/// </para>
/// <para>
/// The SPNEGO <c>mechListMIC</c> is parsed but not enforced (downgrade protection is a per-mechanism
/// concern — see the NTLM MIC hardening item O1). This matches the prior single-mechanism behavior.
/// </para>
/// </summary>
public sealed class SpnegoNegotiator : ISpnegoNegotiator
{
    private readonly IReadOnlyList<IGssMechanismFactory> _factories;

    public SpnegoNegotiator(params IGssMechanismFactory[] factories)
        : this((IReadOnlyList<IGssMechanismFactory>)factories) { }

    public SpnegoNegotiator(IReadOnlyList<IGssMechanismFactory> factories)
    {
        if (factories is null || factories.Count == 0)
            throw new ArgumentException("At least one GSS mechanism factory is required.", nameof(factories));
        _factories = factories;
    }

    /// <summary>Advertises all registered mechanisms in server-preference order (Context §9.2).</summary>
    public byte[] CreateInitialServerToken()
    {
        var oids = new List<string>(_factories.Count);
        foreach (IGssMechanismFactory f in _factories)
            if (!oids.Contains(f.MechOid)) oids.Add(f.MechOid);
        return SpnegoTokens.CreateNegTokenInit2(oids);
    }

    public ISpnegoServerContext CreateServerContext() => new Context(_factories);

    private sealed class Context : ISpnegoServerContext
    {
        private readonly IReadOnlyList<IGssMechanismFactory> _factories;
        private IGssMechanism? _mech;
        private bool _raw;                // raw NTLMSSP: no SPNEGO wrapping on responses
        private bool _supportedMechEmitted;
        private string? _selectedOid;

        public Context(IReadOnlyList<IGssMechanismFactory> factories) => _factories = factories;

        public GssResult Accept(ReadOnlySpan<byte> token)
        {
            // Raw NTLMSSP (no SPNEGO envelope): route straight to the NTLM mechanism, unwrapped.
            if (_mech is null && NtlmConstants.IsNtlmSsp(token))
            {
                IGssMechanismFactory? ntlm = Find(GssOids.Ntlm);
                if (ntlm is null) return GssResult.Failed(NtStatus.InvalidParameter);
                _mech = ntlm.Create();
                _selectedOid = ntlm.MechOid;
                _raw = true;
                return _mech.Accept(token);
            }
            if (_raw && _mech is not null)
                return _mech.Accept(token);

            SpnegoParseResult parsed;
            try { parsed = SpnegoTokens.Parse(token); }
            catch (Exception) { return GssResult.Failed(NtStatus.InvalidParameter); }

            if (_mech is null)
                return SelectAndAccept(parsed);

            // Follow-up NegTokenResp for the already-selected mechanism.
            return Wrap(_mech.Accept(parsed.MechToken ?? []));
        }

        /// <summary>Picks a mechanism from the client's NegTokenInit and runs the first step.</summary>
        private GssResult SelectAndAccept(SpnegoParseResult parsed)
        {
            if (parsed.MechTypes.Count > 0)
            {
                // Optimistic case: the client's most-preferred mechanism is one we support → use it
                // together with the mechToken it already sent.
                IGssMechanismFactory? first = Find(parsed.MechTypes[0]);
                if (first is not null)
                {
                    _mech = first.Create();
                    _selectedOid = first.MechOid;
                    return Wrap(_mech.Accept(parsed.MechToken ?? []));
                }

                // Otherwise select the first mutually-supported mechanism and ask the client to resend
                // a token for it (its optimistic token was for a mechanism we do not have).
                foreach (string oid in parsed.MechTypes)
                {
                    IGssMechanismFactory? f = Find(oid);
                    if (f is null) continue;
                    _mech = f.Create();
                    _selectedOid = f.MechOid;
                    _supportedMechEmitted = true;
                    return GssResult.Continue(SpnegoTokens.CreateNegTokenResp(
                        SpnegoTokens.NegStateAcceptIncomplete, f.MechOid, responseToken: null));
                }
                return Reject(NtStatus.LogonFailure);
            }

            // No mechTypes offered (unusual). If exactly one mechanism is registered, use it.
            if (_factories.Count == 1)
            {
                _mech = _factories[0].Create();
                _selectedOid = _factories[0].MechOid;
                return Wrap(_mech.Accept(parsed.MechToken ?? []));
            }
            return Reject(NtStatus.InvalidParameter);
        }

        private GssResult Wrap(GssResult inner)
        {
            if (_raw) return inner;

            // The server echoes the negotiated mechanism (supportedMech) on the first response only.
            string? supportedMech = _supportedMechEmitted ? null : _selectedOid;
            _supportedMechEmitted = true;

            if (inner.NeedsMoreProcessing)
                return GssResult.Continue(SpnegoTokens.CreateNegTokenResp(
                    SpnegoTokens.NegStateAcceptIncomplete, supportedMech, inner.OutToken));

            if (inner.IsSuccess)
            {
                byte[] wrapped = SpnegoTokens.CreateNegTokenResp(
                    SpnegoTokens.NegStateAcceptCompleted, supportedMech, inner.OutToken);
                return GssResult.Succeeded(inner.SessionKey!, inner.Identity!, wrapped);
            }

            return new GssResult
            {
                Status = inner.Status,
                OutToken = SpnegoTokens.CreateNegTokenResp(SpnegoTokens.NegStateReject),
            };
        }

        private static GssResult Reject(NtStatus status) => new()
        {
            Status = status,
            OutToken = SpnegoTokens.CreateNegTokenResp(SpnegoTokens.NegStateReject),
        };

        private IGssMechanismFactory? Find(string oid)
        {
            foreach (IGssMechanismFactory f in _factories)
                if (f.MechOid == oid) return f;
            return null;
        }
    }
}
