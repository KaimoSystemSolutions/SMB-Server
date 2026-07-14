using System.Security.Cryptography;
using Smb.Auth.Ntlm;
using Smb.Auth.Oids;
using Smb.Crypto;
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
/// <b>Downgrade protection (RFC 4178 §5, MS-SPNG §3.3.5.1).</b> When <see cref="RequireMechListMic"/>
/// is set, the client's <c>mechListMIC</c> is verified once the selected mechanism succeeds: the MIC is
/// recomputed over the <c>MechTypeList</c> exactly as received and compared in constant time, so a MITM
/// that strips the stronger mechanism (e.g. Kerberos) to force the NTLM fallback is detected. This is
/// enforced for the <b>NTLM</b> mechanism (the O8 fallback-downgrade case), whose GSS_getMIC this layer
/// can compute from the negotiated session key; a Kerberos context's own integrity is validated inside
/// its GSS provider (B1/SSPI). Off by default for compatibility — Windows clients always send the MIC,
/// so enable it only against clients known to comply. See docs/SECURITY_AUDIT.md finding O8.
/// </para>
/// </summary>
public sealed class SpnegoNegotiator : ISpnegoNegotiator
{
    private readonly IReadOnlyList<IGssMechanismFactory> _factories;

    /// <summary>
    /// When true, enforce the SPNEGO <c>mechListMIC</c> for the NTLM mechanism (downgrade protection,
    /// RFC 4178 §5). Default false (compatibility). See the class remarks and audit finding O8.
    /// </summary>
    public bool RequireMechListMic { get; init; }

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

    public ISpnegoServerContext CreateServerContext() => new Context(_factories, RequireMechListMic);

    private sealed class Context : ISpnegoServerContext
    {
        private readonly IReadOnlyList<IGssMechanismFactory> _factories;
        private readonly bool _requireMechListMic;
        private IGssMechanism? _mech;
        private bool _raw;                // raw NTLMSSP: no SPNEGO wrapping on responses
        private bool _supportedMechEmitted;
        private string? _selectedOid;
        private byte[]? _mechListBytes;   // MechTypeList as received (signed by the mechListMIC, RFC 4178 §5)

        public Context(IReadOnlyList<IGssMechanismFactory> factories, bool requireMechListMic)
        {
            _factories = factories;
            _requireMechListMic = requireMechListMic;
        }

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
            {
                // Remember the mechList exactly as received so the mechListMIC (in a later NegTokenResp)
                // is verified against the on-wire bytes — that is what makes a strip detectable.
                _mechListBytes = parsed.MechListBytes;
                return SelectAndAccept(parsed);
            }

            // Follow-up NegTokenResp for the already-selected mechanism.
            return Wrap(_mech.Accept(parsed.MechToken ?? []), parsed.MechListMic);
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
                    return Wrap(_mech.Accept(parsed.MechToken ?? []), parsed.MechListMic);
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
                return Wrap(_mech.Accept(parsed.MechToken ?? []), parsed.MechListMic);
            }
            return Reject(NtStatus.InvalidParameter);
        }

        private GssResult Wrap(GssResult inner, byte[]? mechListMic)
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
                // RFC 4178 §5 downgrade protection: the mechanism succeeded, so now verify the client's
                // mechListMIC over the mechList we actually received (before completing the exchange).
                NtStatus mic = VerifyMechListMic(inner.SessionKey, mechListMic);
                if (mic != NtStatus.Success)
                    return Reject(mic);

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

        /// <summary>
        /// Verifies the SPNEGO <c>mechListMIC</c> (RFC 4178 §5) once the mechanism has succeeded. Only
        /// enforced when <see cref="RequireMechListMic"/> is set and the negotiated mechanism is NTLM
        /// (whose GSS_getMIC this layer can compute from the session key). A required-but-absent or a
        /// mismatching MIC is a downgrade → <see cref="NtStatus.AccessDenied"/>.
        /// </summary>
        private NtStatus VerifyMechListMic(byte[]? sessionKey, byte[]? mechListMic)
        {
            if (!_requireMechListMic) return NtStatus.Success;         // opt-in only
            if (_selectedOid != GssOids.Ntlm) return NtStatus.Success; // only NTLM verifiable here
            if (_mechListBytes is null) return NtStatus.Success;       // no SPNEGO mechList to protect

            if (mechListMic is null || sessionKey is null)
                return NtStatus.AccessDenied;                          // required but absent → downgrade

            byte[] expected = NtlmCryptography.NtlmMechListMic(sessionKey, client: true, _mechListBytes);
            return expected.Length == mechListMic.Length
                   && CryptographicOperations.FixedTimeEquals(expected, mechListMic)
                ? NtStatus.Success
                : NtStatus.AccessDenied;
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
