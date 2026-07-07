using Smb.Auth.Oids;
using Smb.Protocol.Enums;

namespace Smb.Auth.Kerberos;

/// <summary>
/// Server-side Kerberos V5 GSS mechanism (Context §9, MS-KILE). It is a one-leg exchange: the client's
/// SPNEGO <c>mechToken</c> carries a GSS-wrapped KRB_AP_REQ, which this mechanism unwraps
/// (<see cref="KerberosGssToken"/>) and hands to the injected <see cref="IKerberosTicketValidator"/> for
/// ticket decryption, authenticator verification and identity resolution. On success it returns the
/// ticket session key (the SMB GSS session key) and the identity, plus a GSS-wrapped AP-REP when the
/// validator supplies one for mutual authentication.
/// <para>
/// The mechanism deliberately owns no Kerberos cryptography: that lives behind
/// <see cref="IKerberosTicketValidator"/> so the platform binding (SSPI, MIT/Heimdal GSSAPI, a custom
/// KDC) is entirely the library user's choice. Register it via <see cref="KerberosMechanismFactory"/>.
/// </para>
/// </summary>
public sealed class KerberosServerMechanism : IGssMechanism
{
    private readonly IKerberosTicketValidator _validator;
    private readonly string _mechOid;
    private bool _complete;

    public KerberosServerMechanism(IKerberosTicketValidator validator, string mechOid = GssOids.KerberosV5)
    {
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        _mechOid = mechOid;
    }

    public string MechOid => _mechOid;
    public bool IsComplete => _complete;

    public GssResult Accept(ReadOnlySpan<byte> inToken)
    {
        _complete = true;
        if (inToken.IsEmpty)
            return GssResult.Failed(NtStatus.InvalidParameter);

        // Strip the GSS-API wrapper; tolerate a bare AP-REQ (some stacks hand it over unwrapped).
        byte[] apReq = KerberosGssToken.TryReadApReq(inToken, out byte[] unwrapped)
            ? unwrapped
            : inToken.ToArray();

        KerberosValidationResult result = _validator.Validate(apReq);
        if (!result.IsSuccess)
            return GssResult.Failed(result.Status);

        if (result.SessionKey is not { Length: > 0 } || result.Identity is null)
            return GssResult.Failed(NtStatus.LogonFailure); // validator contract violation → deny

        byte[]? outToken = result.ApRep is { Length: > 0 } apRep
            ? KerberosGssToken.WrapApRep(apRep)
            : null;

        return GssResult.Succeeded(result.SessionKey, result.Identity, outToken);
    }
}
