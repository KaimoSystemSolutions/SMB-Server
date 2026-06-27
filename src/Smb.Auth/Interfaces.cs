namespace Smb.Auth;

/// <summary>
/// A single GSS auth mechanism (NTLM, Kerberos, …), Context §9.1. Processes incoming mech tokens
/// and returns response tokens as needed, until <see cref="GssResult.Status"/> reports Success or
/// an error. One instance serves exactly one auth operation (one session) and holds its state.
/// </summary>
public interface IGssMechanism
{
    /// <summary>OID of the mechanism (e.g. NTLM 1.3.6.1.4.1.311.2.2.10), Context §9.2.</summary>
    string MechOid { get; }

    /// <summary>True once the mechanism is complete (success or final failure).</summary>
    bool IsComplete { get; }

    /// <summary>Processes an incoming mech token and returns the next result.</summary>
    GssResult Accept(ReadOnlySpan<byte> inToken);
}

/// <summary>
/// Factory for mechanism-specific auth operations. Exactly one
/// <see cref="IGssMechanism"/> instance is created per session.
/// </summary>
public interface IGssMechanismFactory
{
    string MechOid { get; }
    IGssMechanism Create();
}

/// <summary>
/// SPNEGO wrapper (Context §9.1): selects the mechanism, encapsulates NegTokenInit2/NegTokenResp.
/// The SESSION_SETUP code talks exclusively to this interface.
/// </summary>
public interface ISpnegoNegotiator
{
    /// <summary>Creates the initial server token (NegTokenInit2) for the NEGOTIATE response.</summary>
    byte[] CreateInitialServerToken();

    /// <summary>Creates a new, stateful SPNEGO context for a session.</summary>
    ISpnegoServerContext CreateServerContext();
}

/// <summary>Stateful SPNEGO server context for exactly one session.</summary>
public interface ISpnegoServerContext
{
    /// <summary>Processes an incoming SPNEGO token (from the SESSION_SETUP security buffer).</summary>
    GssResult Accept(ReadOnlySpan<byte> spnegoToken);
}

/// <summary>
/// Backend for verification/identity resolution (Context §9.1). LDAP/AD plug in <b>here</b> later —
/// NTLM and Kerberos share the same identity source.
/// </summary>
public interface IIdentityBackend
{
    /// <summary>Returns the NT hash (MD4 of the UTF-16LE password) for local NTLM verification.</summary>
    bool TryGetNtHash(string domain, string user, out byte[] ntHash);

    /// <summary>Resolves Domain\User to a full identity (SID + groups).</summary>
    SecurityIdentity Resolve(string domain, string user);
}
