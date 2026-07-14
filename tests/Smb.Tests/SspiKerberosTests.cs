using System.Text;
using Smb.Auth;
using Smb.Auth.Kerberos;
using Smb.Auth.Ntlm;
using Smb.Auth.Oids;
using Smb.Auth.Sspi;
using Smb.Protocol.Enums;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// SSPI-backed turnkey Kerberos (docs/ENTERPRISE_HARDENING_ROADMAP.md, B1). The composition path and the
/// platform guard are cross-platform; the P/Invoke round-trip (reject a bogus AP-REQ without crashing) runs
/// on Windows only. The Kerberos <i>happy path</i> (real ticket + session-key/PAC extraction) needs a
/// domain-joined host and is verified manually — see the roadmap.
/// </summary>
public class SspiKerberosTests
{
    [Fact]
    public void CreateNegotiator_OffersKerberosFirstThenFallback()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        IKerberosTicketValidator fake = new DelegatingKerberosTicketValidator(
            _ => KerberosValidationResult.Failed(NtStatus.LogonFailure));

        SpnegoNegotiator negotiator = SspiKerberos.CreateNegotiator(fake, new NtlmMechanismFactory(backend));

        // The initial server token must advertise Kerberos (preferred) then NTLM.
        SpnegoParseResult parsed = SpnegoTokens.Parse(negotiator.CreateInitialServerToken());
        Assert.Equal(new[] { GssOids.KerberosV5, GssOids.Ntlm }, parsed.MechTypes);
    }

    [Fact]
    public void Constructor_OnNonWindows_ThrowsPlatformNotSupported()
    {
        if (OperatingSystem.IsWindows()) return; // Windows behaviour is covered by the round-trip test below.
        Assert.Throws<PlatformNotSupportedException>(() => new SspiKerberosTicketValidator());
    }

    [Fact]
    public void Validate_BogusApReq_IsRejected_WithoutCrashing()
    {
        if (!OperatingSystem.IsWindows()) return; // SSPI is Windows-only.

        SspiKerberosTicketValidator validator;
        try
        {
            // Negotiate is present on every Windows host, domain-joined or not.
            validator = new SspiKerberosTicketValidator(SspiKerberosTicketValidator.NegotiatePackage);
        }
        catch (SspiException)
        {
            return; // the security package/credential is unavailable in this environment → skip.
        }

        using (validator)
        {
            // Exercises the full P/Invoke round-trip: GSS-wrap → AcceptSecurityContext → error → mapped result.
            KerberosValidationResult result = validator.Validate(Encoding.ASCII.GetBytes("not-a-real-ap-req"));
            Assert.False(result.IsSuccess);
            Assert.Null(result.SessionKey);
        }
    }

    [Fact]
    public void Validate_EmptyToken_IsRejected()
    {
        if (!OperatingSystem.IsWindows()) return;

        SspiKerberosTicketValidator validator;
        try { validator = new SspiKerberosTicketValidator(SspiKerberosTicketValidator.NegotiatePackage); }
        catch (SspiException) { return; }

        using (validator)
            Assert.Equal(NtStatus.InvalidParameter, validator.Validate([]).Status);
    }
}
