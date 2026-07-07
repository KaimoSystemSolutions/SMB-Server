using System.DirectoryServices.Protocols;
using System.Net;
using Smb.Auth.Ldap;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 2 / M2.2 increment E — the opt-in <see cref="DirectoryServicesLdapSearcher"/>. The live LDAP
/// round-trip is an integration test against a real domain controller; here we only cover the wiring
/// and argument validation that runs before any network access.
/// </summary>
public class DirectoryServicesLdapSearcherTests
{
    [Fact]
    public void Ctor_NullOptions_Throws()
        => Assert.Throws<ArgumentNullException>(() => new DirectoryServicesLdapSearcher(null!));

    [Fact]
    public void Ctor_EmptyServer_ThrowsBeforeConnecting()
        => Assert.Throws<ArgumentException>(() => new DirectoryServicesLdapSearcher(
            new LdapConnectionOptions { Server = "" }));

    [Fact]
    public void ConnectionOptions_HaveSensibleDefaults()
    {
        var options = new LdapConnectionOptions { Server = "dc01.corp.example.com" };
        Assert.Equal(389, options.Port);
        Assert.False(options.UseSsl);
        Assert.Equal(AuthType.Negotiate, options.AuthType);
        Assert.Null(options.Credential);
        Assert.Equal(TimeSpan.FromSeconds(30), options.Timeout);
    }

    [Fact]
    public void ConnectionOptions_AcceptCredentialAndTls()
    {
        var options = new LdapConnectionOptions
        {
            Server = "dc01.corp.example.com",
            Port = 636,
            UseSsl = true,
            Credential = new NetworkCredential("svc", "pw", "CORP"),
        };
        Assert.Equal(636, options.Port);
        Assert.True(options.UseSsl);
        Assert.Equal("svc", options.Credential!.UserName);
    }
}
