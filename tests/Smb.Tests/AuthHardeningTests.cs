using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 2 / M2.3 — NTLM / negotiate hardening (audit items O3, O4). O1 (NTLM MIC) is covered by
/// <see cref="NtlmMicTests"/>.
/// </summary>
public class AuthHardeningTests
{
    // --- O4: SESSION_SETUP before NEGOTIATE ---

    [Fact]
    public void SessionSetup_BeforeNegotiate_IsRejected()
    {
        var (d, conn) = NewServer();

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01, 0x02, 0x03]));

        Assert.Equal(NtStatus.InvalidParameter, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void SessionSetup_AfterNegotiate_IsAccepted()
    {
        var (d, conn) = NewServer();
        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));

        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));

        // NTLM needs a second leg → MoreProcessingRequired, i.e. NEGOTIATE gate passed.
        Assert.Equal(NtStatus.MoreProcessingRequired, Smb2Header.Read(resp).Status);
    }

    // --- O3: 3.1.1 NEGOTIATE must carry a PreauthIntegrity context ---

    [Fact]
    public void Negotiate311_WithoutPreauthContext_IsRejected()
    {
        var (d, conn) = NewServer();

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest(
            [SmbDialect.Smb311], includePreauthContext: false));

        Assert.Equal(NtStatus.InvalidParameter, Smb2Header.Read(resp).Status);
        Assert.False(conn.NegotiateDone); // negotiation did not complete
    }

    [Fact]
    public void Negotiate311_WithPreauthContext_Succeeds()
    {
        var (d, conn) = NewServer();

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));

        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        Assert.True(conn.NegotiateDone);
    }

    [Fact]
    public void Negotiate30_WithoutPreauthContext_IsAccepted()
    {
        // The preauth-context requirement applies only to 3.1.1; older dialects have no contexts.
        var (d, conn) = NewServer();

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb300]));

        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
    }

    private static (Smb2Dispatcher, SmbConnection) NewServer()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());
        return (new Smb2Dispatcher(new SmbServerState(options)), new SmbConnection());
    }
}
