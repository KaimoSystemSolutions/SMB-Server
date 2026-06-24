using System.Buffers.Binary;
using Smb.Auth;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Authorization;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

public class ShareAuthorizationTests
{
    // Policy: "Secret" nur für alice (sichtbar & zugreifbar, Vollzugriff);
    // alle anderen User bekommen auf andere Shares nur Lesezugriff.
    private static IShareAccessPolicy DemoPolicy() => new DelegateSharePolicy(
        authorize: ctx =>
        {
            bool isSecret = ctx.ShareName == "Secret";
            bool isAlice = ctx.Identity.UserName == "alice";
            if (isSecret && !isAlice) return ShareAccessResult.Deny(NtStatus.AccessDenied);
            return ShareAccessResult.Grant(isAlice ? SmbAccessMask.FullAccess : SmbAccessMask.ReadOnly);
        },
        isVisible: ctx => !(ctx.ShareName == "Secret" && ctx.Identity.UserName != "alice"));

    private static (Smb2Dispatcher dispatcher, SmbServerState state, SmbConnection conn) NewServer(string userName)
    {
        var identity = new SecurityIdentity { DomainName = "DOM", UserName = userName };
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new DevSpnegoNegotiator(new byte[16], identity),
            RequireMessageSigning = false,
            AllowAnonymousAccess = true,
            ShareAccessPolicy = DemoPolicy(),
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Data", Type = ShareType.Disk });
        options.Shares.Add(new Share { Name = "Secret", Type = ShareType.Disk });

        var state = new SmbServerState(options);
        return (new Smb2Dispatcher(state), state, new SmbConnection());
    }

    private static ulong DoHandshake(Smb2Dispatcher dispatcher, SmbConnection conn)
    {
        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        Smb2Header ss = Smb2Header.Read(dispatcher.ProcessMessage(conn,
            TestHelpers.BuildSessionSetupRequest(1, 0, [0x01])));
        return ss.SessionId;
    }

    private static uint ReadMaximalAccess(byte[] treeConnectResponse)
        // Body: StructureSize(2)+ShareType(1)+Reserved(1)+ShareFlags(4)+Capabilities(4)+MaximalAccess(4)
        => BinaryPrimitives.ReadUInt32LittleEndian(treeConnectResponse.AsSpan(Smb2Header.Size + 12, 4));

    [Fact]
    public void TreeConnect_DeniedForUnauthorizedUser()
    {
        var (dispatcher, _, conn) = NewServer("bob");
        ulong sid = DoHandshake(dispatcher, conn);

        byte[] resp = dispatcher.ProcessMessage(conn,
            TestHelpers.BuildTreeConnectRequest(2, sid, @"\\server\Secret"));
        Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void TreeConnect_AllowedForAuthorizedUser_WithFullAccess()
    {
        var (dispatcher, _, conn) = NewServer("alice");
        ulong sid = DoHandshake(dispatcher, conn);

        byte[] resp = dispatcher.ProcessMessage(conn,
            TestHelpers.BuildTreeConnectRequest(2, sid, @"\\server\Secret"));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        Assert.Equal((uint)SmbAccessMask.FullAccess, ReadMaximalAccess(resp));
    }

    [Fact]
    public void TreeConnect_GrantsReducedAccessMask_PerPolicy()
    {
        var (dispatcher, _, conn) = NewServer("bob");
        ulong sid = DoHandshake(dispatcher, conn);

        byte[] resp = dispatcher.ProcessMessage(conn,
            TestHelpers.BuildTreeConnectRequest(2, sid, @"\\server\Data"));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        // bob erhält nur Lese-Zugriff — der Client sieht das an der MaximalAccess-Maske.
        Assert.Equal((uint)SmbAccessMask.ReadOnly, ReadMaximalAccess(resp));
    }

    [Fact]
    public void GetVisibleShares_FiltersByPolicy()
    {
        var (_, state, _) = NewServer("bob");
        var bob = new SecurityIdentity { DomainName = "DOM", UserName = "bob" };
        var alice = new SecurityIdentity { DomainName = "DOM", UserName = "alice" };

        var bobShares = state.GetVisibleShares(bob).Select(s => s.Name).ToList();
        var aliceShares = state.GetVisibleShares(alice).Select(s => s.Name).ToList();

        Assert.DoesNotContain("Secret", bobShares);   // für bob ausgeblendet
        Assert.Contains("Data", bobShares);
        Assert.Contains("Secret", aliceShares);        // für alice sichtbar
    }

    [Fact]
    public void DefaultPolicy_AllowsEverything()
    {
        var policy = new AllowAllSharePolicy();
        var ctx = new ShareAccessContext
        {
            Identity = new SecurityIdentity { DomainName = "D", UserName = "u" },
            Share = new Share { Name = "Any" },
        };
        Assert.True(policy.IsVisible(ctx));
        ShareAccessResult result = policy.AuthorizeConnect(ctx);
        Assert.True(result.Allowed);
        Assert.Equal(SmbAccessMask.FullAccess, result.MaximalAccess);
    }
}
