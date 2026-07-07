using Smb.Protocol.Security;
using Xunit;

namespace Smb.Tests;

/// <summary>Phase 3 / M3.3 increment A — the DACL access-check evaluator (MS-DTYP §2.5.3.2).</summary>
public class AccessCheckTests
{
    private static readonly Sid Alice = Sid.FromString("S-1-5-21-1-2-3-1001");
    private static readonly Sid Admins = WellKnownSids.BuiltinAdministrators;
    private static readonly Sid[] AliceToken = [Alice, WellKnownSids.Everyone];

    [Fact]
    public void NoDacl_GrantsAll()
    {
        // DaclPresent not set → unprotected.
        var sd = SecurityDescriptor.Create(WellKnownSids.LocalSystem, null, dacl: null);
        Assert.True(AccessCheck.IsGranted(sd, AliceToken, AccessMask.GenericAll, out _));
    }

    [Fact]
    public void NullDacl_GrantsAll()
    {
        var sd = SecurityDescriptor.Create(WellKnownSids.LocalSystem, null, dacl: null,
            extraControl: SecurityDescriptorControl.DaclPresent);
        Assert.True(AccessCheck.IsGranted(sd, AliceToken, AccessMask.FileWriteData, out _));
    }

    [Fact]
    public void EmptyDacl_DeniesAll()
    {
        var sd = SecurityDescriptor.Create(WellKnownSids.LocalSystem, null, new Acl());
        Assert.False(AccessCheck.IsGranted(sd, AliceToken, AccessMask.FileReadData, out uint granted));
        Assert.Equal(0u, granted);
    }

    [Fact]
    public void AllowAce_GrantsRequestedSubset()
    {
        var dacl = new Acl { Aces = [Ace.Allow(Alice, AccessMask.FileReadData | AccessMask.FileReadAttributes)] };
        var sd = SecurityDescriptor.Create(null, null, dacl);

        Assert.True(AccessCheck.IsGranted(sd, AliceToken, AccessMask.FileReadData, out _));
        Assert.False(AccessCheck.IsGranted(sd, AliceToken, AccessMask.FileWriteData, out _)); // write not granted
    }

    [Fact]
    public void GroupAce_MatchesViaToken()
    {
        // Alice is not named, but her token contains the Everyone SID.
        var dacl = new Acl { Aces = [Ace.Allow(WellKnownSids.Everyone, AccessMask.FileReadData)] };
        var sd = SecurityDescriptor.Create(null, null, dacl);
        Assert.True(AccessCheck.IsGranted(sd, AliceToken, AccessMask.FileReadData, out _));
    }

    [Fact]
    public void DenyBeforeAllow_Wins()
    {
        var dacl = new Acl
        {
            Aces =
            [
                Ace.Deny(Alice, AccessMask.WriteAccess),                 // canonical: deny first
                Ace.Allow(WellKnownSids.Everyone, AccessMask.FileReadData | AccessMask.WriteAccess),
            ],
        };
        var sd = SecurityDescriptor.Create(null, null, dacl);

        Assert.False(AccessCheck.IsGranted(sd, AliceToken, AccessMask.FileWriteData, out _)); // denied
        Assert.True(AccessCheck.IsGranted(sd, AliceToken, AccessMask.FileReadData, out _));   // still allowed
    }

    [Fact]
    public void MaximalAccess_ReflectsAllowedBits()
    {
        var dacl = new Acl
        {
            Aces =
            [
                Ace.Allow(Alice, AccessMask.FileReadData | AccessMask.FileWriteData),
                Ace.Allow(Admins, AccessMask.GenericAll),               // Alice is not an admin here
            ],
        };
        var sd = SecurityDescriptor.Create(null, null, dacl);

        uint max = AccessCheck.MaximalAccess(sd, AliceToken);
        Assert.Equal(AccessMask.FileReadData | AccessMask.FileWriteData, max);
    }

    [Fact]
    public void MaximumAllowed_ResolvesToMaximal()
    {
        var dacl = new Acl { Aces = [Ace.Allow(Alice, AccessMask.FileReadData)] };
        var sd = SecurityDescriptor.Create(null, null, dacl);

        Assert.True(AccessCheck.IsGranted(sd, AliceToken, AccessMask.MaximumAllowed, out uint granted));
        Assert.Equal(AccessMask.FileReadData, granted);
    }
}
