using Smb.Protocol.Security;
using Xunit;

namespace Smb.Tests;

/// <summary>Phase 3 / M3.1 increments C+D — <see cref="Acl"/> and <see cref="SecurityDescriptor"/>
/// (self-relative, MS-DTYP §2.4.5/§2.4.6).</summary>
public class SecurityDescriptorTests
{
    private const uint FullControl = 0x001F01FF;
    private const uint Write = 0x00000002;

    [Fact]
    public void Acl_RoundTrips()
    {
        var acl = new Acl
        {
            Aces =
            [
                Ace.Allow(WellKnownSids.BuiltinAdministrators, FullControl),
                Ace.Deny(WellKnownSids.Everyone, Write),
            ],
        };

        Acl parsed = Acl.Parse(acl.ToBytes(), out int consumed);

        Assert.Equal(acl.BinaryLength, consumed);
        Assert.Equal(2, parsed.Aces.Count);
        Assert.Equal(AceType.AccessAllowed, parsed.Aces[0].Type);
        Assert.Equal(WellKnownSids.BuiltinAdministrators, parsed.Aces[0].Sid);
        Assert.Equal(AceType.AccessDenied, parsed.Aces[1].Type);
        Assert.Equal(Write, parsed.Aces[1].AccessMask);
    }

    [Fact]
    public void SecurityDescriptor_WithDacl_RoundTrips()
    {
        var dacl = new Acl
        {
            Aces =
            [
                Ace.Allow(WellKnownSids.BuiltinAdministrators, FullControl),
                Ace.Allow(WellKnownSids.AuthenticatedUsers, 0x00120089), // read+execute
            ],
        };
        SecurityDescriptor sd = SecurityDescriptor.Create(
            WellKnownSids.LocalSystem, WellKnownSids.BuiltinUsers, dacl);

        SecurityDescriptor parsed = SecurityDescriptor.Parse(sd.ToBytes());

        Assert.True(parsed.Control.HasFlag(SecurityDescriptorControl.SelfRelative));
        Assert.True(parsed.Control.HasFlag(SecurityDescriptorControl.DaclPresent));
        Assert.Equal(WellKnownSids.LocalSystem, parsed.Owner);
        Assert.Equal(WellKnownSids.BuiltinUsers, parsed.Group);
        Assert.NotNull(parsed.Dacl);
        Assert.Equal(2, parsed.Dacl!.Aces.Count);
        Assert.Equal(WellKnownSids.AuthenticatedUsers, parsed.Dacl.Aces[1].Sid);
        Assert.Null(parsed.Sacl);

        // full byte-for-byte round-trip
        Assert.Equal(sd.ToBytes(), parsed.ToBytes());
    }

    [Fact]
    public void NullDacl_IsDistinctFromNoDacl()
    {
        // NULL DACL: present flag set, no ACL body → "everyone full access".
        SecurityDescriptor nullDacl = SecurityDescriptor.Create(
            WellKnownSids.LocalSystem, null, dacl: null,
            extraControl: SecurityDescriptorControl.DaclPresent);
        SecurityDescriptor pNull = SecurityDescriptor.Parse(nullDacl.ToBytes());
        Assert.True(pNull.Control.HasFlag(SecurityDescriptorControl.DaclPresent));
        Assert.Null(pNull.Dacl);

        // No DACL: present flag clear → unprotected.
        SecurityDescriptor noDacl = SecurityDescriptor.Create(WellKnownSids.LocalSystem, null, dacl: null);
        SecurityDescriptor pNo = SecurityDescriptor.Parse(noDacl.ToBytes());
        Assert.False(pNo.Control.HasFlag(SecurityDescriptorControl.DaclPresent));
        Assert.Null(pNo.Dacl);
    }

    [Fact]
    public void SecurityDescriptor_WithSacl_RoundTrips()
    {
        var sacl = new Acl { Aces = [Ace.Audit(WellKnownSids.Everyone, FullControl, AceFlags.FailedAccess)] };
        SecurityDescriptor sd = SecurityDescriptor.Create(
            WellKnownSids.LocalSystem, null, dacl: null, sacl: sacl);

        SecurityDescriptor parsed = SecurityDescriptor.Parse(sd.ToBytes());
        Assert.True(parsed.Control.HasFlag(SecurityDescriptorControl.SaclPresent));
        Assert.NotNull(parsed.Sacl);
        Assert.Equal(AceType.SystemAudit, parsed.Sacl!.Aces[0].Type);
    }

    [Fact]
    public void Parses_WindowsShapedBlob()
    {
        // A minimal self-relative SD: owner S-1-5-18, no group, DACL with one allow-Everyone-full ACE.
        var owner = WellKnownSids.LocalSystem;
        var dacl = new Acl { Aces = [Ace.Allow(WellKnownSids.Everyone, FullControl)] };
        byte[] blob = SecurityDescriptor.Create(owner, null, dacl).ToBytes();

        SecurityDescriptor sd = SecurityDescriptor.Parse(blob);
        Assert.Equal("S-1-5-18", sd.Owner!.ToString());
        Assert.Null(sd.Group);
        Assert.Single(sd.Dacl!.Aces);
        Assert.Equal("S-1-1-0", sd.Dacl.Aces[0].Sid!.ToString());
        Assert.Equal(FullControl, sd.Dacl.Aces[0].AccessMask);
    }
}
