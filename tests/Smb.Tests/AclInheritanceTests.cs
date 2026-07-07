using Smb.Protocol.Security;
using Xunit;

namespace Smb.Tests;

/// <summary>Phase 3 / M3.3 — the creator-inheritance algorithm (MS-DTYP §2.5.3.4, pure layer).</summary>
public class AclInheritanceTests
{
    private static readonly Sid Alice = Sid.FromString("S-1-5-21-1-2-3-1001");

    [Fact]
    public void NoInheritableAces_ReturnsNull()
    {
        // The default-style descriptor: an effective ACE with no inheritance flags does not propagate.
        var dacl = new Acl { Aces = [Ace.Allow(Alice, AccessMask.FileAllAccess)] };
        var parent = SecurityDescriptor.Create(WellKnownSids.LocalSystem, null, dacl);

        Assert.Null(AclInheritance.ComputeInherited(parent, childIsContainer: false));
        Assert.Null(AclInheritance.ComputeInherited(parent, childIsContainer: true));
    }

    [Fact]
    public void FileChild_InheritsObjectInheritAce_AsEffectiveTerminalAce()
    {
        var dacl = new Acl
        {
            Aces = [Ace.Allow(Alice, AccessMask.FileAllAccess, AceFlags.ObjectInherit | AceFlags.ContainerInherit)],
        };
        var parent = SecurityDescriptor.Create(Alice, null, dacl);

        SecurityDescriptor? child = AclInheritance.ComputeInherited(parent, childIsContainer: false);

        Assert.NotNull(child);
        Ace ace = Assert.Single(child!.Dacl!.Aces);
        Assert.Equal(Alice, ace.Sid);
        Assert.Equal(AccessMask.FileAllAccess, ace.AccessMask);
        Assert.Equal(AceFlags.Inherited, ace.Flags); // a file is a leaf: all inherit flags stripped
    }

    [Fact]
    public void FileChild_SkipsContainerOnlyAce()
    {
        // ContainerInherit without ObjectInherit does not reach a leaf.
        var dacl = new Acl { Aces = [Ace.Allow(Alice, AccessMask.FileAllAccess, AceFlags.ContainerInherit)] };
        var parent = SecurityDescriptor.Create(Alice, null, dacl);

        Assert.Null(AclInheritance.ComputeInherited(parent, childIsContainer: false));
    }

    [Fact]
    public void DirectoryChild_KeepsInheritFlags_ForFurtherPropagation()
    {
        var dacl = new Acl
        {
            Aces = [Ace.Allow(Alice, AccessMask.FileAllAccess, AceFlags.ObjectInherit | AceFlags.ContainerInherit)],
        };
        var parent = SecurityDescriptor.Create(Alice, null, dacl);

        SecurityDescriptor? child = AclInheritance.ComputeInherited(parent, childIsContainer: true);

        Ace ace = Assert.Single(child!.Dacl!.Aces);
        Assert.True(ace.Flags.HasFlag(AceFlags.Inherited));
        Assert.True(ace.Flags.HasFlag(AceFlags.ObjectInherit));
        Assert.True(ace.Flags.HasFlag(AceFlags.ContainerInherit));
        Assert.False(ace.Flags.HasFlag(AceFlags.InheritOnly)); // ContainerInherit → also effective on the dir
    }

    [Fact]
    public void DirectoryChild_ObjectInheritOnly_BecomesInheritOnly()
    {
        // Applies to leaf grandchildren only, not to the directory itself.
        var dacl = new Acl { Aces = [Ace.Allow(Alice, AccessMask.FileAllAccess, AceFlags.ObjectInherit)] };
        var parent = SecurityDescriptor.Create(Alice, null, dacl);

        SecurityDescriptor? child = AclInheritance.ComputeInherited(parent, childIsContainer: true);

        Ace ace = Assert.Single(child!.Dacl!.Aces);
        Assert.True(ace.Flags.HasFlag(AceFlags.InheritOnly));
        Assert.True(ace.Flags.HasFlag(AceFlags.ObjectInherit));
    }

    [Fact]
    public void NoPropagateInherit_ProducesTerminalAce_OnDirectory()
    {
        var dacl = new Acl
        {
            Aces =
            [
                Ace.Allow(Alice, AccessMask.FileAllAccess,
                    AceFlags.ObjectInherit | AceFlags.ContainerInherit | AceFlags.NoPropagateInherit),
            ],
        };
        var parent = SecurityDescriptor.Create(Alice, null, dacl);

        SecurityDescriptor? child = AclInheritance.ComputeInherited(parent, childIsContainer: true);

        Ace ace = Assert.Single(child!.Dacl!.Aces);
        Assert.Equal(AceFlags.Inherited, ace.Flags); // effective here, but does not propagate further
    }

    [Fact]
    public void DenyAces_ArePropagated_WithType()
    {
        var dacl = new Acl
        {
            Aces = [Ace.Deny(Alice, AccessMask.WriteAccess, AceFlags.ObjectInherit)],
        };
        var parent = SecurityDescriptor.Create(Alice, null, dacl);

        SecurityDescriptor? child = AclInheritance.ComputeInherited(parent, childIsContainer: false);

        Ace ace = Assert.Single(child!.Dacl!.Aces);
        Assert.Equal(AceType.AccessDenied, ace.Type);
        Assert.Equal(AccessMask.WriteAccess, ace.AccessMask);
    }
}
