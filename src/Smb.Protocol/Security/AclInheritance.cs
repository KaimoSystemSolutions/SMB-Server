namespace Smb.Protocol.Security;

/// <summary>
/// Computes the security descriptor a newly created file or directory inherits from its parent
/// container (MS-DTYP §2.5.3.4, the creator-inheritance algorithm). Pure and side-effect free.
/// <para>
/// Only the parent's <b>inheritable</b> ACEs (<see cref="AceFlags.ObjectInherit"/> /
/// <see cref="AceFlags.ContainerInherit"/>) propagate. On the child every inherited ACE is marked
/// <see cref="AceFlags.Inherited"/>; a leaf (file) child strips all inheritance flags, while a
/// container (directory) child keeps them so the ACE propagates further — unless the parent ACE
/// carries <see cref="AceFlags.NoPropagateInherit"/>.
/// </para>
/// </summary>
public static class AclInheritance
{
    /// <summary>
    /// Returns the descriptor to apply to a new child, or <c>null</c> when the parent has no
    /// inheritable ACEs (the caller then keeps whatever default it uses). Owner/group are copied from
    /// the parent so the child starts with a sensible ownership.
    /// </summary>
    public static SecurityDescriptor? ComputeInherited(SecurityDescriptor parent, bool childIsContainer)
    {
        if (parent.Dacl is null)
            return null; // NULL/absent parent DACL → nothing to inherit

        var inherited = new List<Ace>();
        foreach (Ace ace in parent.Dacl.Aces)
        {
            if (!ace.IsBasic || ace.Sid is null)
                continue; // object/unknown ACEs are not propagated by this basic implementation

            bool objectInherit = ace.Flags.HasFlag(AceFlags.ObjectInherit);
            bool containerInherit = ace.Flags.HasFlag(AceFlags.ContainerInherit);
            if (!objectInherit && !containerInherit)
                continue; // not an inheritable ACE

            bool noPropagate = ace.Flags.HasFlag(AceFlags.NoPropagateInherit);

            if (!childIsContainer)
            {
                // Leaf (file): inherits only ObjectInherit ACEs, and only as an effective, terminal ACE.
                if (!objectInherit)
                    continue;
                inherited.Add(Rewrite(ace, AceFlags.Inherited));
                continue;
            }

            // Container (directory).
            if (containerInherit)
            {
                // Applies to this directory. Keep propagating (unless NoPropagate stops the chain).
                AceFlags flags = AceFlags.Inherited;
                if (!noPropagate)
                    flags |= ace.Flags & (AceFlags.ObjectInherit | AceFlags.ContainerInherit);
                inherited.Add(Rewrite(ace, flags));
            }
            else
            {
                // ObjectInherit only: does not apply to the directory itself; it passes to leaf
                // grandchildren via an InheritOnly ObjectInherit ACE. NoPropagate cuts the chain → dropped.
                if (noPropagate)
                    continue;
                inherited.Add(Rewrite(ace, AceFlags.Inherited | AceFlags.ObjectInherit | AceFlags.InheritOnly));
            }
        }

        if (inherited.Count == 0)
            return null;

        return SecurityDescriptor.Create(parent.Owner, parent.Group, new Acl { Aces = inherited });
    }

    private static Ace Rewrite(Ace source, AceFlags flags)
        => new() { Type = source.Type, Flags = flags, AccessMask = source.AccessMask, Sid = source.Sid };
}
