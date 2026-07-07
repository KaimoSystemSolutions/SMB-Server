using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Security;

/// <summary>
/// A Windows security descriptor in <b>self-relative</b> form (MS-DTYP §2.4.6) — the layout SMB
/// exchanges over QUERY/SET_SECURITY_INFO. Holds the owner/group SIDs and the discretionary (DACL) and
/// system (SACL) access control lists.
/// <para>Header: <c>Revision(1) · Sbz1(1) · Control(2) · OffsetOwner(4) · OffsetGroup(4) ·
/// OffsetSacl(4) · OffsetDacl(4)</c>, followed by the referenced SIDs/ACLs at their offsets.</para>
/// <para>
/// The <see cref="Control"/> flags are preserved exactly so the three DACL states round-trip:
/// <b>no DACL</b> (<see cref="SecurityDescriptorControl.DaclPresent"/> clear → unprotected, access
/// granted), <b>NULL DACL</b> (flag set, <see cref="Dacl"/> null → everyone full access) and a
/// <b>present DACL</b> (flag set, <see cref="Dacl"/> non-null → its ACEs govern access).
/// </para>
/// </summary>
public sealed class SecurityDescriptor
{
    private const int HeaderSize = 20;

    public byte Revision { get; init; } = 1;
    public SecurityDescriptorControl Control { get; init; }
    public Sid? Owner { get; init; }
    public Sid? Group { get; init; }
    public Acl? Dacl { get; init; }
    public Acl? Sacl { get; init; }

    /// <summary>
    /// Builds a self-relative descriptor, setting the DACL/SACL-present control bits automatically when
    /// the corresponding list is supplied. For a NULL DACL (everyone full access) pass
    /// <paramref name="dacl"/> = null with <see cref="SecurityDescriptorControl.DaclPresent"/> in
    /// <paramref name="extraControl"/>.
    /// </summary>
    public static SecurityDescriptor Create(
        Sid? owner, Sid? group, Acl? dacl, Acl? sacl = null, SecurityDescriptorControl extraControl = SecurityDescriptorControl.None)
    {
        SecurityDescriptorControl control = extraControl | SecurityDescriptorControl.SelfRelative;
        if (dacl is not null) control |= SecurityDescriptorControl.DaclPresent;
        if (sacl is not null) control |= SecurityDescriptorControl.SaclPresent;
        return new SecurityDescriptor { Owner = owner, Group = group, Dacl = dacl, Sacl = sacl, Control = control };
    }

    public static SecurityDescriptor Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderSize)
            throw new SmbWireFormatException($"Security descriptor header needs {HeaderSize} bytes, has {data.Length}.");

        byte revision = data[0];
        var control = (SecurityDescriptorControl)BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(2, 2));
        int offOwner = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
        int offGroup = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8, 4));
        int offSacl = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(12, 4));
        int offDacl = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(16, 4));

        Sid? owner = offOwner != 0 ? Sid.Parse(SliceFrom(data, offOwner)) : null;
        Sid? group = offGroup != 0 ? Sid.Parse(SliceFrom(data, offGroup)) : null;
        Acl? sacl = control.HasFlag(SecurityDescriptorControl.SaclPresent) && offSacl != 0
            ? Acl.Parse(SliceFrom(data, offSacl), out _) : null;
        Acl? dacl = control.HasFlag(SecurityDescriptorControl.DaclPresent) && offDacl != 0
            ? Acl.Parse(SliceFrom(data, offDacl), out _) : null;

        return new SecurityDescriptor
        {
            Revision = revision,
            Control = control,
            Owner = owner,
            Group = group,
            Sacl = sacl,
            Dacl = dacl,
        };
    }

    /// <summary>Serializes to the self-relative binary form.</summary>
    public byte[] ToBytes()
    {
        // Layout after the header: Owner, Group, SACL, DACL (order is arbitrary — offsets locate them).
        int pos = HeaderSize;
        int offOwner = 0, offGroup = 0, offSacl = 0, offDacl = 0;

        if (Owner is not null) { offOwner = pos; pos += Owner.BinaryLength; }
        if (Group is not null) { offGroup = pos; pos += Group.BinaryLength; }
        if (Control.HasFlag(SecurityDescriptorControl.SaclPresent) && Sacl is not null) { offSacl = pos; pos += Sacl.BinaryLength; }
        if (Control.HasFlag(SecurityDescriptorControl.DaclPresent) && Dacl is not null) { offDacl = pos; pos += Dacl.BinaryLength; }

        var bytes = new byte[pos];
        var w = new SpanWriter(bytes);
        w.WriteByte(Revision);
        w.WriteByte(0);                                                   // Sbz1
        w.WriteUInt16((ushort)(Control | SecurityDescriptorControl.SelfRelative));
        w.WriteUInt32((uint)offOwner);
        w.WriteUInt32((uint)offGroup);
        w.WriteUInt32((uint)offSacl);
        w.WriteUInt32((uint)offDacl);

        if (offOwner != 0) { w.Seek(offOwner); Owner!.Write(ref w); }
        if (offGroup != 0) { w.Seek(offGroup); Group!.Write(ref w); }
        if (offSacl != 0) { w.Seek(offSacl); Sacl!.Write(ref w); }
        if (offDacl != 0) { w.Seek(offDacl); Dacl!.Write(ref w); }

        return bytes;
    }

    private static ReadOnlySpan<byte> SliceFrom(ReadOnlySpan<byte> data, int offset)
    {
        if ((uint)offset >= (uint)data.Length)
            throw new SmbWireFormatException($"Security descriptor offset {offset} out of range ({data.Length}).");
        return data[offset..];
    }
}
