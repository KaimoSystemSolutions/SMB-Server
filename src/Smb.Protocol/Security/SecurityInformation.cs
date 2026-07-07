namespace Smb.Protocol.Security;

/// <summary>
/// SECURITY_INFORMATION flags (MS-DTYP §2.4.7) — carried in the <c>AdditionalInformation</c> field of
/// QUERY_INFO / SET_INFO with <c>InfoType = Security</c>. Selects which parts of the security
/// descriptor a query returns or a set modifies.
/// </summary>
[Flags]
public enum SecurityInformation : uint
{
    None = 0x00000000,
    Owner = 0x00000001,
    Group = 0x00000002,
    Dacl = 0x00000004,
    Sacl = 0x00000008,
    Label = 0x00000010,
    Attribute = 0x00000020,
    Scope = 0x00000040,
    Backup = 0x00010000,
    ProtectedDacl = 0x80000000,
    ProtectedSacl = 0x40000000,
    UnprotectedDacl = 0x20000000,
    UnprotectedSacl = 0x10000000,
}
