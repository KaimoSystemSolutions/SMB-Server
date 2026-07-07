namespace Smb.Protocol.Security;

/// <summary>ACE type (MS-DTYP §2.4.4.1 <c>AceType</c>). Only the basic (non-object) types are modeled.</summary>
public enum AceType : byte
{
    AccessAllowed = 0x00,
    AccessDenied = 0x01,
    SystemAudit = 0x02,
    SystemAlarm = 0x03,
}

/// <summary>ACE flags (MS-DTYP §2.4.4.1 <c>AceFlags</c>): inheritance and audit control.</summary>
[Flags]
public enum AceFlags : byte
{
    None = 0x00,
    ObjectInherit = 0x01,
    ContainerInherit = 0x02,
    NoPropagateInherit = 0x04,
    InheritOnly = 0x08,
    Inherited = 0x10,
    SuccessfulAccess = 0x40, // audit: log successful access
    FailedAccess = 0x80,     // audit: log failed access
}

/// <summary>Security-descriptor control flags (MS-DTYP §2.4.6 <c>Control</c>).</summary>
[Flags]
public enum SecurityDescriptorControl : ushort
{
    None = 0x0000,
    OwnerDefaulted = 0x0001,
    GroupDefaulted = 0x0002,
    DaclPresent = 0x0004,
    DaclDefaulted = 0x0008,
    SaclPresent = 0x0010,
    SaclDefaulted = 0x0020,
    DaclAutoInheritReq = 0x0100,
    SaclAutoInheritReq = 0x0200,
    DaclAutoInherited = 0x0400,
    SaclAutoInherited = 0x0800,
    DaclProtected = 0x1000,
    SaclProtected = 0x2000,
    RmControlValid = 0x4000,
    SelfRelative = 0x8000,
}
