namespace Smb.Protocol.Enums;

/// <summary>SMB2_GLOBAL_CAP_* Capability-Flags (Context §6.3, MS-SMB2 §2.2.3).</summary>
[Flags]
public enum Smb2Capabilities : uint
{
    None = 0x00000000,
    Dfs = 0x00000001,
    Leasing = 0x00000002,

    /// <summary>Large MTU / Multi-Credit — Phase 1 setzen.</summary>
    LargeMtu = 0x00000004,
    MultiChannel = 0x00000008,
    PersistentHandles = 0x00000010,
    DirectoryLeasing = 0x00000020,

    /// <summary>Encryption (3.0/3.0.2; bei 3.1.1 via Negotiate-Context).</summary>
    Encryption = 0x00000040,
    Notifications = 0x00000080,
}
