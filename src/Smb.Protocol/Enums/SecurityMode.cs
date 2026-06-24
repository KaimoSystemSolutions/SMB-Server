namespace Smb.Protocol.Enums;

/// <summary>SecurityMode-Flags in NEGOTIATE/SESSION_SETUP (Context §6.3, MS-SMB2 §2.2.3/§2.2.4).</summary>
[Flags]
public enum SmbSecurityMode : ushort
{
    None = 0x0000,

    /// <summary>Signing wird unterstützt/angeboten.</summary>
    SigningEnabled = 0x0001,

    /// <summary>Signing wird erzwungen (sichere Defaults, Context §20).</summary>
    SigningRequired = 0x0002,
}
