namespace Smb.Protocol.Enums;

/// <summary>SMB2-Header-Flags (Context §4, MS-SMB2 §2.2.1.2).</summary>
[Flags]
public enum Smb2HeaderFlags : uint
{
    None = 0x00000000,

    /// <summary>Response (Server→Client). Auf allen Antworten setzen.</summary>
    ServerToRedir = 0x00000001,

    /// <summary>ASYNC-Header-Variante (AsyncId statt Reserved/TreeId).</summary>
    AsyncCommand = 0x00000002,

    /// <summary>Related Compound: nutzt SessionId/TreeId/FileId des Vorgängers.</summary>
    RelatedOperations = 0x00000004,

    /// <summary>Paket ist signiert.</summary>
    Signed = 0x00000008,

    /// <summary>Maske der 3-Bit-I/O-Priorität (3.1.1).</summary>
    PriorityMask = 0x00000070,

    /// <summary>DFS-Operation.</summary>
    DfsOperations = 0x10000000,

    /// <summary>Replay nach Channel-Failover (3.x).</summary>
    ReplayOperation = 0x20000000,
}
