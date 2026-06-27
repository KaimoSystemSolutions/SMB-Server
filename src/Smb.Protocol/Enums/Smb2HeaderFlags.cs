namespace Smb.Protocol.Enums;

/// <summary>SMB2 header flags (Context §4, MS-SMB2 §2.2.1.2).</summary>
[Flags]
public enum Smb2HeaderFlags : uint
{
    None = 0x00000000,

    /// <summary>Response (server→client). Set on every response.</summary>
    ServerToRedir = 0x00000001,

    /// <summary>ASYNC header variant (AsyncId instead of Reserved/TreeId).</summary>
    AsyncCommand = 0x00000002,

    /// <summary>Related compound: uses the predecessor's SessionId/TreeId/FileId.</summary>
    RelatedOperations = 0x00000004,

    /// <summary>Packet is signed.</summary>
    Signed = 0x00000008,

    /// <summary>Mask of the 3-bit I/O priority (3.1.1).</summary>
    PriorityMask = 0x00000070,

    /// <summary>DFS operation.</summary>
    DfsOperations = 0x10000000,

    /// <summary>Replay after channel failover (3.x).</summary>
    ReplayOperation = 0x20000000,
}
