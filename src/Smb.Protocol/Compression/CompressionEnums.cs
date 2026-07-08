namespace Smb.Protocol.Compression;

/// <summary>
/// Flags of the SMB2_COMPRESSION_TRANSFORM_HEADER (MS-SMB2 §2.2.42) and, at negotiate time, of the
/// SMB2_COMPRESSION_CAPABILITIES context (§2.2.3.1.3). <see cref="Chained"/> selects the chained
/// framing (a sequence of payload headers) instead of the single-payload unchained framing.
/// </summary>
[Flags]
public enum SmbCompressionFlags : uint
{
    None = 0x00000000,
    Chained = 0x00000001,
}
