namespace Smb.Protocol.Constants;

/// <summary>
/// Fixed protocol signatures (Context §4, §11, §19.1). These are byte sequences,
/// not little-endian numbers.
/// </summary>
public static class SmbProtocolIds
{
    /// <summary>SMB2 header: <c>FE 53 4D 42</c> ("\xFESMB").</summary>
    public static ReadOnlySpan<byte> Smb2 => [0xFE, 0x53, 0x4D, 0x42];

    /// <summary>SMB2 TRANSFORM_HEADER (encrypted): <c>FD 53 4D 42</c> ("\xFDSMB").</summary>
    public static ReadOnlySpan<byte> Smb2Transform => [0xFD, 0x53, 0x4D, 0x42];

    /// <summary>SMB2 COMPRESSION_TRANSFORM_HEADER: <c>FC 53 4D 42</c> ("\xFCSMB").</summary>
    public static ReadOnlySpan<byte> Smb2Compression => [0xFC, 0x53, 0x4D, 0x42];

    /// <summary>SMB1 header: <c>FF 53 4D 42</c> ("\xFFSMB"). Only for multi-protocol negotiate (§6.1).</summary>
    public static ReadOnlySpan<byte> Smb1 => [0xFF, 0x53, 0x4D, 0x42];

    /// <summary>Checks whether the first 4 bytes match the SMB2 ProtocolId.</summary>
    public static bool IsSmb2(ReadOnlySpan<byte> data) => StartsWith(data, Smb2);

    /// <summary>Checks whether the first 4 bytes match the transform ProtocolId.</summary>
    public static bool IsTransform(ReadOnlySpan<byte> data) => StartsWith(data, Smb2Transform);

    /// <summary>Checks whether the first 4 bytes match the compression ProtocolId.</summary>
    public static bool IsCompression(ReadOnlySpan<byte> data) => StartsWith(data, Smb2Compression);

    /// <summary>Checks whether the first 4 bytes match the SMB1 ProtocolId.</summary>
    public static bool IsSmb1(ReadOnlySpan<byte> data) => StartsWith(data, Smb1);

    private static bool StartsWith(ReadOnlySpan<byte> data, ReadOnlySpan<byte> prefix)
        => data.Length >= prefix.Length && data[..prefix.Length].SequenceEqual(prefix);
}
