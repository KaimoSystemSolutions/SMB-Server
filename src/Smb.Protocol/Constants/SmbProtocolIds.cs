namespace Smb.Protocol.Constants;

/// <summary>
/// Feste Protokoll-Signaturen (Context §4, §11, §19.1). Diese gelten als Bytefolgen,
/// nicht als Little-Endian-Zahlen.
/// </summary>
public static class SmbProtocolIds
{
    /// <summary>SMB2-Header: <c>FE 53 4D 42</c> ("\xFESMB").</summary>
    public static ReadOnlySpan<byte> Smb2 => [0xFE, 0x53, 0x4D, 0x42];

    /// <summary>SMB2 TRANSFORM_HEADER (verschlüsselt): <c>FD 53 4D 42</c> ("\xFDSMB").</summary>
    public static ReadOnlySpan<byte> Smb2Transform => [0xFD, 0x53, 0x4D, 0x42];

    /// <summary>SMB2 COMPRESSION_TRANSFORM_HEADER: <c>FC 53 4D 42</c> ("\xFCSMB").</summary>
    public static ReadOnlySpan<byte> Smb2Compression => [0xFC, 0x53, 0x4D, 0x42];

    /// <summary>SMB1-Header: <c>FF 53 4D 42</c> ("\xFFSMB"). Nur für Multi-Protocol-Negotiate (§6.1).</summary>
    public static ReadOnlySpan<byte> Smb1 => [0xFF, 0x53, 0x4D, 0x42];

    /// <summary>Prüft, ob die ersten 4 Bytes dem SMB2-ProtocolId entsprechen.</summary>
    public static bool IsSmb2(ReadOnlySpan<byte> data) => StartsWith(data, Smb2);

    /// <summary>Prüft, ob die ersten 4 Bytes dem Transform-ProtocolId entsprechen.</summary>
    public static bool IsTransform(ReadOnlySpan<byte> data) => StartsWith(data, Smb2Transform);

    /// <summary>Prüft, ob die ersten 4 Bytes dem Compression-ProtocolId entsprechen.</summary>
    public static bool IsCompression(ReadOnlySpan<byte> data) => StartsWith(data, Smb2Compression);

    /// <summary>Prüft, ob die ersten 4 Bytes dem SMB1-ProtocolId entsprechen.</summary>
    public static bool IsSmb1(ReadOnlySpan<byte> data) => StartsWith(data, Smb1);

    private static bool StartsWith(ReadOnlySpan<byte> data, ReadOnlySpan<byte> prefix)
        => data.Length >= prefix.Length && data[..prefix.Length].SequenceEqual(prefix);
}
