namespace Smb.Protocol.Enums;

/// <summary>Negotiate context types (3.1.1 only, Context §6.4, MS-SMB2 §2.2.3.1/§2.2.4.1).</summary>
public enum NegotiateContextType : ushort
{
    PreauthIntegrityCapabilities = 0x0001,
    EncryptionCapabilities = 0x0002,
    CompressionCapabilities = 0x0003,
    NetnameNegotiateContextId = 0x0005,
    TransportCapabilities = 0x0006,
    RdmaTransformCapabilities = 0x0007,
    SigningCapabilities = 0x0008,
}

/// <summary>Preauth integrity hash algorithms (Context §6.4). Currently SHA-512 only.</summary>
public enum PreauthHashAlgorithm : ushort
{
    Sha512 = 0x0001,
}

/// <summary>AEAD cipher identifiers for encryption (Context §6.4, §11).</summary>
public enum SmbCipherId : ushort
{
    None = 0x0000,
    Aes128Ccm = 0x0001,
    Aes128Gcm = 0x0002,
    Aes256Ccm = 0x0003,
    Aes256Gcm = 0x0004,
}

/// <summary>Signing algorithms (3.1.1 SIGNING_CAPABILITIES, Context §6.4, §10).</summary>
public enum SmbSigningAlgorithmId : ushort
{
    HmacSha256 = 0x0000,
    AesCmac = 0x0001,
    AesGmac = 0x0002,
}

/// <summary>Compression algorithms (Context §6.4). Phase ≥2.</summary>
public enum SmbCompressionAlgorithm : ushort
{
    None = 0x0000,
    Lznt1 = 0x0001,
    Lz77 = 0x0002,
    Lz77Huffman = 0x0003,
    PatternV1 = 0x0004,
    Lz4 = 0x0005,
}
