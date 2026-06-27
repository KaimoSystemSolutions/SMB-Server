using Smb.Protocol.Constants;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 TRANSFORM_HEADER (52 bytes, Context §11, MS-SMB2 §2.2.41) — the frame of encrypted
/// messages (SMB 3.x only). The AAD for the AEAD spans the header <b>from the nonce onward</b>
/// (i.e. without ProtocolId and Signature).
/// </summary>
public sealed class TransformHeader
{
    public const int Size = 52;

    /// <summary>Offset where the AAD begins (nonce), = after ProtocolId(4)+Signature(16).</summary>
    public const int AadOffset = 20;

    /// <summary>Length of the AAD (Nonce..SessionId) = Size - AadOffset.</summary>
    public const int AadLength = Size - AadOffset;

    /// <summary>Flags value for "encrypted" (3.1.1).</summary>
    public const ushort FlagEncrypted = 0x0001;

    /// <summary>16-byte AEAD tag (over AAD + ciphertext).</summary>
    public byte[] Signature { get; set; } = new byte[16];

    /// <summary>16-byte nonce field (CCM uses the first 11, GCM the first 12 bytes; rest 0).</summary>
    public byte[] Nonce { get; set; } = new byte[16];

    /// <summary>Plaintext size of the embedded SMB2 message.</summary>
    public uint OriginalMessageSize { get; set; }

    /// <summary>3.1.1: 0x0001 = encrypted. 3.0/3.0.2: AlgorithmId.</summary>
    public ushort Flags { get; set; } = FlagEncrypted;

    public ulong SessionId { get; set; }

    /// <summary>Writes the 52-byte header. The Signature field can be patched later.</summary>
    public void Write(Span<byte> destination)
    {
        if (destination.Length < Size)
            throw new SmbWireFormatException($"TRANSFORM_HEADER requires {Size} bytes.");
        var w = new SpanWriter(destination);
        w.WriteBytes(SmbProtocolIds.Smb2Transform);
        w.WriteBytes(Signature);          // 16
        w.WriteBytes(Nonce);              // 16
        w.WriteUInt32(OriginalMessageSize);
        w.WriteUInt16(0);                 // Reserved
        w.WriteUInt16(Flags);
        w.WriteUInt64(SessionId);
    }

    /// <summary>Reads the 52-byte header.</summary>
    public static TransformHeader Read(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < Size)
            throw new SmbWireFormatException($"TRANSFORM_HEADER requires {Size} bytes.");
        if (!SmbProtocolIds.IsTransform(buffer))
            throw new SmbWireFormatException("Invalid transform ProtocolId (expected FD 53 4D 42).");

        var r = new SpanReader(buffer);
        r.Skip(4); // ProtocolId
        var header = new TransformHeader
        {
            Signature = r.ReadByteArray(16),
            Nonce = r.ReadByteArray(16),
            OriginalMessageSize = r.ReadUInt32(),
        };
        r.Skip(2); // Reserved
        header.Flags = r.ReadUInt16();
        header.SessionId = r.ReadUInt64();
        return header;
    }
}
