using Smb.Protocol.Constants;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 TRANSFORM_HEADER (52 Byte, Context §11, MS-SMB2 §2.2.41) — Rahmen verschlüsselter
/// Nachrichten (nur SMB 3.x). Die AAD für das AEAD umfasst den Header <b>ab Nonce</b>
/// (also ohne ProtocolId und Signature).
/// </summary>
public sealed class TransformHeader
{
    public const int Size = 52;

    /// <summary>Offset, ab dem die AAD beginnt (Nonce), = nach ProtocolId(4)+Signature(16).</summary>
    public const int AadOffset = 20;

    /// <summary>Länge der AAD (Nonce..SessionId) = Size - AadOffset.</summary>
    public const int AadLength = Size - AadOffset;

    /// <summary>Flags-Wert für "verschlüsselt" (3.1.1).</summary>
    public const ushort FlagEncrypted = 0x0001;

    /// <summary>16-Byte-AEAD-Tag (über AAD + Ciphertext).</summary>
    public byte[] Signature { get; set; } = new byte[16];

    /// <summary>16-Byte-Nonce-Feld (CCM nutzt die ersten 11, GCM die ersten 12 Byte; Rest 0).</summary>
    public byte[] Nonce { get; set; } = new byte[16];

    /// <summary>Klartextgröße der eingebetteten SMB2-Nachricht.</summary>
    public uint OriginalMessageSize { get; set; }

    /// <summary>3.1.1: 0x0001 = encrypted. 3.0/3.0.2: AlgorithmId.</summary>
    public ushort Flags { get; set; } = FlagEncrypted;

    public ulong SessionId { get; set; }

    /// <summary>Schreibt den 52-Byte-Header. Signature-Feld kann später gepatcht werden.</summary>
    public void Write(Span<byte> destination)
    {
        if (destination.Length < Size)
            throw new SmbWireFormatException($"TRANSFORM_HEADER benötigt {Size} Byte.");
        var w = new SpanWriter(destination);
        w.WriteBytes(SmbProtocolIds.Smb2Transform);
        w.WriteBytes(Signature);          // 16
        w.WriteBytes(Nonce);              // 16
        w.WriteUInt32(OriginalMessageSize);
        w.WriteUInt16(0);                 // Reserved
        w.WriteUInt16(Flags);
        w.WriteUInt64(SessionId);
    }

    /// <summary>Liest den 52-Byte-Header.</summary>
    public static TransformHeader Read(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < Size)
            throw new SmbWireFormatException($"TRANSFORM_HEADER benötigt {Size} Byte.");
        if (!SmbProtocolIds.IsTransform(buffer))
            throw new SmbWireFormatException("Ungültiger Transform-ProtocolId (erwartet FD 53 4D 42).");

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
