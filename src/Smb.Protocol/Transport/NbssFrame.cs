namespace Smb.Protocol.Transport;

/// <summary>
/// NBSS / "direct TCP transport" (MS-SMB2 §2.1, Context §3): 4-Byte-Präfix vor jeder
/// SMB2-Nachricht auf TCP/445.
/// <list type="bullet">
///   <item>Byte 0: Message-Type (0x00 = Session Message).</item>
///   <item>Bytes 1–3: 24-Bit-Länge der folgenden SMB2-Nachricht, <b>Big-Endian</b>.</item>
/// </list>
/// Achtung: Dieses Längenfeld ist das <b>einzige</b> Big-Endian-Feld; SMB2 selbst ist
/// Little-Endian (Context §23). Maximale Payload damit 0xFFFFFF (16 MiB).
/// </summary>
public static class NbssFrame
{
    /// <summary>Länge des NBSS-Präfix in Bytes.</summary>
    public const int HeaderLength = 4;

    /// <summary>Message-Type für eine reguläre Session-Nachricht.</summary>
    public const byte SessionMessageType = 0x00;

    /// <summary>Maximale Payload-Länge (24 Bit).</summary>
    public const int MaxPayloadLength = 0xFFFFFF;

    /// <summary>Liest die Payload-Länge aus einem 4-Byte-Präfix.</summary>
    /// <exception cref="ArgumentException">Wenn weniger als 4 Bytes vorliegen.</exception>
    public static int ReadLength(ReadOnlySpan<byte> header)
    {
        if (header.Length < HeaderLength)
            throw new ArgumentException("NBSS-Präfix benötigt mindestens 4 Bytes.", nameof(header));
        // Byte 0 = Type (ignoriert für Längenberechnung), Bytes 1..3 = 24-Bit Big-Endian.
        return (header[1] << 16) | (header[2] << 8) | header[3];
    }

    /// <summary>Liest den Message-Type (Byte 0).</summary>
    public static byte ReadMessageType(ReadOnlySpan<byte> header)
    {
        if (header.Length < HeaderLength)
            throw new ArgumentException("NBSS-Präfix benötigt mindestens 4 Bytes.", nameof(header));
        return header[0];
    }

    /// <summary>Schreibt ein 4-Byte-Präfix für eine Payload der angegebenen Länge.</summary>
    public static void WriteHeader(Span<byte> destination, int payloadLength)
    {
        if (destination.Length < HeaderLength)
            throw new ArgumentException("Ziel benötigt mindestens 4 Bytes.", nameof(destination));
        if ((uint)payloadLength > MaxPayloadLength)
            throw new ArgumentOutOfRangeException(nameof(payloadLength),
                $"NBSS-Payload darf höchstens {MaxPayloadLength} Bytes sein.");

        destination[0] = SessionMessageType;
        destination[1] = (byte)((payloadLength >> 16) & 0xFF);
        destination[2] = (byte)((payloadLength >> 8) & 0xFF);
        destination[3] = (byte)(payloadLength & 0xFF);
    }

    /// <summary>Verpackt eine SMB2-Nachricht in einen vollständigen NBSS-Frame (Präfix + Payload).</summary>
    public static byte[] Wrap(ReadOnlySpan<byte> payload)
    {
        var frame = new byte[HeaderLength + payload.Length];
        WriteHeader(frame, payload.Length);
        payload.CopyTo(frame.AsSpan(HeaderLength));
        return frame;
    }
}
