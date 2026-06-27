namespace Smb.Protocol.Transport;

/// <summary>
/// NBSS / "direct TCP transport" (MS-SMB2 §2.1, Context §3): a 4-byte prefix before every
/// SMB2 message on TCP/445.
/// <list type="bullet">
///   <item>Byte 0: message type (0x00 = session message).</item>
///   <item>Bytes 1–3: 24-bit length of the following SMB2 message, <b>big-endian</b>.</item>
/// </list>
/// Note: this length field is the <b>only</b> big-endian field; SMB2 itself is
/// little-endian (Context §23). Maximum payload is therefore 0xFFFFFF (16 MiB).
/// </summary>
public static class NbssFrame
{
    /// <summary>Length of the NBSS prefix in bytes.</summary>
    public const int HeaderLength = 4;

    /// <summary>Message type for a regular session message.</summary>
    public const byte SessionMessageType = 0x00;

    /// <summary>Maximum payload length (24 bit).</summary>
    public const int MaxPayloadLength = 0xFFFFFF;

    /// <summary>Reads the payload length from a 4-byte prefix.</summary>
    /// <exception cref="ArgumentException">If fewer than 4 bytes are present.</exception>
    public static int ReadLength(ReadOnlySpan<byte> header)
    {
        if (header.Length < HeaderLength)
            throw new ArgumentException("NBSS prefix requires at least 4 bytes.", nameof(header));
        // Byte 0 = type (ignored for the length calculation), bytes 1..3 = 24-bit big-endian.
        return (header[1] << 16) | (header[2] << 8) | header[3];
    }

    /// <summary>Reads the message type (byte 0).</summary>
    public static byte ReadMessageType(ReadOnlySpan<byte> header)
    {
        if (header.Length < HeaderLength)
            throw new ArgumentException("NBSS prefix requires at least 4 bytes.", nameof(header));
        return header[0];
    }

    /// <summary>Writes a 4-byte prefix for a payload of the given length.</summary>
    public static void WriteHeader(Span<byte> destination, int payloadLength)
    {
        if (destination.Length < HeaderLength)
            throw new ArgumentException("Destination requires at least 4 bytes.", nameof(destination));
        if ((uint)payloadLength > MaxPayloadLength)
            throw new ArgumentOutOfRangeException(nameof(payloadLength),
                $"NBSS payload must be at most {MaxPayloadLength} bytes.");

        destination[0] = SessionMessageType;
        destination[1] = (byte)((payloadLength >> 16) & 0xFF);
        destination[2] = (byte)((payloadLength >> 8) & 0xFF);
        destination[3] = (byte)(payloadLength & 0xFF);
    }

    /// <summary>Wraps an SMB2 message into a complete NBSS frame (prefix + payload).</summary>
    public static byte[] Wrap(ReadOnlySpan<byte> payload)
    {
        var frame = new byte[HeaderLength + payload.Length];
        WriteHeader(frame, payload.Length);
        payload.CopyTo(frame.AsSpan(HeaderLength));
        return frame;
    }
}
