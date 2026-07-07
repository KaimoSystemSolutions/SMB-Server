using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>SMB2 IOCTL Request/Response (Context §14, MS-SMB2 §2.2.31/§2.2.32).</summary>
public static class IoctlMessage
{
    public const ushort RequestStructureSize = 57;
    public const ushort ResponseStructureSize = 49;

    /// <summary>FSCTL_PIPE_TRANSCEIVE — combined write+read on a named pipe (DCERPC).</summary>
    public const uint FsctlPipeTransceive = 0x0011C017;

    /// <summary>FSCTL_VALIDATE_NEGOTIATE_INFO — secure negotiate (3.0/3.0.2, Context §14).</summary>
    public const uint FsctlValidateNegotiateInfo = 0x00140204;

    /// <summary>FSCTL_SRV_ENUMERATE_SNAPSHOTS — list "previous versions" (MS-SMB2 §2.2.31.2/§2.2.32.2).</summary>
    public const uint FsctlSrvEnumerateSnapshots = 0x00144064;

    public const uint FlagIsFsctl = 0x00000001;

    public readonly record struct Request(
        uint CtlCode, ulong PersistentId, ulong VolatileId, uint Flags, byte[] Input, uint MaxOutputResponse);

    public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var r = new SpanReader(message[bodyOffset..]);
        ushort ss = r.ReadUInt16();
        if (ss != RequestStructureSize)
            throw new SmbWireFormatException($"IOCTL Request StructureSize {ss} ≠ {RequestStructureSize}.");
        r.Skip(2);                  // Reserved
        uint ctlCode = r.ReadUInt32();
        ulong persistent = r.ReadUInt64();
        ulong vol = r.ReadUInt64();
        uint inputOffset = r.ReadUInt32();
        uint inputCount = r.ReadUInt32();
        r.ReadUInt32();             // MaxInputResponse
        r.ReadUInt32();             // OutputOffset
        r.ReadUInt32();             // OutputCount
        uint maxOutputResponse = r.ReadUInt32();
        uint flags = r.ReadUInt32();
        r.ReadUInt32();             // Reserved2

        byte[] input = [];
        if (inputCount > 0)
        {
            if (inputOffset + inputCount > message.Length)
                throw new SmbWireFormatException("IOCTL input extends past the message.");
            input = message.Slice((int)inputOffset, (int)inputCount).ToArray();
        }

        return new Request(ctlCode, persistent, vol, flags, input, maxOutputResponse);
    }

    /// <summary>Builds the response. OutputOffset = header(64) + fixed body(48) = 112.</summary>
    public static byte[] BuildResponseBody(uint ctlCode, ulong persistentId, ulong volatileId, ReadOnlySpan<byte> output)
    {
        const uint outputOffset = Smb2Header.Size + 48; // 112
        var body = new byte[48 + output.Length];
        var w = new SpanWriter(body);
        w.WriteUInt16(ResponseStructureSize);
        w.WriteUInt16(0);           // Reserved
        w.WriteUInt32(ctlCode);
        w.WriteUInt64(persistentId);
        w.WriteUInt64(volatileId);
        w.WriteUInt32(0);           // InputOffset
        w.WriteUInt32(0);           // InputCount
        w.WriteUInt32(output.Length > 0 ? outputOffset : 0); // OutputOffset
        w.WriteUInt32((uint)output.Length);
        w.WriteUInt32(0);           // Flags
        w.WriteUInt32(0);           // Reserved2
        w.WriteBytes(output);
        return body;
    }

    /// <summary>Parsed VALIDATE_NEGOTIATE_INFO request (MS-SMB2 §2.2.31.4): the client echoes back
    /// what it sent in NEGOTIATE so the server can prove no attacker downgraded it.</summary>
    public readonly record struct ValidateNegotiateRequest(
        uint Capabilities, byte[] Guid, ushort SecurityMode, ushort[] Dialects);

    /// <summary>Parses a VALIDATE_NEGOTIATE_INFO request input buffer (MS-SMB2 §2.2.31.4).</summary>
    public static ValidateNegotiateRequest ParseValidateNegotiate(ReadOnlySpan<byte> input)
    {
        var r = new SpanReader(input);
        uint capabilities = r.ReadUInt32();
        byte[] guid = r.ReadByteArray(16);
        ushort securityMode = r.ReadUInt16();
        ushort dialectCount = r.ReadUInt16();
        var dialects = new ushort[dialectCount];
        for (int i = 0; i < dialectCount; i++)
            dialects[i] = r.ReadUInt16();
        return new ValidateNegotiateRequest(capabilities, guid, securityMode, dialects);
    }

    /// <summary>Builds a VALIDATE_NEGOTIATE_INFO response (MS-SMB2 §2.2.32.6, fixed 24 bytes).</summary>
    public static byte[] BuildValidateNegotiateResponse(uint capabilities, ReadOnlySpan<byte> serverGuid, ushort securityMode, ushort dialect)
    {
        var body = new byte[24];
        var w = new SpanWriter(body);
        w.WriteUInt32(capabilities);
        w.WriteBytes(serverGuid.Length == 16 ? serverGuid : new byte[16]);
        w.WriteUInt16(securityMode);
        w.WriteUInt16(dialect);
        return body;
    }

    /// <summary>
    /// Builds the <c>SRV_SNAPSHOT_ARRAY</c> payload (MS-SMB2 §2.2.32.2) for
    /// FSCTL_SRV_ENUMERATE_SNAPSHOTS from already-formatted <c>@GMT-…</c> tokens.
    /// If the array does not fit in <paramref name="maxOutputResponse"/>, only the counters and the
    /// required size are reported (Returned=0) so the client retries with a larger buffer.
    /// </summary>
    public static byte[] BuildEnumerateSnapshotsResponse(IReadOnlyList<string> gmtTokens, uint maxOutputResponse)
    {
        // Array: one null-terminated UTF-16LE string per token, plus a trailing double null.
        var array = new List<byte>();
        foreach (string token in gmtTokens)
        {
            array.AddRange(System.Text.Encoding.Unicode.GetBytes(token));
            array.Add(0); array.Add(0);
        }
        array.Add(0); array.Add(0); // SnapshotArray terminator

        uint numberOfSnapshots = (uint)gmtTokens.Count;
        uint arraySize = (uint)array.Count;
        bool fits = 12u + arraySize <= maxOutputResponse;

        byte[] arrayBytes = fits ? [.. array] : [];
        uint returned = fits ? numberOfSnapshots : 0;

        var body = new byte[12 + arrayBytes.Length];
        var w = new SpanWriter(body);
        w.WriteUInt32(numberOfSnapshots);
        w.WriteUInt32(returned);
        w.WriteUInt32(arraySize);   // required array size (even if the buffer was too small)
        w.WriteBytes(arrayBytes);
        return body;
    }
}
