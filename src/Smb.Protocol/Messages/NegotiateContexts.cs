using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// Negotiate contexts (SMB 3.1.1 only, Context §6.4, MS-SMB2 §2.2.3.1/§2.2.4.1).
/// Each context: ContextType(2) ‖ DataLength(2) ‖ Reserved(4) ‖ Data; contexts are aligned to an
/// 8-byte boundary between one another (the padding does not count toward DataLength).
/// </summary>
public abstract class NegotiateContext
{
    /// <summary>Header size of a context (ContextType+DataLength+Reserved) without Data.</summary>
    public const int HeaderSize = 8;

    public abstract NegotiateContextType Type { get; }

    /// <summary>Serializes only the data part (without the 8-byte context header).</summary>
    protected abstract void WriteData(GrowableWriter w);

    /// <summary>Writes the context header + data into <paramref name="w"/> (without trailing padding).</summary>
    public void Write(GrowableWriter w)
    {
        int typePos = w.Position;
        w.WriteUInt16((ushort)Type);
        w.WriteUInt16(0);   // DataLength – patched below
        w.WriteUInt32(0);   // Reserved
        int dataStart = w.Position;
        WriteData(w);
        int dataLen = w.Position - dataStart;
        w.PatchUInt16(typePos + 2, (ushort)dataLen);
    }

    /// <summary>Reads a context (header + data) and reports the total length without padding via <paramref name="consumed"/>.</summary>
    public static NegotiateContext Read(ReadOnlySpan<byte> buffer, out int consumed)
    {
        var r = new SpanReader(buffer);
        var type = (NegotiateContextType)r.ReadUInt16();
        int dataLength = r.ReadUInt16();
        r.Skip(4); // Reserved
        ReadOnlySpan<byte> data = r.ReadBytes(dataLength);
        consumed = HeaderSize + dataLength;

        return type switch
        {
            NegotiateContextType.PreauthIntegrityCapabilities => PreauthIntegrityContext.ParseData(data),
            NegotiateContextType.EncryptionCapabilities => EncryptionContext.ParseData(data),
            NegotiateContextType.SigningCapabilities => SigningContext.ParseData(data),
            NegotiateContextType.CompressionCapabilities => CompressionContext.ParseData(data),
            NegotiateContextType.NetnameNegotiateContextId => NetnameContext.ParseData(data),
            _ => new UnknownNegotiateContext(type, data.ToArray()),
        };
    }
}

/// <summary>PREAUTH_INTEGRITY_CAPABILITIES (0x0001) — mandatory for 3.1.1.</summary>
public sealed class PreauthIntegrityContext : NegotiateContext
{
    public override NegotiateContextType Type => NegotiateContextType.PreauthIntegrityCapabilities;

    public IReadOnlyList<PreauthHashAlgorithm> HashAlgorithms { get; init; } = [PreauthHashAlgorithm.Sha512];
    public byte[] Salt { get; init; } = [];

    protected override void WriteData(GrowableWriter w)
    {
        w.WriteUInt16((ushort)HashAlgorithms.Count);
        w.WriteUInt16((ushort)Salt.Length);
        foreach (var alg in HashAlgorithms) w.WriteUInt16((ushort)alg);
        w.WriteBytes(Salt);
    }

    public static PreauthIntegrityContext ParseData(ReadOnlySpan<byte> data)
    {
        var r = new SpanReader(data);
        int count = r.ReadUInt16();
        int saltLen = r.ReadUInt16();
        var algs = new PreauthHashAlgorithm[count];
        for (int i = 0; i < count; i++) algs[i] = (PreauthHashAlgorithm)r.ReadUInt16();
        byte[] salt = r.ReadByteArray(saltLen);
        return new PreauthIntegrityContext { HashAlgorithms = algs, Salt = salt };
    }
}

/// <summary>ENCRYPTION_CAPABILITIES (0x0002) — cipher list in preference order.</summary>
public sealed class EncryptionContext : NegotiateContext
{
    public override NegotiateContextType Type => NegotiateContextType.EncryptionCapabilities;

    public IReadOnlyList<SmbCipherId> Ciphers { get; init; } = [];

    protected override void WriteData(GrowableWriter w)
    {
        w.WriteUInt16((ushort)Ciphers.Count);
        foreach (var c in Ciphers) w.WriteUInt16((ushort)c);
    }

    public static EncryptionContext ParseData(ReadOnlySpan<byte> data)
    {
        var r = new SpanReader(data);
        int count = r.ReadUInt16();
        var ciphers = new SmbCipherId[count];
        for (int i = 0; i < count; i++) ciphers[i] = (SmbCipherId)r.ReadUInt16();
        return new EncryptionContext { Ciphers = ciphers };
    }
}

/// <summary>SIGNING_CAPABILITIES (0x0008) — signing algorithms in preference order.</summary>
public sealed class SigningContext : NegotiateContext
{
    public override NegotiateContextType Type => NegotiateContextType.SigningCapabilities;

    public IReadOnlyList<SmbSigningAlgorithmId> Algorithms { get; init; } = [];

    protected override void WriteData(GrowableWriter w)
    {
        w.WriteUInt16((ushort)Algorithms.Count);
        foreach (var a in Algorithms) w.WriteUInt16((ushort)a);
    }

    public static SigningContext ParseData(ReadOnlySpan<byte> data)
    {
        var r = new SpanReader(data);
        int count = r.ReadUInt16();
        var algs = new SmbSigningAlgorithmId[count];
        for (int i = 0; i < count; i++) algs[i] = (SmbSigningAlgorithmId)r.ReadUInt16();
        return new SigningContext { Algorithms = algs };
    }
}

/// <summary>COMPRESSION_CAPABILITIES (0x0003) — phase ≥2 (parse/echo only).</summary>
public sealed class CompressionContext : NegotiateContext
{
    public override NegotiateContextType Type => NegotiateContextType.CompressionCapabilities;

    public uint Flags { get; init; }
    public IReadOnlyList<SmbCompressionAlgorithm> Algorithms { get; init; } = [];

    protected override void WriteData(GrowableWriter w)
    {
        w.WriteUInt16((ushort)Algorithms.Count);
        w.WriteUInt16(0); // Padding
        w.WriteUInt32(Flags);
        foreach (var a in Algorithms) w.WriteUInt16((ushort)a);
    }

    public static CompressionContext ParseData(ReadOnlySpan<byte> data)
    {
        var r = new SpanReader(data);
        int count = r.ReadUInt16();
        r.Skip(2); // Padding
        uint flags = r.ReadUInt32();
        var algs = new SmbCompressionAlgorithm[count];
        for (int i = 0; i < count; i++) algs[i] = (SmbCompressionAlgorithm)r.ReadUInt16();
        return new CompressionContext { Flags = flags, Algorithms = algs };
    }
}

/// <summary>NETNAME_NEGOTIATE_CONTEXT_ID (0x0005) — target server name (informational, UTF-16LE).</summary>
public sealed class NetnameContext : NegotiateContext
{
    public override NegotiateContextType Type => NegotiateContextType.NetnameNegotiateContextId;

    public string NetName { get; init; } = string.Empty;

    protected override void WriteData(GrowableWriter w) => w.WriteUtf16(NetName);

    public static NetnameContext ParseData(ReadOnlySpan<byte> data)
        => new() { NetName = System.Text.Encoding.Unicode.GetString(data) };
}

/// <summary>Unknown/unhandled context — Data is kept opaque (Context §13.2: ignorable).</summary>
public sealed class UnknownNegotiateContext : NegotiateContext
{
    private readonly NegotiateContextType _type;
    public byte[] Data { get; }

    public UnknownNegotiateContext(NegotiateContextType type, byte[] data)
    {
        _type = type;
        Data = data;
    }

    public override NegotiateContextType Type => _type;
    protected override void WriteData(GrowableWriter w) => w.WriteBytes(Data);
}
