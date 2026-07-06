using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// Typed view of the lease CREATE context ("RqLs", MS-SMB2 §2.2.13.2.8 for V1 / §2.2.13.2.10 for
/// V2). The two versions are distinguished by data length: V1 is 32 bytes, V2 is 52 bytes (adding
/// <c>ParentLeaseKey</c> and <c>Epoch</c> for directory leasing). Parsing accepts both; the
/// response context is written back with the same version via <see cref="SerializeResponse"/>.
/// </summary>
public sealed class LeaseRequest
{
    public const int V1Size = 32;
    public const int V2Size = 52;

    public required LeaseKey Key { get; init; }
    public required LeaseState RequestedState { get; init; }
    public LeaseFlags Flags { get; init; }

    /// <summary>Parent directory lease key (V2 only; valid when <see cref="LeaseFlags.ParentLeaseKeySet"/>).</summary>
    public LeaseKey ParentKey { get; init; }

    /// <summary>Client lease epoch (V2 only; used to order lease state changes, §2.2.13.2.10).</summary>
    public ushort Epoch { get; init; }

    /// <summary>True if this is a lease-V2 request (52-byte context, directory-lease capable).</summary>
    public bool IsV2 { get; init; }

    /// <summary>
    /// Parses the lease context <b>data</b> (the blob after the context header). Length 32 → V1,
    /// length 52 → V2; anything else is rejected as malformed.
    /// </summary>
    public static LeaseRequest ParseData(ReadOnlySpan<byte> data)
    {
        if (data.Length is not (V1Size or V2Size))
            throw new SmbWireFormatException($"Lease context data length {data.Length} ∉ {{{V1Size}, {V2Size}}}.");

        bool isV2 = data.Length == V2Size;
        var r = new SpanReader(data);

        LeaseKey key = LeaseKey.From(r.ReadBytes(LeaseKey.Size));
        var state = (LeaseState)r.ReadUInt32();
        var flags = (LeaseFlags)r.ReadUInt32();
        r.ReadUInt64();   // LeaseDuration — reserved, must be 0.

        LeaseKey parent = default;
        ushort epoch = 0;
        if (isV2)
        {
            parent = LeaseKey.From(r.ReadBytes(LeaseKey.Size));
            epoch = r.ReadUInt16();
            r.ReadUInt16();   // Reserved
        }

        return new LeaseRequest
        {
            Key = key,
            RequestedState = state,
            Flags = flags,
            ParentKey = parent,
            Epoch = epoch,
            IsV2 = isV2,
        };
    }

    /// <summary>
    /// Serializes the lease response context <b>data</b> that echoes the granted state back to the
    /// client (§2.2.13.2.8/§2.2.13.2.10). The version (V1/V2) mirrors the request so the client
    /// parses it with the same layout it sent.
    /// </summary>
    public byte[] SerializeResponse(LeaseState grantedState, ushort grantedEpoch, LeaseFlags flags = LeaseFlags.None)
    {
        var body = new byte[IsV2 ? V2Size : V1Size];
        var w = new SpanWriter(body);

        w.WriteBytes(Key.ToBytes());
        w.WriteUInt32((uint)grantedState);
        w.WriteUInt32((uint)flags);
        w.WriteUInt64(0);   // LeaseDuration

        if (IsV2)
        {
            w.WriteBytes(ParentKey.ToBytes());
            w.WriteUInt16(grantedEpoch);
            w.WriteUInt16(0);   // Reserved
        }
        return body;
    }

    /// <summary>Convenience: parse the lease request from a raw <see cref="CreateContext"/>.</summary>
    public static LeaseRequest FromContext(CreateContext context) => ParseData(context.Data);
}
