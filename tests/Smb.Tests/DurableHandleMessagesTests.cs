using Smb.Protocol.Messages;
using Xunit;

namespace Smb.Tests;

/// <summary>Phase 4 / M4.1–M4.2 — durable-handle CREATE context parse/serialize (pure protocol layer).</summary>
public class DurableHandleMessagesTests
{
    [Fact]
    public void V1Reconnect_FileId_RoundTrips()
    {
        byte[] data = DurableHandleMessages.BuildReconnectData(0x8000_0000_0000_0007UL, 0x42UL);
        (ulong persistent, ulong vol) = DurableHandleMessages.ParseReconnect(data);
        Assert.Equal(0x8000_0000_0000_0007UL, persistent);
        Assert.Equal(0x42UL, vol);
    }

    [Fact]
    public void V1ResponseContext_HasName_And8ByteData()
    {
        CreateContext ctx = DurableHandleMessages.BuildV1ResponseContext();
        Assert.Equal(CreateContextNames.DurableHandleRequest, ctx.Tag);
        Assert.Equal(8, ctx.Data.Length);
    }

    [Fact]
    public void V2Request_RoundTrips_WithPersistentFlag()
    {
        var guid = Guid.NewGuid();
        byte[] data = DurableHandleMessages.BuildV2RequestData(timeoutMs: 30_000, createGuid: guid, persistent: true);

        DurableHandleMessages.V2Request parsed = DurableHandleMessages.ParseV2Request(data);
        Assert.Equal(30_000u, parsed.TimeoutMs);
        Assert.Equal(guid, parsed.CreateGuid);
        Assert.True(parsed.IsPersistent);
    }

    [Fact]
    public void V2Reconnect_RoundTrips()
    {
        var guid = Guid.NewGuid();
        byte[] data = DurableHandleMessages.BuildV2ReconnectData(
            persistentId: 0x8000_0000_0000_0001UL, volatileId: 9, createGuid: guid, persistent: false);

        DurableHandleMessages.V2Reconnect parsed = DurableHandleMessages.ParseV2Reconnect(data);
        Assert.Equal(0x8000_0000_0000_0001UL, parsed.PersistentId);
        Assert.Equal(9UL, parsed.VolatileId);
        Assert.Equal(guid, parsed.CreateGuid);
        Assert.False(parsed.IsPersistent);
    }

    [Fact]
    public void V2ResponseContext_CarriesTimeoutAndFlag()
    {
        CreateContext ctx = DurableHandleMessages.BuildV2ResponseContext(timeoutMs: 45_000, persistent: true);
        Assert.Equal(CreateContextNames.DurableHandleRequestV2, ctx.Tag);
        Assert.Equal(8, ctx.Data.Length);
        Assert.Equal(45_000u, System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(ctx.Data));
        Assert.Equal(DurableHandleMessages.FlagPersistent,
            System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(ctx.Data.AsSpan(4)));
    }

    [Fact]
    public void ParseReconnect_TooShort_Throws()
        => Assert.Throws<Smb.Protocol.Wire.SmbWireFormatException>(() => DurableHandleMessages.ParseReconnect(new byte[8]));
}
