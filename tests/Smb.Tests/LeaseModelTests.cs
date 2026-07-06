using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;
using Smb.Server.Leases;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 1 / M1.1 — lease state model. Covers the protocol layer (lease key value semantics,
/// CREATE-context chain parse/serialize round-trips, lease V1/V2 context parsing) and the
/// <see cref="InMemoryLeaseManager"/> policy (solo grant, multi-key downgrade, acknowledgment,
/// release). No dispatcher wiring yet — that is M1.2.
/// </summary>
public class LeaseModelTests
{
    // --- LeaseKey value semantics ---

    [Fact]
    public void LeaseKey_RoundTripsThroughBytes_AndComparesByValue()
    {
        byte[] raw = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        LeaseKey a = LeaseKey.From(raw);
        LeaseKey b = LeaseKey.From(raw);

        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.Equal(raw, a.ToBytes());
        Assert.False(a.IsZero);
        Assert.True(default(LeaseKey).IsZero);
    }

    [Fact]
    public void LeaseKey_DifferentBytes_AreNotEqual()
    {
        LeaseKey a = LeaseKey.From(new byte[16]);
        var other = new byte[16];
        other[15] = 1;
        Assert.NotEqual(a, LeaseKey.From(other));
    }

    // --- Lease CREATE context parse/serialize ---

    [Fact]
    public void LeaseContext_V1_ParsesAllFields()
    {
        byte[] key = Fill(0xAA, 16);
        byte[] data = BuildLeaseV1(key, LeaseState.ReadWriteHandle);

        LeaseRequest req = LeaseRequest.ParseData(data);

        Assert.False(req.IsV2);
        Assert.Equal(LeaseKey.From(key), req.Key);
        Assert.Equal(LeaseState.ReadWriteHandle, req.RequestedState);
    }

    [Fact]
    public void LeaseContext_V2_ParsesParentKeyAndEpoch()
    {
        byte[] key = Fill(0x11, 16);
        byte[] parent = Fill(0x22, 16);
        byte[] data = BuildLeaseV2(key, LeaseState.Read, parent, epoch: 7, LeaseFlags.ParentLeaseKeySet);

        LeaseRequest req = LeaseRequest.ParseData(data);

        Assert.True(req.IsV2);
        Assert.Equal(LeaseKey.From(key), req.Key);
        Assert.Equal(LeaseKey.From(parent), req.ParentKey);
        Assert.Equal((ushort)7, req.Epoch);
        Assert.Equal(LeaseState.Read, req.RequestedState);
        Assert.True(req.Flags.HasFlag(LeaseFlags.ParentLeaseKeySet));
    }

    [Fact]
    public void LeaseContext_InvalidLength_Throws()
        => Assert.Throws<SmbWireFormatException>(() => LeaseRequest.ParseData(new byte[40]));

    [Fact]
    public void LeaseContext_SerializeResponse_RoundTripsThroughParse()
    {
        byte[] key = Fill(0x33, 16);
        LeaseRequest req = LeaseRequest.ParseData(BuildLeaseV2(key, LeaseState.ReadWriteHandle, Fill(0, 16), 3, LeaseFlags.None));

        byte[] responseData = req.SerializeResponse(LeaseState.Read, grantedEpoch: 4);
        LeaseRequest reparsed = LeaseRequest.ParseData(responseData);

        Assert.True(reparsed.IsV2);
        Assert.Equal(req.Key, reparsed.Key);
        Assert.Equal(LeaseState.Read, reparsed.RequestedState);
        Assert.Equal((ushort)4, reparsed.Epoch);
    }

    // --- Generic CREATE-context chain ---

    [Fact]
    public void CreateContextChain_SerializeThenParse_PreservesEntries()
    {
        var contexts = new List<CreateContext>
        {
            new() { Name = TagBytes(CreateContextNames.MaximalAccess), Data = new byte[] { 1, 2, 3, 4 } },
            new() { Name = TagBytes(CreateContextNames.Lease), Data = BuildLeaseV1(Fill(0x5A, 16), LeaseState.ReadHandle) },
        };

        byte[] blob = CreateContextList.Serialize(contexts);
        IReadOnlyList<CreateContext> parsed = CreateContextList.Parse(blob, 0, blob.Length);

        Assert.Equal(2, parsed.Count);
        Assert.Equal(CreateContextNames.MaximalAccess, parsed[0].Tag);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, parsed[0].Data);

        CreateContext? lease = CreateContextList.Find(parsed, CreateContextNames.Lease);
        Assert.NotNull(lease);
        LeaseRequest req = LeaseRequest.FromContext(lease!);
        Assert.Equal(LeaseState.ReadHandle, req.RequestedState);
    }

    [Fact]
    public void CreateContextChain_EmptyOrZeroRange_YieldsEmptyList()
    {
        Assert.Empty(CreateContextList.Parse(ReadOnlySpan<byte>.Empty, 0, 0));
        Assert.Empty(CreateContextList.Serialize(Array.Empty<CreateContext>()));
    }

    // --- InMemoryLeaseManager policy ---

    [Theory]
    [InlineData(LeaseState.Read)]
    [InlineData(LeaseState.ReadWrite)]
    [InlineData(LeaseState.ReadWriteHandle)]
    public void SoloOpen_GrantsFullRequestedState(LeaseState requested)
    {
        var mgr = new InMemoryLeaseManager();
        SmbOpen open = OpenFor("file1");
        LeaseKey key = LeaseKey.From(Fill(0x01, 16));

        LeaseGrant grant = mgr.RequestLease(open, LeaseReq(key, requested));

        Assert.Equal(requested, grant.GrantedState);
        Assert.Empty(grant.Breaks);
    }

    [Fact]
    public void ZeroLeaseKey_GrantsNothing()
    {
        var mgr = new InMemoryLeaseManager();
        LeaseGrant grant = mgr.RequestLease(OpenFor("f"), LeaseReq(default, LeaseState.ReadWriteHandle));
        Assert.Equal(LeaseState.None, grant.GrantedState);
    }

    [Fact]
    public void SecondDistinctKey_BreaksFirstToRead_AndGrantsReadToSecond()
    {
        var mgr = new InMemoryLeaseManager();
        SmbOpen first = OpenFor("shared");
        SmbOpen second = OpenFor("shared");
        LeaseKey k1 = LeaseKey.From(Fill(0x01, 16));
        LeaseKey k2 = LeaseKey.From(Fill(0x02, 16));

        LeaseGrant g1 = mgr.RequestLease(first, LeaseReq(k1, LeaseState.ReadWriteHandle));
        Assert.Equal(LeaseState.ReadWriteHandle, g1.GrantedState);

        LeaseGrant g2 = mgr.RequestLease(second, LeaseReq(k2, LeaseState.ReadWriteHandle));

        // Second open receives shared read caching only.
        Assert.Equal(LeaseState.Read, g2.GrantedState);
        // The first lease is broken down to Read.
        LeaseBreak brk = Assert.Single(g2.Breaks);
        Assert.Equal(k1, brk.Key);
        Assert.Equal(LeaseState.ReadWriteHandle, brk.FromState);
        Assert.Equal(LeaseState.Read, brk.ToState);
        Assert.Same(first, brk.Holder);
        Assert.True(brk.Epoch > 0);
    }

    [Fact]
    public void SecondOpen_SameKey_SharesLease_NoBreak()
    {
        var mgr = new InMemoryLeaseManager();
        SmbOpen a = OpenFor("same");
        SmbOpen b = OpenFor("same");
        LeaseKey key = LeaseKey.From(Fill(0x09, 16));

        mgr.RequestLease(a, LeaseReq(key, LeaseState.ReadWriteHandle));
        LeaseGrant g = mgr.RequestLease(b, LeaseReq(key, LeaseState.ReadWriteHandle));

        // Same client key on the same file → keeps full caching, no break.
        Assert.Equal(LeaseState.ReadWriteHandle, g.GrantedState);
        Assert.Empty(g.Breaks);
    }

    [Fact]
    public void Acknowledge_DowngradesLeaseState()
    {
        var mgr = new InMemoryLeaseManager();
        SmbOpen open = OpenFor("ackfile");
        LeaseKey key = LeaseKey.From(Fill(0x0A, 16));
        mgr.RequestLease(open, LeaseReq(key, LeaseState.ReadWriteHandle));

        LeaseState now = mgr.Acknowledge(key, LeaseState.Read);
        Assert.Equal(LeaseState.Read, now);
    }

    [Fact]
    public void Acknowledge_UnknownKey_ReturnsNone()
        => Assert.Equal(LeaseState.None, new InMemoryLeaseManager().Acknowledge(LeaseKey.From(Fill(0x7F, 16)), LeaseState.Read));

    [Fact]
    public void ReleaseOwner_LastOpen_LetsNextSoloOpenGetFullLeaseAgain()
    {
        var mgr = new InMemoryLeaseManager();
        SmbOpen first = OpenFor("rel");
        SmbOpen second = OpenFor("rel");
        LeaseKey k1 = LeaseKey.From(Fill(0x01, 16));
        LeaseKey k2 = LeaseKey.From(Fill(0x02, 16));

        mgr.RequestLease(first, LeaseReq(k1, LeaseState.ReadWriteHandle));
        mgr.ReleaseOwner(first);   // file has no leases anymore

        // A fresh distinct key on the now-empty file is solo again → full grant, no break.
        LeaseGrant g = mgr.RequestLease(second, LeaseReq(k2, LeaseState.ReadWriteHandle));
        Assert.Equal(LeaseState.ReadWriteHandle, g.GrantedState);
        Assert.Empty(g.Breaks);
    }

    [Fact]
    public void ReleaseOwner_SharedKey_KeepsLeaseUntilLastOpenGone()
    {
        var mgr = new InMemoryLeaseManager();
        SmbOpen a = OpenFor("multi");
        SmbOpen b = OpenFor("multi");
        SmbOpen intruder = OpenFor("multi");
        LeaseKey key = LeaseKey.From(Fill(0x33, 16));
        LeaseKey other = LeaseKey.From(Fill(0x44, 16));

        mgr.RequestLease(a, LeaseReq(key, LeaseState.ReadWriteHandle));
        mgr.RequestLease(b, LeaseReq(key, LeaseState.ReadWriteHandle));
        mgr.ReleaseOwner(a);   // lease still held by b

        // A distinct key must still see the lease (held by b) and break it.
        LeaseGrant g = mgr.RequestLease(intruder, LeaseReq(other, LeaseState.ReadWriteHandle));
        Assert.Single(g.Breaks);
        Assert.Equal(key, g.Breaks[0].Key);
    }

    // --- NullLeaseManager (leasing disabled) ---

    [Fact]
    public void NullLeaseManager_NeverGrantsALease_AndReportsNoBreaks()
    {
        var mgr = new NullLeaseManager();
        SmbOpen open = OpenFor("nolease");
        LeaseKey key = LeaseKey.From(Fill(0x55, 16));

        LeaseGrant grant = mgr.RequestLease(open, LeaseReq(key, LeaseState.ReadWriteHandle));

        Assert.Equal(LeaseState.None, grant.GrantedState);
        Assert.Empty(grant.Breaks);
    }

    [Fact]
    public void NullLeaseManager_AcknowledgeReturnsNone_AndReleaseIsNoOp()
    {
        var mgr = new NullLeaseManager();
        LeaseKey key = LeaseKey.From(Fill(0x55, 16));

        Assert.Equal(LeaseState.None, mgr.Acknowledge(key, LeaseState.Read));
        mgr.ReleaseOwner(OpenFor("nolease"));   // must not throw
    }

    // --- helpers ---

    private static LeaseRequest LeaseReq(LeaseKey key, LeaseState state, bool v2 = false, ushort epoch = 0) => new()
    {
        Key = key,
        RequestedState = state,
        IsV2 = v2,
        Epoch = epoch,
    };

    /// <summary>A minimally-populated open bound to a logical path used as the lease file key.</summary>
    private static SmbOpen OpenFor(string path) => new()
    {
        PersistentFileId = 0,
        VolatileFileId = 0,
        Session = null!,
        TreeConnect = null!,
        PathName = path,
    };

    private static byte[] Fill(byte value, int count)
    {
        var b = new byte[count];
        Array.Fill(b, value);
        return b;
    }

    private static byte[] TagBytes(uint tag)
    {
        var b = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(b, tag);
        return b;
    }

    private static byte[] BuildLeaseV1(byte[] key16, LeaseState state)
    {
        var data = new byte[LeaseRequest.V1Size];
        var w = new SpanWriter(data);
        w.WriteBytes(key16);
        w.WriteUInt32((uint)state);
        w.WriteUInt32(0);   // flags
        w.WriteUInt64(0);   // duration
        return data;
    }

    private static byte[] BuildLeaseV2(byte[] key16, LeaseState state, byte[] parent16, ushort epoch, LeaseFlags flags)
    {
        var data = new byte[LeaseRequest.V2Size];
        var w = new SpanWriter(data);
        w.WriteBytes(key16);
        w.WriteUInt32((uint)state);
        w.WriteUInt32((uint)flags);
        w.WriteUInt64(0);   // duration
        w.WriteBytes(parent16);
        w.WriteUInt16(epoch);
        w.WriteUInt16(0);   // reserved
        return data;
    }
}
