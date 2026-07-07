using System.Buffers.Binary;
using System.Net;
using Smb.Auth;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Multichannel;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 6 / M6.2 — FSCTL_QUERY_NETWORK_INTERFACE_INFO (§2.2.32.5): the server advertises its network
/// interfaces so a multichannel client can open additional connections and bind them.
/// </summary>
public class Phase6InterfaceInfoTests
{
    private const uint Fsctl = NetworkInterfaceInfoMessage.FsctlQueryNetworkInterfaceInfo;

    private sealed class FakeProvider(params NetworkInterfaceInfo[] interfaces) : INetworkInterfaceProvider
    {
        public IReadOnlyList<NetworkInterfaceInfo> GetInterfaces() => interfaces;
    }

    private static (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup(
        INetworkInterfaceProvider provider, bool enableMultichannel = true, SmbDialect dialect = SmbDialect.Smb311)
    {
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new DevSpnegoNegotiator(),
            RequireMessageSigning = false,
            AllowAnonymousAccess = true,
            RejectGuestAccess = true,
            NetworkInterfaceProvider = provider,
            EnableMultichannel = enableMultichannel,
        };
        options.Shares.Add(Share.CreateIpc());
        var d = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();

        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([dialect]));
        ulong sid = Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]))).SessionId;
        uint tid = Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\s\IPC$"))).TreeId;
        return (d, conn, sid, tid);
    }

    [Fact]
    public void Query_ReturnsProviderInterfaces_ChainedAndParseable()
    {
        var provider = new FakeProvider(
            new NetworkInterfaceInfo(5, NetworkInterfaceCapability.RssCapable, 10_000_000_000, IPAddress.Parse("192.168.1.10")),
            new NetworkInterfaceInfo(6, NetworkInterfaceCapability.None, 1_000_000_000, IPAddress.Parse("fe80::1")));
        var (d, conn, sid, tid) = Setup(provider);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            3, sid, tid, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, Fsctl, []));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);

        byte[] output = ExtractIoctlOutput(resp);
        Assert.Equal(2 * NetworkInterfaceInfoMessage.EntrySize, output.Length);

        // Entry 0 — IPv4, chained (Next = 152).
        Assert.Equal((uint)NetworkInterfaceInfoMessage.EntrySize, U32(output, 0));       // Next
        Assert.Equal(5u, U32(output, 4));                                                 // IfIndex
        Assert.Equal((uint)NetworkInterfaceCapability.RssCapable, U32(output, 8));        // Capability
        Assert.Equal(10_000_000_000UL, U64(output, 16));                                  // LinkSpeed
        Assert.Equal(0x0002, U16(output, 24));                                            // AF_INET
        Assert.Equal(IPAddress.Parse("192.168.1.10").GetAddressBytes(), output[28..32]);  // sin_addr

        // Entry 1 — IPv6, last (Next = 0).
        int e1 = NetworkInterfaceInfoMessage.EntrySize;
        Assert.Equal(0u, U32(output, e1 + 0));                                            // Next
        Assert.Equal(6u, U32(output, e1 + 4));                                            // IfIndex
        Assert.Equal(0x0017, U16(output, e1 + 24));                                       // AF_INET6
        Assert.Equal(IPAddress.Parse("fe80::1").GetAddressBytes(), output[(e1 + 32)..(e1 + 48)]); // sin6_addr
    }

    [Fact]
    public void Query_EmptyInterfaceList_SucceedsWithEmptyOutput()
    {
        var (d, conn, sid, tid) = Setup(new FakeProvider());
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            3, sid, tid, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, Fsctl, []));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        Assert.Empty(ExtractIoctlOutput(resp));
    }

    [Fact]
    public void Query_WhenMultichannelDisabled_ReturnsNotSupported()
    {
        var (d, conn, sid, tid) = Setup(
            new FakeProvider(new NetworkInterfaceInfo(1, NetworkInterfaceCapability.None, 1_000_000_000, IPAddress.Loopback)),
            enableMultichannel: false);
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            3, sid, tid, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, Fsctl, []));
        Assert.Equal(NtStatus.NotSupported, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void Query_OnSmb2Dialect_ReturnsNotSupported()
    {
        var (d, conn, sid, tid) = Setup(
            new FakeProvider(new NetworkInterfaceInfo(1, NetworkInterfaceCapability.None, 1_000_000_000, IPAddress.Loopback)),
            dialect: SmbDialect.Smb210);
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            3, sid, tid, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, Fsctl, []));
        Assert.Equal(NtStatus.NotSupported, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void Negotiate_AdvertisesMultichannelCapability_OnlyForSmb3()
    {
        var (_, conn3, _, _) = Setup(new FakeProvider(), dialect: SmbDialect.Smb311);
        Assert.True(conn3.ServerCapabilities.HasFlag(Smb2Capabilities.MultiChannel));

        var (_, conn2, _, _) = Setup(new FakeProvider(), dialect: SmbDialect.Smb210);
        Assert.False(conn2.ServerCapabilities.HasFlag(Smb2Capabilities.MultiChannel));
    }

    // ─── helpers ──────────────────────────────────────────────────────────

    private static byte[] ExtractIoctlOutput(byte[] resp)
    {
        int off = (int)U32AbsFromBody(resp, 32); // OutputOffset (absolute from message start)
        int len = (int)U32AbsFromBody(resp, 36); // OutputCount
        return len == 0 ? [] : resp.AsSpan(off, len).ToArray();
    }

    private static uint U32AbsFromBody(byte[] resp, int bodyOffset)
        => BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + bodyOffset, 4));

    private static uint U32(byte[] b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o, 4));
    private static ulong U64(byte[] b, int o) => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o, 8));
    private static ushort U16(byte[] b, int o) => BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(o, 2));
}
