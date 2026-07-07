using System.Buffers.Binary;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 5 / M5.3 — FSCTL_VALIDATE_NEGOTIATE_INFO hardening (MS-SMB2 §3.3.5.15.12): the client
/// re-sends the NEGOTIATE parameters so the server can detect a man-in-the-middle downgrade. A match
/// returns the server's negotiated values; any mismatch tears the connection down without a reply.
/// </summary>
public class ValidateNegotiateTests : IDisposable
{
    private readonly string _dir;
    private ulong _mid = 10;

    private ulong NextMid() => _mid++;

    public ValidateNegotiateTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "smbvn_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void ValidateNegotiate_RoundTripsWire()
    {
        byte[] guid = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        byte[] input = BuildInput(0x40, guid, 0x02, [(ushort)SmbDialect.Smb300, (ushort)SmbDialect.Smb302]);

        IoctlMessage.ValidateNegotiateRequest req = IoctlMessage.ParseValidateNegotiate(input);
        Assert.Equal(0x40u, req.Capabilities);
        Assert.Equal(guid, req.Guid);
        Assert.Equal(0x02, req.SecurityMode);
        Assert.Equal([(ushort)SmbDialect.Smb300, (ushort)SmbDialect.Smb302], req.Dialects);

        byte[] resp = IoctlMessage.BuildValidateNegotiateResponse(0x40, guid, 0x02, (ushort)SmbDialect.Smb302);
        Assert.Equal(24, resp.Length);
        Assert.Equal((ushort)SmbDialect.Smb302, BinaryPrimitives.ReadUInt16LittleEndian(resp.AsSpan(22, 2)));
    }

    [Fact]
    public void MatchingParameters_ReturnsServerInfo()
    {
        var (d, conn, sid, tid) = Setup();
        byte[] input = BuildInput((uint)conn.ClientCapabilities, conn.ClientGuid,
            (ushort)conn.ClientSecurityMode, [(ushort)conn.Dialect]);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            NextMid(), sid, tid, 0, 0, IoctlMessage.FsctlValidateNegotiateInfo, input));

        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        Assert.False(conn.MustTerminate);

        byte[] output = IoctlOutput(resp);
        Assert.Equal(24, output.Length);
        Assert.Equal((uint)conn.ServerCapabilities, BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(0, 4)));
        Assert.Equal((ushort)conn.ServerSecurityMode, BinaryPrimitives.ReadUInt16LittleEndian(output.AsSpan(20, 2)));
        Assert.Equal((ushort)conn.Dialect, BinaryPrimitives.ReadUInt16LittleEndian(output.AsSpan(22, 2)));
    }

    [Fact]
    public void TamperedCapabilities_TerminatesConnection()
    {
        var (d, conn, sid, tid) = Setup();
        // An attacker stripped a capability the client actually advertised.
        uint tampered = (uint)conn.ClientCapabilities ^ (uint)Smb2Capabilities.LargeMtu;
        byte[] input = BuildInput(tampered, conn.ClientGuid, (ushort)conn.ClientSecurityMode, [(ushort)conn.Dialect]);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            NextMid(), sid, tid, 0, 0, IoctlMessage.FsctlValidateNegotiateInfo, input));

        Assert.Empty(resp);              // no reply — the connection is dropped
        Assert.True(conn.MustTerminate);
    }

    [Fact]
    public void TamperedGuid_TerminatesConnection()
    {
        var (d, conn, sid, tid) = Setup();
        byte[] wrongGuid = (byte[])conn.ClientGuid.Clone();
        wrongGuid[0] ^= 0xFF;
        byte[] input = BuildInput((uint)conn.ClientCapabilities, wrongGuid, (ushort)conn.ClientSecurityMode, [(ushort)conn.Dialect]);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            NextMid(), sid, tid, 0, 0, IoctlMessage.FsctlValidateNegotiateInfo, input));

        Assert.Empty(resp);
        Assert.True(conn.MustTerminate);
    }

    [Fact]
    public void TamperedDialectList_TerminatesConnection()
    {
        var (d, conn, sid, tid) = Setup();
        // A downgraded dialect list resolves to a different dialect than the one negotiated.
        byte[] input = BuildInput((uint)conn.ClientCapabilities, conn.ClientGuid,
            (ushort)conn.ClientSecurityMode, [(ushort)SmbDialect.Smb202]);

        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(
            NextMid(), sid, tid, 0, 0, IoctlMessage.FsctlValidateNegotiateInfo, input));

        Assert.Empty(resp);
        Assert.True(conn.MustTerminate);
    }

    // --- helpers ---

    private static byte[] BuildInput(uint capabilities, byte[] guid, ushort securityMode, ushort[] dialects)
    {
        var w = new GrowableWriter(24 + dialects.Length * 2);
        w.WriteUInt32(capabilities);
        w.WriteBytes(guid);
        w.WriteUInt16(securityMode);
        w.WriteUInt16((ushort)dialects.Length);
        foreach (ushort d in dialects) w.WriteUInt16(d);
        return w.ToArray();
    }

    private static byte[] IoctlOutput(byte[] resp)
    {
        int outputOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 32, 4));
        int outputCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 36, 4));
        return outputCount == 0 ? [] : resp.AsSpan(outputOffset, outputCount).ToArray();
    }

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = Enumerable.Range(100, 16).Select(i => (byte)i).ToArray(),
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_dir, readOnly: false) });

        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();

        // SMB 3.0 — the dialect for which secure negotiate is defined.
        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb300]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        uint treeId = Smb2Header.Read(dispatcher.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\s\Files"))).TreeId;
        return (dispatcher, conn, sessionId, treeId);
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }
}
