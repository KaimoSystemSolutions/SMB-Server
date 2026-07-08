using System.Collections.Concurrent;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Host;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 8 / M8.4 — graceful shutdown &amp; connection draining: caching holders are notified before
/// their handles close (<see cref="Smb2Dispatcher.SendShutdownBreaksAsync"/>), and a graceful
/// <see cref="SmbServer.StopAsync(System.TimeSpan?)"/> drains an idle connection and closes it.
/// </summary>
public class ShutdownDrainTests : IDisposable
{
    private readonly string _dir;

    public ShutdownDrainTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "smbdrain_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { /* ignore */ }
    }

    [Fact]
    public async Task SendShutdownBreaks_NotifiesOplockHolder()
    {
        var (d, conn, sid, tid) = Setup();
        File.WriteAllBytes(Path.Combine(_dir, "doc.txt"), new byte[8]);

        var sent = new ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        // Solo open with a Batch oplock (granted without a break).
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            10, sid, tid, "doc.txt", 0x00000003, (uint)CreateDisposition.Open,
            (uint)CreateOptions.NonDirectoryFile, requestedOplockLevel: (byte)OplockLevel.Batch));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        Assert.Empty(sent);

        await d.SendShutdownBreaksAsync();

        Assert.True(sent.TryDequeue(out byte[]? brk));
        Smb2Header h = Smb2Header.Read(brk!);
        Assert.Equal(SmbCommand.OplockBreak, h.Command);
        Assert.Equal((byte)OplockLevel.None, brk![Smb2Header.Size + 2]); // broken to None
    }

    [Fact]
    public async Task GracefulStop_DrainsIdleConnection_AndCloses()
    {
        await using var server = SmbServerBuilder.Create()
            .WithEndpoint(IPAddress.Loopback, 0)
            .UseDevAuthentication()
            .AddShare(new Share { Name = "Data", Type = ShareType.Disk })
            .Build();

        await server.StartAsync();
        int port = server.Endpoint.Port;

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        await using NetworkStream stream = client.GetStream();

        // Complete a NEGOTIATE so the connection is fully live, then leave it idle.
        await stream.WriteAsync(NbssFrame.Wrap(TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311])));
        await stream.FlushAsync();
        var prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix);
        await stream.ReadExactlyAsync(new byte[NbssFrame.ReadLength(prefix)]);

        // Graceful stop must return promptly (idle connection has no in-flight work) and close the socket.
        Task stop = server.StopAsync(TimeSpan.FromSeconds(5));
        Assert.Same(stop, await Task.WhenAny(stop, Task.Delay(TimeSpan.FromSeconds(10))));
        await stop;

        // The server closed the connection → the client sees EOF (read returns 0).
        using var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        int n = await stream.ReadAsync(new byte[1], readCts.Token);
        Assert.Equal(0, n);
    }

    // --- helpers ---

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) Setup()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_dir, readOnly: false) });

        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();

        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
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
