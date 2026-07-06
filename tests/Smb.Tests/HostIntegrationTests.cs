using System.Net;
using System.Net.Sockets;
using Smb.FileSystem;
using Smb.Host;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Xunit;

namespace Smb.Tests;

public class HostIntegrationTests
{
    [Fact]
    public async Task Server_AcceptsTcpConnection_AndAnswersNegotiateOverNbss()
    {
        await using var server = SmbServerBuilder.Create()
            .WithEndpoint(IPAddress.Loopback, 0) // ephemerer Port
            .UseDevAuthentication()
            .AddShare(new Share { Name = "Data", Type = ShareType.Disk })
            .Build();

        await server.StartAsync();
        int port = server.Endpoint.Port;

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        await using NetworkStream stream = client.GetStream();

        // NEGOTIATE senden (NBSS-gerahmt).
        byte[] negotiate = TestHelpers.BuildNegotiateRequest(
            [SmbDialect.Smb210, SmbDialect.Smb300, SmbDialect.Smb311],
            ciphers: [SmbCipherId.Aes128Gcm]);
        byte[] framed = NbssFrame.Wrap(negotiate);
        await stream.WriteAsync(framed);
        await stream.FlushAsync();

        // Read the response.
        var prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix);
        int length = NbssFrame.ReadLength(prefix);
        Assert.True(length is > 0 and < 65536);

        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload);

        Smb2Header header = Smb2Header.Read(payload);
        Assert.Equal(SmbCommand.Negotiate, header.Command);
        Assert.Equal(NtStatus.Success, header.Status);
        Assert.True(header.Flags.HasFlag(Smb2HeaderFlags.ServerToRedir));

        await server.StopAsync();
    }

    [Fact]
    public async Task Server_EnsuresIpcShareExists()
    {
        await using var server = SmbServerBuilder.Create()
            .WithEndpoint(IPAddress.Loopback, 0)
            .UseDevAuthentication()
            .Build();

        Assert.True(server.State.Shares.Contains("IPC$"));
    }
}
