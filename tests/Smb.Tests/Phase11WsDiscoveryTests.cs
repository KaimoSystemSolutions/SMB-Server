using System.Net;
using System.Net.Sockets;
using System.Text;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Host;
using Smb.Protocol.Discovery;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// [M11.3] WS-Discovery (network browsing). A Probe over UDP is answered with a ProbeMatches reply that
/// advertises the server's endpoint, so it appears in Windows Explorer's Network view. The pure
/// <see cref="WsDiscoveryResponder"/> is tested directly; one host-level loopback test drives the real
/// UDP socket end-to-end.
/// </summary>
public class Phase11WsDiscoveryTests
{
    private static readonly Guid Endpoint = Guid.Parse("11111111-2222-3333-4444-555555555555");

    private static byte[] Probe(string messageId, string? typesXml)
    {
        // A representative WS-Discovery 2005/04 Probe envelope (as Windows FDPHost emits).
        string types = typesXml is null ? "" : $"<wsd:Types xmlns:pub=\"http://schemas.microsoft.com/windows/pub/2005/07\">{typesXml}</wsd:Types>";
        string xml =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
            "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" " +
            "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
            "xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">" +
            "<soap:Header>" +
            "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>" +
            "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>" +
            $"<wsa:MessageID>{messageId}</wsa:MessageID>" +
            "</soap:Header>" +
            $"<soap:Body><wsd:Probe>{types}</wsd:Probe></soap:Body>" +
            "</soap:Envelope>";
        return Encoding.UTF8.GetBytes(xml);
    }

    // --- pure parsing / building ---

    [Fact]
    public void ParseProbe_ExtractsMessageIdAndTypes()
    {
        Assert.True(WsDiscoveryMessage.TryParseProbe(Probe("urn:uuid:abc", "pub:Computer"), out WsDiscoveryProbe p));
        Assert.Equal("urn:uuid:abc", p.MessageId);
        Assert.Contains("{http://schemas.microsoft.com/windows/pub/2005/07}Computer", p.Types);
    }

    [Fact]
    public void TryParseProbe_OnNonProbeOrGarbage_ReturnsFalse()
    {
        Assert.False(WsDiscoveryMessage.TryParseProbe(Encoding.UTF8.GetBytes("not xml at all"), out _));
        Assert.False(WsDiscoveryMessage.TryParseProbe([], out _));
        // A well-formed but non-Probe envelope (Hello) is not a probe.
        byte[] hello = WsDiscoveryMessage.BuildHello(Endpoint, [WsDiscoveryQName.Computer], ["http://host"], 1, 1);
        Assert.False(WsDiscoveryMessage.TryParseProbe(hello, out _));
    }

    // --- responder ---

    [Fact]
    public void Responder_MatchingProbe_RepliesWithEndpointAndRelatesTo()
    {
        var responder = new WsDiscoveryResponder(Endpoint, [WsDiscoveryQName.Computer], ["http://server.local/"]);
        byte[]? reply = responder.TryCreateProbeMatch(Probe("urn:uuid:req-1", "pub:Computer"));

        Assert.NotNull(reply);
        string xml = Encoding.UTF8.GetString(reply!);
        Assert.Contains("ProbeMatches", xml);
        Assert.Contains("urn:uuid:" + Endpoint.ToString("D"), xml); // the advertised endpoint
        Assert.Contains("http://server.local/", xml);               // XAddrs
        Assert.Contains("urn:uuid:req-1", xml);                     // RelatesTo = probe MessageID
    }

    [Fact]
    public void Responder_ProbeAll_Matches_ButUnknownType_DoesNot()
    {
        var responder = new WsDiscoveryResponder(Endpoint, [WsDiscoveryQName.Computer], ["http://server.local/"]);

        Assert.NotNull(responder.TryCreateProbeMatch(Probe("urn:uuid:a", typesXml: null))); // probe-all
        Assert.Null(responder.TryCreateProbeMatch(Probe("urn:uuid:b", "pub:Printer")));      // wrong type
        Assert.Null(responder.TryCreateProbeMatch(Encoding.UTF8.GetBytes("garbage")));        // not a probe
    }

    [Fact]
    public void Responder_MessageNumberIncrements_InstanceIdStable()
    {
        var responder = new WsDiscoveryResponder(Endpoint, [WsDiscoveryQName.Computer], [], instanceId: 4242);
        Assert.Equal(4242ul, responder.InstanceId);

        string first = Encoding.UTF8.GetString(responder.CreateHello());
        string second = Encoding.UTF8.GetString(responder.CreateHello());
        Assert.Contains("MessageNumber=\"1\"", first);
        Assert.Contains("MessageNumber=\"2\"", second);
        Assert.Contains("InstanceId=\"4242\"", first);
        Assert.Contains("InstanceId=\"4242\"", second);
    }

    // --- host-level UDP round-trip (unicast, no multicast join → reliable on any CI) ---

    [Fact]
    public async Task Host_UnicastProbe_ReceivesProbeMatch()
    {
        string dir = Path.Combine(Path.GetTempPath(), "smbwsd_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            await using SmbServer server = SmbServerBuilder.Create()
                .WithEndpoint(IPAddress.Loopback, 0)
                .UseDevAuthentication()
                .AddShare(new Share { Name = "Data", Type = ShareType.Disk, FileStore = new LocalFileStore(dir, readOnly: true) })
                .UseWsDiscovery(o =>
                {
                    o.EndpointId = Endpoint;
                    o.BindAddress = IPAddress.Loopback;
                    o.Port = 0;                 // ephemeral → no clash with a real WSD service
                    o.JoinMulticast = false;    // unicast-only test path
                    o.AnnouncePresence = false;
                    o.XAddrs = ["http://smb-host.local/"];
                })
                .Build();
            await server.StartAsync();

            IPEndPoint wsd = server.WsDiscoveryEndpoint!;
            using var client = new UdpClient(AddressFamily.InterNetwork);
            client.Client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            await client.SendAsync(Probe("urn:uuid:host-req", "pub:Computer"), new IPEndPoint(IPAddress.Loopback, wsd.Port));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            UdpReceiveResult received = await client.ReceiveAsync(cts.Token);
            string xml = Encoding.UTF8.GetString(received.Buffer);

            Assert.Contains("ProbeMatches", xml);
            Assert.Contains("urn:uuid:" + Endpoint.ToString("D"), xml);
            Assert.Contains("urn:uuid:host-req", xml); // RelatesTo
            Assert.Contains("http://smb-host.local/", xml);

            await server.StopAsync();
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }
}
