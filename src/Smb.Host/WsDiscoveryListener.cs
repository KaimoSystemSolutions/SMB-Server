using System.Net;
using System.Net.Sockets;
using Smb.Protocol.Discovery;

namespace Smb.Host;

/// <summary>
/// [M11.3] WS-Discovery UDP responder. Binds a datagram socket on the WS-Discovery port (default 3702),
/// optionally joins the IPv4 multicast group 239.255.255.250, and answers Probe messages with a ProbeMatches
/// reply so the server appears in Windows Explorer's Network view. Also emits a Hello on start and a Bye on
/// stop. The wire format is built by the pure <see cref="WsDiscoveryResponder"/>; this class only owns the
/// socket. Kept in the host layer so the core stays transport-agnostic.
/// </summary>
internal sealed class WsDiscoveryListener
{
    private readonly WsDiscoveryOptions _options;
    private readonly WsDiscoveryResponder _responder;
    private readonly Action<string>? _log;

    private Socket? _socket;
    private IPEndPoint? _multicastEndpoint;
    private Task? _receiveLoop;
    private CancellationTokenSource? _cts;

    public WsDiscoveryListener(WsDiscoveryOptions options, Action<string>? log)
    {
        _options = options;
        _responder = options.CreateResponder();
        _log = log;
    }

    /// <summary>The bound local endpoint (with the actual port after <see cref="Start"/>), for diagnostics/tests.</summary>
    public IPEndPoint? LocalEndPoint => _socket?.LocalEndPoint as IPEndPoint;

    /// <summary>Binds the socket, optionally joins the multicast group, announces Hello, and starts receiving.</summary>
    public void Start(CancellationToken hardCt)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(hardCt);
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _socket.Bind(new IPEndPoint(_options.BindAddress, _options.Port));

        var group = IPAddress.Parse(WsDiscoveryConstants.MulticastAddressV4);
        _multicastEndpoint = new IPEndPoint(group, _options.Port);
        if (_options.JoinMulticast)
        {
            try
            {
                _socket.SetSocketOption(SocketOptionLevel.IP,
                    SocketOptionName.AddMembership, new MulticastOption(group, _options.BindAddress));
            }
            catch (SocketException ex)
            {
                // Membership can fail if another WSD service already owns the group on this box; keep serving
                // unicast/directed probes instead of failing the whole server.
                _log?.Invoke($"[wsd] multicast join failed ({ex.SocketErrorCode}); serving unicast probes only.");
            }
        }

        _log?.Invoke($"WS-Discovery listening on {LocalEndPoint} (endpoint {_responder.EndpointId:D}).");
        _receiveLoop = ReceiveLoopAsync(_cts.Token);

        if (_options.AnnouncePresence && _options.JoinMulticast)
            _ = SendToMulticastAsync(_responder.CreateHello(), _cts.Token);
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var buffer = new byte[64 * 1024]; // one datagram; WSD messages are small
        try
        {
            while (!ct.IsCancellationRequested)
            {
                SocketReceiveFromResult received;
                try
                {
                    received = await _socket!.ReceiveFromAsync(
                        buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), ct).ConfigureAwait(false);
                }
                catch (SocketException) { continue; } // transient receive error → keep listening
                catch (OperationCanceledException) { break; }

                byte[]? reply;
                try
                {
                    reply = _responder.TryCreateProbeMatch(buffer.AsSpan(0, received.ReceivedBytes));
                }
                catch (Exception ex)
                {
                    _log?.Invoke($"[wsd] probe handling error: {ex.GetType().Name}: {ex.Message}");
                    continue;
                }

                if (reply is null)
                    continue; // not a matching Probe — defined no-op

                try
                {
                    // WS-Discovery ProbeMatch is unicast back to the probing endpoint.
                    await _socket!.SendToAsync(reply, SocketFlags.None, received.RemoteEndPoint, ct).ConfigureAwait(false);
                }
                catch (SocketException ex) { _log?.Invoke($"[wsd] reply send failed: {ex.SocketErrorCode}."); }
            }
        }
        catch (OperationCanceledException) { /* stop */ }
        catch (ObjectDisposedException) { /* socket disposed */ }
    }

    private async Task SendToMulticastAsync(byte[] message, CancellationToken ct)
    {
        try
        {
            if (_socket is not null && _multicastEndpoint is not null)
                await _socket.SendToAsync(message, SocketFlags.None, _multicastEndpoint, ct).ConfigureAwait(false);
        }
        catch (SocketException ex) { _log?.Invoke($"[wsd] multicast send failed: {ex.SocketErrorCode}."); }
        catch (ObjectDisposedException) { /* stopping */ }
        catch (OperationCanceledException) { /* stopping */ }
    }

    /// <summary>Announces Bye (best-effort), stops the receive loop and closes the socket.</summary>
    public async Task StopAsync()
    {
        if (_options.AnnouncePresence && _options.JoinMulticast && _socket is not null)
        {
            try { await SendToMulticastAsync(_responder.CreateBye(), CancellationToken.None).ConfigureAwait(false); }
            catch { /* best-effort */ }
        }

        try { if (_cts is not null) await _cts.CancelAsync().ConfigureAwait(false); } catch { /* ignore */ }
        if (_socket is not null) { try { _socket.Dispose(); } catch { /* ignore */ } }
        if (_receiveLoop is not null) { try { await _receiveLoop.ConfigureAwait(false); } catch { /* ignore */ } }
        _cts?.Dispose();
        _socket = null;
    }
}
