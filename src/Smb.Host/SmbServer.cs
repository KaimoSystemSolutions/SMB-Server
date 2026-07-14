using System.Net;
using System.Net.Sockets;
using Smb.FileSystem;
using Smb.Server;
using Smb.Server.State;

namespace Smb.Host;

/// <summary>
/// Public SMB-2/3 server host (Context §3, §19). Listens on TCP (default 445),
/// accepts connections and serves them concurrently. Simple usage:
/// <code>
/// await using var server = SmbServerBuilder.Create()
///     .WithEndpoint(IPAddress.Any, 445)
///     .UseDevAuthentication()        // test/dev only; use a real negotiator in production
///     .AddShare(new Share { Name = "Data", FileStore = myStore })
///     .Build();
/// await server.StartAsync();
/// </code>
/// </summary>
public sealed class SmbServer : IAsyncDisposable
{
    private readonly SmbServerState _state;
    private readonly IPEndPoint _endpoint;
    private readonly Action<string>? _log;
    private readonly ConnectionLimiter _limiter;
    private readonly SmbTlsOptions? _tls;
    private readonly SmbQuicOptions? _quicOptions;
    private readonly IPEndPoint? _quicEndpoint;
    private readonly WsDiscoveryOptions? _wsDiscoveryOptions;
    private TcpListener? _listener;
    private SmbQuicListener? _quicListener;
    private WsDiscoveryListener? _wsDiscoveryListener;
    private CancellationTokenSource? _hardCts;
    private CancellationTokenSource? _drainCts;
    private Task? _acceptLoop;
    private Task? _sweepLoop;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Task, byte> _connectionTasks = new();

    internal SmbServer(SmbServerOptions options, IPEndPoint endpoint, Action<string>? log,
        SmbTlsOptions? tls = null, SmbQuicOptions? quic = null, int quicPort = 443,
        WsDiscoveryOptions? wsDiscovery = null)
    {
        options.Validate();
        tls?.Validate();
        quic?.Validate();
        wsDiscovery?.Validate();
        EnsureIpcShare(options.Shares);
        _state = new SmbServerState(options);
        _endpoint = endpoint;
        _log = log;
        _tls = tls;
        _quicOptions = quic;
        // [M10.2] QUIC runs on its own UDP endpoint (same bind address as TCP, conventionally port 443).
        _quicEndpoint = quic is not null ? new IPEndPoint(endpoint.Address, quicPort) : null;
        _wsDiscoveryOptions = wsDiscovery;
        _limiter = new ConnectionLimiter(options.MaxConnections, options.MaxConnectionsPerClient);
    }

    /// <summary>The local TCP endpoint on which the server is listening (after <see cref="StartAsync"/> with the actual port).</summary>
    public IPEndPoint Endpoint => (IPEndPoint)(_listener?.LocalEndpoint ?? _endpoint);

    /// <summary>[M10.2] The local UDP endpoint of the SMB-over-QUIC listener, or <c>null</c> when QUIC is not configured.</summary>
    public IPEndPoint? QuicEndpoint => _quicListener?.LocalEndPoint ?? _quicEndpoint;

    /// <summary>[M11.3] The local UDP endpoint of the WS-Discovery responder, or <c>null</c> when it is not enabled.</summary>
    public IPEndPoint? WsDiscoveryEndpoint => _wsDiscoveryListener?.LocalEndPoint;

    /// <summary>Server state (shares, sessions) — for tests/diagnostics.</summary>
    public SmbServerState State => _state;

    /// <summary>[M8.5] Live health &amp; performance counters. Read <c>Metrics.Snapshot()</c> for a health endpoint.</summary>
    public Smb.Server.Diagnostics.SmbServerMetrics Metrics => _state.Options.Metrics;

    /// <summary>Currently published shares (snapshot); reflects runtime add/remove.</summary>
    public IReadOnlyCollection<IShare> Shares => _state.Shares.All;

    /// <summary>
    /// [C1.4] Signals a resource/node availability change to witness-registered clients (MS-SWN): every client
    /// that registered on <paramref name="netName"/> (case-insensitive; null/empty targets all) is asynchronously
    /// notified so it can fail over. Returns the number of clients notified. Call this when a clustered resource
    /// moves or a node goes down. Requires the affected share to advertise continuous availability (C1.0).
    /// </summary>
    public int NotifyWitnessResourceChange(
        string? netName, Smb.Server.Witness.WitnessResourceChange change, string resourceName)
        => _state.WitnessRegistrations.NotifyResourceChange(netName, change, resourceName);

    /// <summary>
    /// Adds (or replaces) a share at runtime. New TREE_CONNECTs see it immediately; existing tree
    /// connections are unaffected. No restart required.
    /// </summary>
    public void AddShare(IShare share) => _state.Shares.Add(share);

    /// <summary>
    /// Removes a share at runtime. New TREE_CONNECTs to it are refused (<c>STATUS_BAD_NETWORK_NAME</c>);
    /// existing tree connections keep working until the client disconnects. Returns false if it was
    /// not present.
    /// </summary>
    public bool RemoveShare(string name) => _state.Shares.Remove(name);

    /// <summary>Starts the listener and the accept loop (Context §3.3.3: open listener on 445).</summary>
    public async Task StartAsync(CancellationToken ct = default)
    {
        if (_listener is not null) throw new InvalidOperationException("Server is already running.");

        _hardCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _drainCts = new CancellationTokenSource();
        _listener = new TcpListener(_endpoint);
        _listener.Start();
        _log?.Invoke($"SMB server listening on {_listener.LocalEndpoint}.");
        _acceptLoop = AcceptLoopAsync(_hardCts.Token);
        _sweepLoop = SweepLoopAsync(_hardCts.Token);

        // [M10.2] Optional additional SMB-over-QUIC listener (UDP). TCP above always works; QUIC is only
        // started when configured and supported by the platform's MsQuic.
        if (_quicOptions is not null)
        {
            _quicListener = new SmbQuicListener(_state, _quicOptions, _quicEndpoint!, _log);
            await _quicListener.StartAsync(_hardCts.Token, _drainCts.Token).ConfigureAwait(false);
        }

        // [M11.3] Optional WS-Discovery responder (UDP 3702) so the server shows up in Explorer's Network view.
        if (_wsDiscoveryOptions is not null)
        {
            _wsDiscoveryListener = new WsDiscoveryListener(_wsDiscoveryOptions, _log);
            _wsDiscoveryListener.Start(_hardCts.Token);
        }
    }

    /// <summary>
    /// [M8.2] Background timeout sweep: periodically expires idle sessions and drops idle / slow-auth
    /// connections (via the dispatcher's <see cref="Smb2Dispatcher.SweepIdleTimeouts"/>) and scavenges
    /// expired durable handles. Disabled when <see cref="SmbServerOptions.TimeoutSweepInterval"/> is zero.
    /// </summary>
    private async Task SweepLoopAsync(CancellationToken ct)
    {
        SmbServerOptions options = _state.Options;
        if (options.TimeoutSweepInterval <= TimeSpan.Zero)
            return;

        var dispatcher = new Smb2Dispatcher(_state, _log);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(options.TimeoutSweepInterval, options.TimeProvider, ct).ConfigureAwait(false);
                try
                {
                    dispatcher.SweepIdleTimeouts();
                    dispatcher.ScavengeDurableHandles();
                }
                catch (Exception ex)
                {
                    _log?.Invoke($"[sweep] error: {ex.GetType().Name}: {ex.Message}");
                }
            }
        }
        catch (OperationCanceledException) { /* stop */ }
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client = await _listener!.AcceptTcpClientAsync(ct);
                client.NoDelay = true;

                // [M8.3] Admission control: reject (immediately close, no state) once the global or
                // per-client connection cap is reached.
                string clientIp = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "unknown";
                if (!_limiter.TryAdmit(clientIp))
                {
                    _log?.Invoke($"Connection from {clientIp} rejected (connection limit reached).");
                    try { client.Dispose(); } catch { /* ignore */ }
                    continue;
                }

                var handler = new SmbConnectionHandler(_state, _log, _tls);
                Task run = handler.RunAsync(client, _hardCts!.Token, _drainCts!.Token);
                _connectionTasks.TryAdd(run, 0);
                _ = run.ContinueWith(t =>
                {
                    _connectionTasks.TryRemove(t, out _);
                    _limiter.Release(clientIp);
                }, TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) { /* Stop */ }
        catch (ObjectDisposedException) { /* Listener stopped */ }
    }

    /// <summary>
    /// [M8.4] Graceful shutdown with connection draining. Stops accepting new connections, sends
    /// oplock/lease breaks to caching holders, then lets in-flight operations finish for up to
    /// <paramref name="drainTimeout"/> (default <see cref="SmbServerOptions.ShutdownDrainTimeout"/>)
    /// before force-closing the remainder.
    /// </summary>
    public async Task StopAsync(TimeSpan? drainTimeout = null)
    {
        if (_hardCts is null) return;
        TimeSpan drain = drainTimeout ?? _state.Options.ShutdownDrainTimeout;

        // 1. Stop accepting (the accept loop exits when the listener is stopped).
        _listener?.Stop();

        // 2. Notify caching holders so they can flush before their handles close (best-effort).
        try { await new Smb2Dispatcher(_state, _log).SendShutdownBreaksAsync(); } catch { /* best-effort */ }

        // 3. Signal connections to stop reading new frames and drain in-flight work.
        if (_drainCts is not null) await _drainCts.CancelAsync();

        // 4. Wait for connections to finish, up to the drain timeout; then force-close.
        Task[] pending = _connectionTasks.Keys.ToArray();
        if (pending.Length > 0)
        {
            _log?.Invoke($"Draining {pending.Length} connection(s), timeout {drain.TotalSeconds:0}s.");
            Task all = Task.WhenAll(pending);
            if (await Task.WhenAny(all, Task.Delay(drain)).ConfigureAwait(false) != all)
            {
                _log?.Invoke("Drain timeout reached — forcing remaining connections closed.");
                await _hardCts.CancelAsync();
            }
            try { await all; } catch { /* connection faults are logged per-connection */ }
        }
        else
        {
            await _hardCts.CancelAsync();
        }

        // 4b. [M10.2] Stop the QUIC listener and drain its connections (they already observe the drain
        //     token from step 3 and the hard token from step 4).
        if (_quicListener is not null) { try { await _quicListener.StopAsync(); } catch { /* ignore */ } }

        // 4c. [M11.3] Stop the WS-Discovery responder (sends Bye, closes the UDP socket).
        if (_wsDiscoveryListener is not null) { try { await _wsDiscoveryListener.StopAsync(); } catch { /* ignore */ } }

        // 5. Wind down the background loops.
        if (_acceptLoop is not null) { try { await _acceptLoop; } catch { /* ignore */ } }
        if (!_hardCts.IsCancellationRequested) await _hardCts.CancelAsync(); // stop the sweep loop
        if (_sweepLoop is not null) { try { await _sweepLoop; } catch { /* ignore */ } }
        _listener = null;
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _hardCts?.Dispose();
        _drainCts?.Dispose();
    }

    private static void EnsureIpcShare(ShareCollection shares)
    {
        // IPC$ must exist — many clients connect to it first (Context §12, §23).
        if (!shares.Contains("IPC$"))
            shares.Add(Share.CreateIpc());
    }
}
