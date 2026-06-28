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
///     .UseDevAuthentication()        // nur Test/Dev; in Produktion echten Negotiator setzen
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
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;

    internal SmbServer(SmbServerOptions options, IPEndPoint endpoint, Action<string>? log)
    {
        options.Validate();
        EnsureIpcShare(options.Shares);
        _state = new SmbServerState(options);
        _endpoint = endpoint;
        _log = log;
    }

    /// <summary>The local endpoint on which the server is listening (after <see cref="StartAsync"/> with the actual port).</summary>
    public IPEndPoint Endpoint => (IPEndPoint)(_listener?.LocalEndpoint ?? _endpoint);

    /// <summary>Server state (shares, sessions) — for tests/diagnostics.</summary>
    public SmbServerState State => _state;

    /// <summary>Currently published shares (snapshot); reflects runtime add/remove.</summary>
    public IReadOnlyCollection<IShare> Shares => _state.Shares.All;

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
    public Task StartAsync(CancellationToken ct = default)
    {
        if (_listener is not null) throw new InvalidOperationException("Server is already running.");

        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _listener = new TcpListener(_endpoint);
        _listener.Start();
        _log?.Invoke($"SMB server listening on {_listener.LocalEndpoint}.");
        _acceptLoop = AcceptLoopAsync(_cts.Token);
        return Task.CompletedTask;
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        var clientTasks = new List<Task>();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client = await _listener!.AcceptTcpClientAsync(ct);
                client.NoDelay = true;
                var handler = new SmbConnectionHandler(_state, _log);
                clientTasks.Add(handler.RunAsync(client, ct));
                clientTasks.RemoveAll(t => t.IsCompleted);
            }
        }
        catch (OperationCanceledException) { /* Stop */ }
        catch (ObjectDisposedException) { /* Listener stopped */ }
        finally
        {
            await Task.WhenAll(clientTasks.Where(t => !t.IsFaulted));
        }
    }

    /// <summary>Stops the listener and terminates the accept loop.</summary>
    public async Task StopAsync()
    {
        if (_cts is null) return;
        await _cts.CancelAsync();
        _listener?.Stop();
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop; } catch { /* ignore */ }
        }
        _listener = null;
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _cts?.Dispose();
    }

    private static void EnsureIpcShare(ShareCollection shares)
    {
        // IPC$ must exist — many clients connect to it first (Context §12, §23).
        if (!shares.Contains("IPC$"))
            shares.Add(Share.CreateIpc());
    }
}
