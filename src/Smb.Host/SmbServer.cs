using System.Net;
using System.Net.Sockets;
using Smb.FileSystem;
using Smb.Server;
using Smb.Server.State;

namespace Smb.Host;

/// <summary>
/// Öffentlicher SMB-2/3-Server-Host (Context §3, §19). Lauscht auf TCP (Default 445),
/// nimmt Verbindungen an und bedient sie nebenläufig. Einfache Nutzung:
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

    /// <summary>Der lokale Endpunkt, auf dem gelauscht wird (nach <see cref="StartAsync"/> mit echtem Port).</summary>
    public IPEndPoint Endpoint => (IPEndPoint)(_listener?.LocalEndpoint ?? _endpoint);

    /// <summary>Server-Zustand (Shares, Sessions) — für Tests/Diagnose.</summary>
    public SmbServerState State => _state;

    /// <summary>Startet den Listener und die Accept-Schleife (Context §3.3.3: Listener auf 445 öffnen).</summary>
    public Task StartAsync(CancellationToken ct = default)
    {
        if (_listener is not null) throw new InvalidOperationException("Server läuft bereits.");

        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _listener = new TcpListener(_endpoint);
        _listener.Start();
        _log?.Invoke($"SMB-Server lauscht auf {_listener.LocalEndpoint}.");
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
        catch (ObjectDisposedException) { /* Listener gestoppt */ }
        finally
        {
            await Task.WhenAll(clientTasks.Where(t => !t.IsFaulted));
        }
    }

    /// <summary>Stoppt den Listener und beendet die Accept-Schleife.</summary>
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
        // IPC$ muss existieren — viele Clients verbinden es zuerst (Context §12, §23).
        if (!shares.Contains("IPC$"))
            shares.Add(Share.CreateIpc());
    }
}
