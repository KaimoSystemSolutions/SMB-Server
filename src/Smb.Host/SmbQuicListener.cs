using System.Collections.Concurrent;
using System.Net;
using System.Net.Quic;
using Smb.Server.State;

// System.Net.Quic is platform-annotated ([SupportedOSPlatform] linux/macOS/windows). Every QUIC call
// here is guarded at runtime by QuicListener.IsSupported (StartAsync throws PlatformNotSupportedException
// otherwise), the sanctioned availability check — so CA1416 is suppressed for this file.
#pragma warning disable CA1416

namespace Smb.Host;

/// <summary>
/// [M10.2] SMB-over-QUIC listener. Accepts QUIC connections (UDP, mandatory TLS 1.3) and serves each
/// inbound bidirectional stream as one SMB2 connection through the shared
/// <see cref="SmbConnectionHandler"/> core — the on-stream framing is identical to direct TCP, so the
/// whole dispatcher/frame loop is reused unchanged. The transport is already encrypted and
/// authenticated by QUIC, so no <see cref="SmbTlsOptions"/> wrapping is applied.
/// <para>
/// Kept entirely in the host layer so <c>Smb.Server</c>/<c>Smb.Protocol</c> stay transport-agnostic and
/// fully cross-platform; only this listener touches the native-MsQuic-backed <c>System.Net.Quic</c> API.
/// </para>
/// </summary>
internal sealed class SmbQuicListener
{
    private readonly SmbServerState _server;
    private readonly SmbQuicOptions _options;
    private readonly IPEndPoint _endpoint;
    private readonly Action<string>? _log;
    private readonly ConcurrentDictionary<Task, byte> _connectionTasks = new();

    private QuicListener? _listener;
    private Task? _acceptLoop;
    private CancellationTokenSource? _listenCts;

    public SmbQuicListener(SmbServerState server, SmbQuicOptions options, IPEndPoint endpoint, Action<string>? log)
    {
        _server = server;
        _options = options;
        _endpoint = endpoint;
        _log = log;
    }

    /// <summary>The bound UDP endpoint (with the actual port after <see cref="StartAsync"/>).</summary>
    public IPEndPoint? LocalEndPoint => _listener?.LocalEndPoint as IPEndPoint ?? _endpoint;

    /// <summary>
    /// Binds the QUIC listener and starts accepting. Throws if QUIC is not supported on this platform
    /// (missing MsQuic) — callers should check <see cref="QuicListener.IsSupported"/> or catch this and
    /// fall back to TCP only.
    /// </summary>
    public async Task StartAsync(CancellationToken hardCt, CancellationToken drainToken)
    {
        if (!QuicListener.IsSupported)
            throw new PlatformNotSupportedException(
                "SMB over QUIC requires MsQuic (built into Windows 11 / Server 2022+; install libmsquic on Linux). " +
                "QuicListener.IsSupported is false on this platform.");

        _listenCts = CancellationTokenSource.CreateLinkedTokenSource(hardCt);
        var listenerOptions = new QuicListenerOptions
        {
            ListenEndPoint = _endpoint,
            ApplicationProtocols = [.. _options.ApplicationProtocols],
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(_options.BuildServerConnectionOptions()),
        };

        _listener = await QuicListener.ListenAsync(listenerOptions, _listenCts.Token).ConfigureAwait(false);
        _log?.Invoke($"SMB-over-QUIC listening on {_listener.LocalEndPoint} (UDP).");
        _acceptLoop = AcceptLoopAsync(hardCt, drainToken, _listenCts.Token);
    }

    private async Task AcceptLoopAsync(CancellationToken hardCt, CancellationToken drainToken, CancellationToken listenCt)
    {
        try
        {
            while (!listenCt.IsCancellationRequested)
            {
                QuicConnection connection = await _listener!.AcceptConnectionAsync(listenCt).ConfigureAwait(false);
                Task run = ServeConnectionAsync(connection, hardCt, drainToken);
                _connectionTasks.TryAdd(run, 0);
                _ = run.ContinueWith(t => _connectionTasks.TryRemove(t, out _), TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) { /* stop */ }
        catch (ObjectDisposedException) { /* listener disposed */ }
        catch (QuicException) { /* listener aborted */ }
    }

    /// <summary>
    /// Serves one QUIC connection: accepts its inbound bidirectional streams, each handled as an
    /// independent SMB2 connection, and disposes the connection once all streams have ended.
    /// </summary>
    private async Task ServeConnectionAsync(QuicConnection connection, CancellationToken hardCt, CancellationToken drainToken)
    {
        var streamTasks = new List<Task>();
        try
        {
            while (true)
            {
                QuicStream stream;
                try
                {
                    // Stop accepting new streams once a graceful drain starts; in-flight streams finish
                    // via their own read/drain tokens.
                    stream = await connection.AcceptInboundStreamAsync(drainToken).ConfigureAwait(false);
                }
                catch
                {
                    break; // connection closed/aborted, or draining → no more streams
                }

                // One handler per stream (its own write lock / IO gate), like one TCP connection.
                var handler = new SmbConnectionHandler(_server, _log);
                Task run = handler.ServeAsync(
                    connection.RemoteEndPoint?.ToString(),
                    establishStream: (_, _) => Task.FromResult<Stream?>(stream),
                    transportPreSecured: true, // QUIC already completed TLS 1.3 (encrypted + authenticated)
                    disposeTransport: () => ValueTask.CompletedTask, // ServeAsync disposes the QuicStream
                    hardCt, drainToken);
                streamTasks.Add(run);
            }
        }
        finally
        {
            try { await Task.WhenAll(streamTasks).ConfigureAwait(false); } catch { /* per-stream faults are logged */ }
            try { await connection.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ }
        }
    }

    /// <summary>Stops accepting, waits for the accept loop and drains outstanding connections.</summary>
    public async Task StopAsync()
    {
        try { if (_listenCts is not null) await _listenCts.CancelAsync().ConfigureAwait(false); } catch { /* ignore */ }
        if (_listener is not null) { try { await _listener.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ } }
        if (_acceptLoop is not null) { try { await _acceptLoop.ConfigureAwait(false); } catch { /* ignore */ } }

        Task[] pending = _connectionTasks.Keys.ToArray();
        if (pending.Length > 0) { try { await Task.WhenAll(pending).ConfigureAwait(false); } catch { /* ignore */ } }

        _listenCts?.Dispose();
        _listener = null;
    }
}
