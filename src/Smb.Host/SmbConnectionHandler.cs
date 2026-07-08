using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using Smb.Crypto;
using Smb.Protocol.Compression;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Smb.Server;
using Smb.Server.Diagnostics;
using Smb.Server.State;

namespace Smb.Host;

/// <summary>
/// Read loop for a single TCP connection (Context §3, §19.1). Decodes NBSS frames,
/// decrypts transform frames, calls the dispatcher and writes the (optionally encrypted,
/// NBSS-framed) response back. Write operations are serialized via
/// <see cref="_writeLock"/> — so asynchronously pending operations (e.g. blocking
/// LOCKs) can send their final response out-of-band without interleaving with read responses.
/// <para>
/// Concurrent file I/O (docs/ASYNC_IO_ROADMAP.md, A4): individual READ/WRITE frames are —
/// capped via <see cref="SmbServerOptions.MaxConcurrentFileOpsPerConnection"/> — processed
/// concurrently; their responses may go out-of-order via the serialized writer.
/// Every other frame acts as a barrier: all outstanding I/Os are drained first, then it is
/// processed sequentially as before (state changes remain ordered).
/// </para>
/// </summary>
internal sealed class SmbConnectionHandler
{
    private readonly SmbServerState _server;
    private readonly Smb2Dispatcher _dispatcher;
    private readonly Action<string>? _log;
    private readonly SmbTlsOptions? _tls;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    /// <summary>Cap for concurrent READ/WRITE frames; <c>null</c> = feature off (option ≤ 1).</summary>
    private readonly SemaphoreSlim? _ioGate;
    private readonly List<Task> _inflight = [];

    public SmbConnectionHandler(SmbServerState server, Action<string>? log, SmbTlsOptions? tls = null)
    {
        _server = server;
        _dispatcher = new Smb2Dispatcher(server, log);
        _log = log;
        _tls = tls;

        int maxOps = server.Options.MaxConcurrentFileOpsPerConnection;
        _ioGate = maxOps > 1 ? new SemaphoreSlim(maxOps, maxOps) : null;
    }

    public async Task RunAsync(TcpClient client, CancellationToken hardCt, CancellationToken drainToken = default)
    {
        long nowTicks = _server.Options.TimeProvider.GetUtcNow().Ticks;
        var connection = new SmbConnection
        {
            ClientAddress = (client.Client.RemoteEndPoint as IPEndPoint)?.ToString(),
            CreatedTicks = nowTicks,
            LastActivityTicks = nowTicks,
        };

        // [M8.2] Per-connection hard cancellation so the timeout sweeper (or a forced shutdown) can drop
        // this connection alone (the read loop is otherwise blocked in ReadAsync). Sends/ops use this token.
        using var connCts = CancellationTokenSource.CreateLinkedTokenSource(hardCt);
        CancellationToken connCt = connCts.Token;
        connection.RequestClose = () => { try { connCts.Cancel(); } catch (ObjectDisposedException) { } };

        // [M8.4] Frame reads additionally observe the graceful-drain token: on shutdown the pending read
        // is cancelled so the loop stops taking new frames, but in-flight work still completes and its
        // response is sent over connCt (which is not cancelled during a graceful drain).
        using var readCts = CancellationTokenSource.CreateLinkedTokenSource(connCt, drainToken);
        CancellationToken readCt = readCts.Token;

        _server.Connections[connection.ConnectionId] = connection;
        _server.Options.Metrics.OnConnectionAccepted();
        AuditConnection(SmbAuditEventType.ConnectionAccepted, connection);

        Stream? stream = null;
        try
        {
            // [M10.1] SMB over TLS: wrap the transport in an SslStream and complete the handshake
            // before any NBSS/SMB2 byte is read. A plain-TCP client fails the handshake here and is
            // dropped. Without TLS configured the raw NetworkStream is used unchanged.
            stream = client.GetStream();
            if (_tls is not null)
            {
                stream = await EstablishTlsAsync((NetworkStream)stream, connection, readCt).ConfigureAwait(false);
                if (stream is null) return; // handshake failed / timed out → connection dropped
            }

            var prefix = new byte[NbssFrame.HeaderLength];

            // Provide an out-of-band send channel: asynchronously completed responses (e.g. a
            // blocking LOCK that was granted/cancelled) go through the same serialized
            // writer. Encryption/framing happen centrally in SendFramedAsync.
            Stream sendStream = stream;
            connection.SendRawAsync = (raw, forceEncrypt) => SendFramedAsync(sendStream, connection, raw, forceEncrypt, connCt);

            while (!readCt.IsCancellationRequested)
            {
                // 1. Read NBSS prefix (4 bytes, 24-bit big-endian length).
                if (!await TryReadExactAsync(stream, prefix, readCt)) break;
                int length = NbssFrame.ReadLength(prefix);
                if (length <= 0 || length > NbssFrame.MaxPayloadLength) break;

                // 2. Read payload.
                var payload = new byte[length];
                if (!await TryReadExactAsync(stream, payload, readCt)) break;

                // 3. Decode transport wrappers: decompress (M10.3) and/or decrypt (transform frame).
                //    null = discard (unknown session, auth tag error, malformed compression).
                (ReadOnlyMemory<byte> Message, bool Encrypted)? decoded = DecodeInboundFrame(connection, payload);
                if (decoded is null) continue;
                (ReadOnlyMemory<byte> message, bool transportEncrypted) = decoded.Value;

                // 4. Single READ/WRITE? → execute concurrently (A4); the response goes
                //    out-of-band via the serialized writer. TryBeginConcurrentFrame
                //    consumes the sequence window here in the read loop (arrival order!).
                if (_ioGate is not null
                    && _dispatcher.TryBeginConcurrentFrame(connection, message, transportEncrypted, out Smb2Dispatcher.PreparedFrame prepared))
                {
                    await _ioGate.WaitAsync(connCt).ConfigureAwait(false); // cap: waits until a slot is free
                    lock (_inflight)
                    {
                        _inflight.RemoveAll(t => t.IsCompleted);
                        _inflight.Add(RunConcurrentFrameAsync(stream, connection, prepared, connCt));
                    }
                    continue;
                }

                // 5. Barrier: drain all concurrent I/Os, then process sequentially.
                //    Empty response = nothing to send (e.g. CANCEL).
                await DrainInflightAsync().ConfigureAwait(false);
                byte[] response = await _dispatcher.ProcessMessageAsync(connection, message, transportEncrypted).ConfigureAwait(false);

                // 6. Encrypt (if needed), NBSS-frame, write back in serialized fashion.
                //    Empty response = nothing to send (e.g. CANCEL).
                if (response.Length != 0)
                    await SendFramedAsync(stream, connection, response, forceEncrypt: false, connCt);

                // [M5.3] A failed FSCTL_VALIDATE_NEGOTIATE_INFO (downgrade attack) requires the
                // transport connection to be torn down (§3.3.5.15.12).
                if (connection.MustTerminate) break;
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
        {
            // Connection drop is normal.
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[conn {connection.ConnectionId:N}] Error: {ex.Message}");
        }
        finally
        {
            connection.SendRawAsync = null;
            connection.RequestClose = null; // the linked CTS is about to be disposed
            await DrainInflightAsync().ConfigureAwait(false); // drain running I/Os (before writeLock dispose!)
            // OnConnectionClosed releases opens (handles/locks/oplocks/share-modes, O5) and cancels pending
            // async ops — but keeps a session (and its pending LOCK/CHANGE_NOTIFY) alive when another
            // multichannel channel survives, rerouting their final response there (M6.3 failover).
            _dispatcher.OnConnectionClosed(connection);
            _server.Connections.TryRemove(connection.ConnectionId, out _);
            _server.Options.Metrics.OnConnectionClosed();
            AuditConnection(SmbAuditEventType.ConnectionClosed, connection);
            _writeLock.Dispose();
            _ioGate?.Dispose();
            if (stream is not null) { try { await stream.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ } }
            client.Dispose();
        }
    }

    /// <summary>
    /// [M10.1] Performs the server-side TLS handshake for a new connection, bounded by
    /// <see cref="SmbTlsOptions.HandshakeTimeout"/>. Returns the authenticated <see cref="SslStream"/>
    /// on success, or <c>null</c> if the handshake failed/timed out (the caller then drops the
    /// connection). The <see cref="SslStream"/> owns and disposes the inner network stream.
    /// </summary>
    private async Task<Stream?> EstablishTlsAsync(NetworkStream inner, SmbConnection connection, CancellationToken ct)
    {
        var ssl = new SslStream(inner, leaveInnerStreamOpen: false);
        try
        {
            SslServerAuthenticationOptions authOptions = _tls!.BuildAuthenticationOptions();
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            handshakeCts.CancelAfter(_tls.HandshakeTimeout);
            await ssl.AuthenticateAsServerAsync(authOptions, handshakeCts.Token).ConfigureAwait(false);
            connection.IsTransportSecured = true;
            return ssl;
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[conn {connection.ConnectionId:N}] TLS handshake failed: {ex.GetType().Name}: {ex.Message}");
            await ssl.DisposeAsync().ConfigureAwait(false);
            return null;
        }
    }

    /// <summary>[M8.1] Emits a connection-lifecycle audit event (accept/close) if the logger is enabled.</summary>
    private void AuditConnection(SmbAuditEventType type, SmbConnection connection)
    {
        ISmbAuditLogger logger = _server.Options.AuditLogger;
        if (!logger.IsEnabled(SmbLogLevel.Information))
            return;
        logger.Log(new SmbAuditEvent
        {
            EventType = type,
            Level = SmbLogLevel.Information,
            Timestamp = _server.Options.TimeProvider.GetUtcNow(),
            ClientAddress = connection.ClientAddress,
        });
    }

    /// <summary>
    /// Executes a prepared READ/WRITE frame and sends the response. Errors stay in the
    /// task (connection drops are handled by the read loop itself); the I/O slot is always released.
    /// </summary>
    private async Task RunConcurrentFrameAsync(Stream stream, SmbConnection connection,
        Smb2Dispatcher.PreparedFrame frame, CancellationToken ct)
    {
        try
        {
            byte[] response = await _dispatcher.ExecutePreparedFrameAsync(connection, frame).ConfigureAwait(false);
            if (response.Length != 0)
                await SendFramedAsync(stream, connection, response, forceEncrypt: false, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException or ObjectDisposedException)
        {
            // Connection drop is normal — the read loop runs into the same error in parallel.
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[conn {connection.ConnectionId:N}] Error in concurrent frame: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            _ioGate!.Release();
        }
    }

    /// <summary>Barrier: drains all concurrent READ/WRITE frames for this connection.</summary>
    private async Task DrainInflightAsync()
    {
        Task[] pending;
        lock (_inflight)
        {
            _inflight.RemoveAll(t => t.IsCompleted);
            if (_inflight.Count == 0) return;
            pending = [.. _inflight];
        }
        await Task.WhenAll(pending).ConfigureAwait(false); // tasks catch their own errors
        lock (_inflight) _inflight.RemoveAll(t => t.IsCompleted);
    }

    /// <summary>
    /// Decodes the transport wrappers of an inbound frame — a compression transform frame (M10.3) is
    /// decompressed, an encryption transform frame is decrypted (and, if it wraps a compressed message,
    /// decompressed). Returns the SMB2 plaintext message plus the encrypted flag — or <c>null</c> if the
    /// frame should be discarded (unknown session, auth tag error, malformed compression).
    /// </summary>
    private (ReadOnlyMemory<byte> Message, bool Encrypted)? DecodeInboundFrame(SmbConnection connection, byte[] payload)
    {
        // Compression transform frame (unencrypted path)? → decompress (Context §11, MS-SMB2 §3.1.4.4).
        if (SmbProtocolIds.IsCompression(payload))
        {
            try { return (SmbCompressor.Decompress(payload), false); }
            catch { return null; } // malformed compression → discard.
        }

        // Transform frame? → decrypt (Context §11, §19.1 step 1).
        if (!SmbProtocolIds.IsTransform(payload))
            return (payload, false);

        TransformHeader th = TransformHeader.Read(payload);
        if (!_server.SessionGlobalList.TryGetValue(th.SessionId, out SmbSession? session))
            return null; // unknown session → discard.

        byte[] message;
        try
        {
            message = Smb2Transform.Decrypt(connection.CipherId, session.DecryptionKey, payload);
            // A sender may compress first, then encrypt: the decrypted payload can itself be a
            // compression transform frame (§3.1.4.4). Decompress it before dispatch.
            if (SmbProtocolIds.IsCompression(message))
                message = SmbCompressor.Decompress(message);
        }
        catch
        {
            return null; // auth tag error / malformed compression → discard.
        }

        // The client has enabled encryption (e.g. smbprotocol with the default
        // require_encryption=True). From now on we also encrypt the responses for this session
        // (§3.3.4.1.4: if the request was encrypted, the response MUST be encrypted too).
        //
        // [AUDIT-2026-06] A successfully decrypted message is already authenticated by AEAD
        // and is not additionally signed (§3.1.4.1). This is now handled PER FRAME
        // in the dispatcher (VerifyInboundSignature skips encrypted frames).
        // Previously session.SigningRequired was permanently cleared here — a downgrade as soon as a
        // later plaintext frame arrived (e.g. RejectUnencryptedAccess=false). No longer.
        // See docs/SECURITY_AUDIT.md (Finding M2).
        session.EncryptData = true;

        return (message, true);
    }

    /// <summary>Encrypts or compresses the response if needed, frames it as NBSS and writes it in serialized fashion.</summary>
    private async Task SendFramedAsync(Stream stream, SmbConnection connection, byte[] rawResponse, bool forceEncrypt, CancellationToken ct)
    {
        byte[] outBytes = EncodeOutbound(connection, rawResponse, forceEncrypt);
        byte[] framed = NbssFrame.Wrap(outBytes);

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await stream.WriteAsync(framed, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Applies the outbound transport wrappers. Encryption takes priority: the response is encrypted
    /// when the addressed session requires it globally, when its tree requires it (per-share encryption,
    /// §3.3.4.1.4 — includes the TREE_CONNECT response of an encrypted share), or when forced (ASYNC).
    /// Otherwise, if compression was negotiated (M10.3) and the frame is large enough to benefit, the
    /// response is compressed. The two are never combined — compressing is always the sender's choice.
    /// </summary>
    private byte[] EncodeOutbound(SmbConnection connection, byte[] response, bool forceEncrypt)
    {
        ulong sessionId = ReadResponseSessionId(response);
        if (sessionId != 0 && _server.SessionGlobalList.TryGetValue(sessionId, out SmbSession? outSession))
        {
            bool encrypt = forceEncrypt
                || outSession.EncryptData
                || (TryReadResponseTreeId(response, out uint treeId)
                    && outSession.TreeConnects.TryGetValue(treeId, out SmbTreeConnect? tree)
                    && tree.EncryptData);
            if (encrypt)
            {
                byte[] nonce = BuildNonce(connection.CipherId, outSession.NextEncryptionNonce());
                return Smb2Transform.Encrypt(connection.CipherId, outSession.EncryptionKey, sessionId, nonce, response);
            }
        }

        return MaybeCompress(connection, response);
    }

    /// <summary>
    /// Compresses the response into an unchained compression transform frame when an algorithm was
    /// negotiated and the plaintext is at least <see cref="SmbServerOptions.CompressionMinSize"/> bytes
    /// and actually shrinks; otherwise the response is returned unchanged.
    /// </summary>
    private byte[] MaybeCompress(SmbConnection connection, byte[] response)
    {
        SmbCompressionAlgorithm algorithm = connection.CompressionAlgorithm;
        if (algorithm == SmbCompressionAlgorithm.None)
            return response;

        byte[]? frame = SmbCompressor.TryCompressUnchained(algorithm, response, _server.Options.CompressionMinSize);
        return frame ?? response;
    }

    private static ulong ReadResponseSessionId(ReadOnlySpan<byte> response)
        => response.Length >= Smb2Header.Size
            ? BinaryPrimitives.ReadUInt64LittleEndian(response.Slice(40, 8))
            : 0;

    /// <summary>
    /// Reads the TreeId from a SYNC response header (offset 36). ASYNC responses
    /// (flag SMB2_FLAGS_ASYNC_COMMAND) carry the AsyncId at this position — there is
    /// no TreeId there, so false is returned (session-global encryption still applies).
    /// </summary>
    private static bool TryReadResponseTreeId(ReadOnlySpan<byte> response, out uint treeId)
    {
        treeId = 0;
        if (response.Length < Smb2Header.Size) return false;
        var flags = (Smb2HeaderFlags)BinaryPrimitives.ReadUInt32LittleEndian(response.Slice(16, 4));
        if (flags.HasFlag(Smb2HeaderFlags.AsyncCommand)) return false;
        treeId = BinaryPrimitives.ReadUInt32LittleEndian(response.Slice(36, 4));
        return true;
    }

    /// <summary>
    /// [AUDIT-2026-06] Builds the AEAD nonce from a monotonically increasing session counter (NOT random).
    /// MS-SMB2 §3.3.4.1.4 requires a nonce value unique per EncryptionKey; a random
    /// 11/12-byte value runs into the birthday bound (with AES-GCM, nonce reuse is fatal).
    /// The counter (LE in the first 8 bytes; remainder 0) guarantees uniqueness per session/key.
    /// </summary>
    private static byte[] BuildNonce(SmbCipherId cipher, ulong counter)
    {
        var nonce = new byte[Smb2Transform.NonceLength(cipher)];
        BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan(0, 8), counter);
        return nonce;
    }

    private static async Task<bool> TryReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        try
        {
            await stream.ReadExactlyAsync(buffer, ct);
            return true;
        }
        catch (EndOfStreamException)
        {
            return false;
        }
        catch (OperationCanceledException)
        {
            return false; // [M8.4] graceful drain / connection close — stop reading, let the finally drain
        }
    }
}
