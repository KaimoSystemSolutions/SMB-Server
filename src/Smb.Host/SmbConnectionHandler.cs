using System.Buffers.Binary;
using System.Net.Sockets;
using Smb.Crypto;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Smb.Server;
using Smb.Server.State;

namespace Smb.Host;

/// <summary>
/// Read loop for a single TCP connection (Context §3, §19.1). Decodes NBSS frames,
/// decrypts transform frames, calls the dispatcher and writes the (optionally encrypted,
/// NBSS-framed) response back. Write operations are serialized via
/// <see cref="_writeLock"/> — so asynchronously pending operations (e.g. blocking
/// LOCKs) can send their final response out-of-band without interleaving with read responses.
/// </summary>
internal sealed class SmbConnectionHandler
{
    private readonly SmbServerState _server;
    private readonly Smb2Dispatcher _dispatcher;
    private readonly Action<string>? _log;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public SmbConnectionHandler(SmbServerState server, Action<string>? log)
    {
        _server = server;
        _dispatcher = new Smb2Dispatcher(server, log);
        _log = log;
    }

    public async Task RunAsync(TcpClient client, CancellationToken ct)
    {
        var connection = new SmbConnection();
        _server.Connections[connection.ConnectionId] = connection;

        try
        {
            using NetworkStream stream = client.GetStream();
            var prefix = new byte[NbssFrame.HeaderLength];

            // Provide an out-of-band send channel: asynchronously completed responses (e.g. a
            // blocking LOCK that was granted/cancelled) go through the same serialized
            // writer. Encryption/framing happen centrally in SendFramedAsync.
            connection.SendRawAsync = (raw, forceEncrypt) => SendFramedAsync(stream, connection, raw, forceEncrypt, ct);

            while (!ct.IsCancellationRequested)
            {
                // 1. Read NBSS prefix (4 bytes, 24-bit big-endian length).
                if (!await TryReadExactAsync(stream, prefix, ct)) break;
                int length = NbssFrame.ReadLength(prefix);
                if (length <= 0 || length > NbssFrame.MaxPayloadLength) break;

                // 2. Read payload.
                var payload = new byte[length];
                if (!await TryReadExactAsync(stream, payload, ct)) break;

                // 3. Process (decrypt → dispatch). Empty response = nothing to send (e.g. CANCEL).
                byte[] response = ProcessFrame(connection, payload);
                if (response.Length == 0) continue;

                // 4. Encrypt (if necessary), NBSS-frame, write back in serialized fashion.
                await SendFramedAsync(stream, connection, response, forceEncrypt: false, ct);
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
            connection.CancelAllPending();            // cancel pending LOCKs etc.
            _dispatcher.OnConnectionClosed(connection); // release opens: handles/locks/oplocks/share-modes (O5)
            _server.Connections.TryRemove(connection.ConnectionId, out _);
            _writeLock.Dispose();
            client.Dispose();
        }
    }

    /// <summary>Decrypts (if transform frame) and dispatches. Returns the raw SMB2 response (empty = nothing to send).</summary>
    private byte[] ProcessFrame(SmbConnection connection, byte[] payload)
    {
        ReadOnlySpan<byte> message = payload;
        bool transportEncrypted = false;

        // Transform frame? → decrypt (Context §11, §19.1 step 1).
        if (SmbProtocolIds.IsTransform(payload))
        {
            TransformHeader th = TransformHeader.Read(payload);
            if (!_server.SessionGlobalList.TryGetValue(th.SessionId, out SmbSession? session))
                return []; // unknown session → discard.

            try
            {
                message = Smb2Transform.Decrypt(connection.CipherId, session.DecryptionKey, payload);
            }
            catch
            {
                return []; // Auth tag error → discard.
            }

            transportEncrypted = true;

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
        }

        return _dispatcher.ProcessMessage(connection, message, transportEncrypted);
    }

    /// <summary>Encrypts the response if needed, frames it as NBSS and writes it in serialized fashion.</summary>
    private async Task SendFramedAsync(NetworkStream stream, SmbConnection connection, byte[] rawResponse, bool forceEncrypt, CancellationToken ct)
    {
        byte[] outBytes = MaybeEncrypt(connection, rawResponse, forceEncrypt);
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
    /// Encrypts the response if the addressed session requires encryption globally,
    /// OR if the response belongs to a tree that requires encryption (per-share encryption,
    /// §3.3.4.1.4 — includes the TREE_CONNECT response of an encrypted share).
    /// </summary>
    private byte[] MaybeEncrypt(SmbConnection connection, byte[] response, bool forceEncrypt = false)
    {
        ulong sessionId = ReadResponseSessionId(response);
        if (sessionId == 0 || !_server.SessionGlobalList.TryGetValue(sessionId, out SmbSession? outSession))
            return response;

        bool encrypt = forceEncrypt
            || outSession.EncryptData
            || (TryReadResponseTreeId(response, out uint treeId)
                && outSession.TreeConnects.TryGetValue(treeId, out SmbTreeConnect? tree)
                && tree.EncryptData);
        if (!encrypt) return response;

        byte[] nonce = BuildNonce(connection.CipherId, outSession.NextEncryptionNonce());
        return Smb2Transform.Encrypt(connection.CipherId, outSession.EncryptionKey, sessionId, nonce, response);
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
    }
}
