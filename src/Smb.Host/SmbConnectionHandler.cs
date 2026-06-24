using System.Buffers.Binary;
using System.Net.Sockets;
using Smb.Crypto;
using Smb.Protocol.Constants;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Smb.Server;
using Smb.Server.State;

namespace Smb.Host;

/// <summary>
/// Lese-Loop einer einzelnen TCP-Verbindung (Context §3, §19.1). Dekodiert NBSS-Frames,
/// entschlüsselt Transform-Frames, ruft den Dispatcher und schreibt die (ggf. verschlüsselte,
/// NBSS-gerahmte) Antwort zurück. Schreibvorgänge laufen serialisiert über
/// <see cref="_writeLock"/> — so können asynchron ausstehende Operationen (z.B. blockierende
/// LOCKs) ihre finale Antwort out-of-band senden, ohne die Lese-Antworten zu verschachteln.
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

            // Out-of-band-Sendekanal bereitstellen: asynchron fertiggestellte Antworten (z.B. ein
            // blockierender LOCK, der gewährt/abgebrochen wurde) gehen über denselben serialisierten
            // Writer. Verschlüsselung/Rahmung passieren zentral in SendFramedAsync.
            connection.SendRawAsync = raw => SendFramedAsync(stream, connection, raw, ct);

            while (!ct.IsCancellationRequested)
            {
                // 1. NBSS-Präfix lesen (4 Byte, 24-Bit Big-Endian Länge).
                if (!await TryReadExactAsync(stream, prefix, ct)) break;
                int length = NbssFrame.ReadLength(prefix);
                if (length <= 0 || length > NbssFrame.MaxPayloadLength) break;

                // 2. Payload lesen.
                var payload = new byte[length];
                if (!await TryReadExactAsync(stream, payload, ct)) break;

                // 3. Verarbeiten (entschlüsseln → dispatchen). Leere Antwort = nichts senden (z.B. CANCEL).
                byte[] response = ProcessFrame(connection, payload);
                if (response.Length == 0) continue;

                // 4. Verschlüsseln (falls nötig), NBSS-rahmen, serialisiert zurückschreiben.
                await SendFramedAsync(stream, connection, response, ct);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
        {
            // Verbindungsabbruch ist normal.
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[conn {connection.ConnectionId:N}] Fehler: {ex.Message}");
        }
        finally
        {
            connection.SendRawAsync = null;
            connection.CancelAllPending();            // wartende LOCKs etc. abbrechen
            _server.Connections.TryRemove(connection.ConnectionId, out _);
            _writeLock.Dispose();
            client.Dispose();
        }
    }

    /// <summary>Entschlüsselt (falls Transform) und dispatcht. Liefert die rohe SMB2-Antwort (leer = nichts senden).</summary>
    private byte[] ProcessFrame(SmbConnection connection, byte[] payload)
    {
        ReadOnlySpan<byte> message = payload;

        // Transform-Frame? → entschlüsseln (Context §11, §19.1 Schritt 1).
        if (SmbProtocolIds.IsTransform(payload))
        {
            TransformHeader th = TransformHeader.Read(payload);
            if (!_server.SessionGlobalList.TryGetValue(th.SessionId, out SmbSession? session))
                return []; // unbekannte Session → verwerfen.

            try
            {
                message = Smb2Transform.Decrypt(connection.CipherId, session.DecryptionKey, payload);
            }
            catch
            {
                return []; // Auth-Tag-Fehler → verwerfen.
            }

            // Der Client hat Verschlüsselung aktiviert (z.B. smbprotocol mit dem Default
            // require_encryption=True). Eine erfolgreich entschlüsselte Nachricht ist durch
            // das AEAD bereits integritätsgeschützt — sie wird NICHT zusätzlich signiert
            // (MS-SMB2 §3.1.4.1). Ab jetzt verschlüsseln wir auch die Antworten dieser Session
            // (§3.3.4.1.4: war der Request verschlüsselt, MUSS die Antwort verschlüsselt sein).
            session.EncryptData = true;
            session.SigningRequired = false;
        }

        return _dispatcher.ProcessMessage(connection, message);
    }

    /// <summary>Verschlüsselt die Antwort bei Bedarf, rahmt sie als NBSS und schreibt sie serialisiert.</summary>
    private async Task SendFramedAsync(NetworkStream stream, SmbConnection connection, byte[] rawResponse, CancellationToken ct)
    {
        byte[] outBytes = MaybeEncrypt(connection, rawResponse);
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

    /// <summary>Verschlüsselt die Antwort, wenn die adressierte Session Verschlüsselung verlangt.</summary>
    private byte[] MaybeEncrypt(SmbConnection connection, byte[] response)
    {
        ulong sessionId = ReadResponseSessionId(response);
        if (sessionId != 0
            && _server.SessionGlobalList.TryGetValue(sessionId, out SmbSession? outSession)
            && outSession.EncryptData)
        {
            byte[] nonce = NewNonce(connection.CipherId);
            return Smb2Transform.Encrypt(connection.CipherId, outSession.EncryptionKey, sessionId, nonce, response);
        }
        return response;
    }

    private static ulong ReadResponseSessionId(ReadOnlySpan<byte> response)
        => response.Length >= Smb2Header.Size
            ? BinaryPrimitives.ReadUInt64LittleEndian(response.Slice(40, 8))
            : 0;

    private static byte[] NewNonce(Smb.Protocol.Enums.SmbCipherId cipher)
        => System.Security.Cryptography.RandomNumberGenerator.GetBytes(Smb2Transform.NonceLength(cipher));

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
