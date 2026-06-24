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
/// NBSS-gerahmte) Antwort zurück.
/// </summary>
internal sealed class SmbConnectionHandler
{
    private readonly SmbServerState _server;
    private readonly Smb2Dispatcher _dispatcher;
    private readonly Action<string>? _log;

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

            while (!ct.IsCancellationRequested)
            {
                // 1. NBSS-Präfix lesen (4 Byte, 24-Bit Big-Endian Länge).
                if (!await TryReadExactAsync(stream, prefix, ct)) break;
                int length = NbssFrame.ReadLength(prefix);
                if (length <= 0 || length > NbssFrame.MaxPayloadLength) break;

                // 2. Payload lesen.
                var payload = new byte[length];
                if (!await TryReadExactAsync(stream, payload, ct)) break;

                // 3. Verarbeiten (entschlüsseln → dispatchen → ggf. verschlüsseln).
                byte[]? response = ProcessFrame(connection, payload);
                if (response is null) continue;

                // 4. NBSS-gerahmt zurückschreiben.
                byte[] framed = NbssFrame.Wrap(response);
                await stream.WriteAsync(framed, ct);
                await stream.FlushAsync(ct);
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
            _server.Connections.TryRemove(connection.ConnectionId, out _);
            client.Dispose();
        }
    }

    private byte[]? ProcessFrame(SmbConnection connection, byte[] payload)
    {
        ReadOnlySpan<byte> message = payload;
        bool requestEncrypted = false;

        // Transform-Frame? → entschlüsseln (Context §11, §19.1 Schritt 1).
        if (SmbProtocolIds.IsTransform(payload))
        {
            TransformHeader th = TransformHeader.Read(payload);
            if (!_server.SessionGlobalList.TryGetValue(th.SessionId, out SmbSession? session))
                return null; // unbekannte Session → verwerfen.

            try
            {
                message = Smb2Transform.Decrypt(connection.CipherId, session.DecryptionKey, payload);
            }
            catch
            {
                return null; // Auth-Tag-Fehler → verwerfen.
            }

            // Der Client hat Verschlüsselung aktiviert (z.B. smbprotocol mit dem Default
            // require_encryption=True). Eine erfolgreich entschlüsselte Nachricht ist durch
            // das AEAD bereits integritätsgeschützt — sie wird NICHT zusätzlich signiert
            // (MS-SMB2 §3.1.4.1: Signieren und Verschlüsseln schließen sich aus). Ab jetzt
            // verschlüsseln wir auch die Antworten dieser Session (§3.3.4.1.4: war der Request
            // verschlüsselt, MUSS die Antwort verschlüsselt sein).
            session.EncryptData = true;
            session.SigningRequired = false;
            requestEncrypted = true;
        }

        byte[] response = _dispatcher.ProcessMessage(connection, message);

        // Ausgehende Verschlüsselung: wenn der Request verschlüsselt kam oder die Session
        // Verschlüsselung verlangt.
        ulong sessionId = ReadResponseSessionId(response);
        if (sessionId != 0
            && _server.SessionGlobalList.TryGetValue(sessionId, out SmbSession? outSession)
            && (requestEncrypted || outSession.EncryptData))
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
