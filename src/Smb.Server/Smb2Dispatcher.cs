using Smb.Auth;
using Smb.Crypto;
using Smb.FileSystem;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;
using Smb.Server.Authorization;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// Verarbeitet eine vollständige (bereits ent-NBSS-gerahmte und ggf. entschlüsselte)
/// eingehende SMB2-Nachricht und liefert die Antwort. Implementiert die Empfangs-Pipeline
/// (Context §19.1) für die Phase-1-Commands: NEGOTIATE, SESSION_SETUP, TREE_CONNECT,
/// TREE_DISCONNECT, LOGOFF, ECHO. Übrige Commands → <c>STATUS_NOT_SUPPORTED</c>.
/// Compound-Ketten (NextCommand) werden zerlegt und einzeln beantwortet (Context §7).
/// </summary>
public sealed partial class Smb2Dispatcher
{
    private readonly SmbServerState _server;

    private static readonly SecurityIdentity AnonymousIdentity = new()
    {
        DomainName = string.Empty,
        UserName = string.Empty,
        IsAnonymous = true,
    };

    private readonly Action<string>? _log;

    /// <summary>
    /// [AUDIT-2026-06] Kam der gerade verarbeitete Frame über einen TRANSFORM-Header (verschlüsselt)?
    /// Pro <see cref="ProcessMessage"/>-Aufruf gesetzt. Da ProcessMessage je Connection-Dispatcher
    /// sequenziell läuft, ist dieses Feld innerhalb eines Aufrufs eindeutig. Steuert das Überspringen
    /// der Eingangs-Signaturprüfung (AEAD authentifiziert bereits, §3.1.4.1).
    /// </summary>
    private bool _frameWasEncrypted;

    public Smb2Dispatcher(SmbServerState server, Action<string>? logger = null)
    {
        _server = server;
        _log = logger;
    }

    /// <summary>
    /// Verarbeitet eine eingehende Nachricht (eine oder mehrere via NextCommand verkettete
    /// SMB2-Nachrichten). Liefert die zusammengesetzte Antwort. <paramref name="transportEncrypted"/>
    /// gibt an, ob die Nachricht über einen TRANSFORM-Frame (verschlüsselt) ankam (§11).
    /// </summary>
    public byte[] ProcessMessage(SmbConnection connection, ReadOnlySpan<byte> message, bool transportEncrypted = false)
    {
        // SMB1 Multi-Protocol-Negotiate (§6.1): Altclients (z.B. impacket) schicken zuerst ein
        // SMB1 SMB_COM_NEGOTIATE (ProtocolId FF 53 4D 42). Darauf mit einer SMB2-NEGOTIATE-Response
        // mit DialectRevision 0x02FF (Wildcard) antworten; danach kommt das echte SMB2-NEGOTIATE.
        if (SmbProtocolIds.IsSmb1(message) && message.Length > 4 && message[4] == 0x72 /* SMB_COM_NEGOTIATE */)
            return BuildSmb1WildcardNegotiateResponse();

        _frameWasEncrypted = transportEncrypted; // [AUDIT-2026-06] gilt für alle Segmente dieses Frames.

        var segments = new List<ResponseSegment>();
        int offset = 0;
        ulong relatedSessionId = 0;
        uint relatedTreeId = 0;

        while (offset < message.Length)
        {
            Smb2Header header;
            try
            {
                header = Smb2Header.Read(message[offset..]);
            }
            catch (SmbWireFormatException ex)
            {
                // Malformed Header → generische Fehlerantwort (Context §19.1 Schritt 6).
                _log?.Invoke($"[parse] ungültiger Header → INVALID_PARAMETER: {ex.Message}; Bytes: {Hex(message[offset..])}");
                segments.Add(BuildError(new Smb2Header { Command = SmbCommand.Negotiate }, NtStatus.InvalidParameter));
                break;
            }

            // Compound-Grenzen bestimmen.
            int segmentLength = header.NextCommand != 0
                ? (int)header.NextCommand
                : message.Length - offset;
            ReadOnlySpan<byte> segment = message.Slice(offset, segmentLength);

            // Related-Operation erbt SessionId/TreeId des Vorgängers (Context §7).
            if (header.Flags.HasFlag(Smb2HeaderFlags.RelatedOperations))
            {
                header.SessionId = relatedSessionId;
                header.TreeId = relatedTreeId;
            }
            else
            {
                relatedSessionId = header.SessionId;
                relatedTreeId = header.TreeId;
            }

            _log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} tid={header.TreeId} len={segment.Length} charge={header.CreditCharge}");
            ResponseSegment? response = DispatchOne(connection, header, segment, transportEncrypted);
            _log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} → {(response is { } r ? r.Header.Status.ToString() : "(keine Antwort)")}");
            if (response is { } seg) segments.Add(seg);

            if (header.NextCommand == 0) break;
            offset += segmentLength;
        }

        return AssembleResponse(segments);
    }

    private ResponseSegment? DispatchOne(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool transportEncrypted)
    {
        try
        {
            // Verschlüsselungspflicht prüfen, bevor der Command überhaupt verarbeitet wird
            // (§3.3.5.2.11): Ist die Session global oder der adressierte Tree verschlüsselungs-
            // pflichtig und kam der Request unverschlüsselt an → ablehnen.
            if (!transportEncrypted && RequiresEncryptedTransport(connection, header))
                return BuildError(header, NtStatus.AccessDenied);

            // [AUDIT-2026-06] MessageId gegen das Sequenz-/Credit-Fenster prüfen (§3.3.5.2.3).
            // Bisher toter Code (CreditManager.IsWithinWindow wurde nie aufgerufen) → Replays und
            // wild springende MessageIds wurden akzeptiert. Siehe docs/SECURITY_AUDIT.md (Finding H2).
            if (!ValidateSequence(connection, header))
                return BuildError(header, NtStatus.InvalidParameter);

            return header.Command switch
            {
                SmbCommand.Negotiate => HandleNegotiate(connection, header, segment),
                SmbCommand.SessionSetup => HandleSessionSetup(connection, header, segment),
                SmbCommand.TreeConnect => HandleTreeConnect(connection, header, segment),
                SmbCommand.TreeDisconnect => HandleTreeDisconnect(connection, header, segment),
                SmbCommand.Logoff => HandleLogoff(connection, header, segment),
                SmbCommand.Echo => HandleEcho(connection, header, segment),
                SmbCommand.Create => HandleCreate(connection, header, segment),
                SmbCommand.Close => HandleClose(connection, header, segment),
                SmbCommand.Read => HandleRead(connection, header, segment),
                SmbCommand.Write => HandleWrite(connection, header, segment),
                SmbCommand.QueryDirectory => HandleQueryDirectory(connection, header, segment),
                SmbCommand.QueryInfo => HandleQueryInfo(connection, header, segment),
                SmbCommand.SetInfo => HandleSetInfo(connection, header, segment),
                SmbCommand.Flush => HandleFlush(connection, header, segment),
                SmbCommand.Ioctl => HandleIoctl(connection, header, segment),
                SmbCommand.Lock => HandleLock(connection, header, segment),
                SmbCommand.Cancel => HandleCancel(connection, header, segment),
                SmbCommand.ChangeNotify => HandleChangeNotify(connection, header, segment),
                SmbCommand.OplockBreak => HandleOplockBreak(connection, header, segment),
                _ => BuildError(header, NtStatus.NotSupported),
            };
        }
        catch (SmbWireFormatException ex)
        {
            _log?.Invoke($"[parse] {header.Command} → INVALID_PARAMETER: {ex.Message}; Bytes: {Hex(segment)}");
            return BuildError(header, NtStatus.InvalidParameter);
        }
        catch (Exception ex)
        {
            // Schutznetz: Ein einzelner fehlgeschlagener Command (z.B. eine Dateisystem-
            // Ausnahme bei einem ungewöhnlichen Pfad) darf NIE die ganze Verbindung abreißen.
            // Auf einen sauberen NTSTATUS abbilden statt die Ausnahme bis in die Lese-Schleife
            // durchschlagen zu lassen (wo IOException stillschweigend als Disconnect gilt).
            _log?.Invoke($"[error] {header.Command} mid={header.MessageId} → {ex.GetType().Name}: {ex.Message}");
            return BuildError(header, MapException(ex));
        }
    }

    /// <summary>
    /// Bestimmt, ob ein Request verschlüsselt ankommen MUSS (RejectUnencryptedAccess, §3.3.5.2.11):
    /// wenn die adressierte Session global verschlüsselt ist oder der adressierte Tree EncryptData
    /// verlangt. NEGOTIATE/SESSION_SETUP sind ausgenommen — deren Token-Austausch läuft im Klartext.
    /// Existiert die Session (noch) nicht, greift die reguläre Session-Prüfung im Handler.
    /// </summary>
    private bool RequiresEncryptedTransport(SmbConnection connection, Smb2Header header)
    {
        if (!_server.Options.RejectUnencryptedAccess) return false;
        if (header.Command is SmbCommand.Negotiate or SmbCommand.SessionSetup) return false;
        if (!connection.Sessions.TryGetValue(header.SessionId, out SmbSession? session)) return false;
        if (session.EncryptData) return true;
        return session.TreeConnects.TryGetValue(header.TreeId, out SmbTreeConnect? tree) && tree.EncryptData;
    }

    /// <summary>
    /// [AUDIT-2026-06] Prüft die MessageId gegen das gültige Sequenzfenster und zieht dessen untere
    /// Grenze nach (§3.3.5.2.3). Ausnahmen: vor abgeschlossenem NEGOTIATE; NEGOTIATE selbst; CANCEL
    /// (referenziert eine bereits konsumierte MessageId und trägt keine neue); Related-Compound-
    /// Elemente (werden mit dem Lead-Element gebündelt). Anfragen treffen pro Verbindung monoton
    /// steigend ein (TCP ist geordnet), daher genügt das Nachziehen der Untergrenze.
    /// </summary>
    private static bool ValidateSequence(SmbConnection connection, Smb2Header header)
    {
        if (!connection.NegotiateDone) return true;
        if (header.Command is SmbCommand.Negotiate or SmbCommand.Cancel) return true;
        if (header.Flags.HasFlag(Smb2HeaderFlags.RelatedOperations)) return true;

        ushort charge = Math.Max(header.CreditCharge, (ushort)1);
        ulong start = connection.SequenceWindowStart;
        ulong size = connection.SequenceWindowSize == 0 ? 1 : connection.SequenceWindowSize;

        if (!CreditManager.IsWithinWindow(header.MessageId, start, size) ||
            !CreditManager.IsWithinWindow(header.MessageId + charge - 1, start, size))
            return false;

        ulong consumedUpTo = header.MessageId + charge;
        if (consumedUpTo > connection.SequenceWindowStart)
            connection.SequenceWindowStart = consumedUpTo;
        return true;
    }

    /// <summary>
    /// Muss eine (ASYNC-)Antwort verschlüsselt werden? Bei ASYNC-Headern fehlt die TreeId, daher
    /// kann der Host die Per-Share-Pflicht nicht aus den Bytes ableiten — wir bestimmen sie hier aus
    /// Session (global) bzw. dem Tree des zugehörigen Open und geben sie an den Sendekanal weiter.
    /// </summary>
    private static bool ResponseNeedsEncryption(SmbSession session, SmbOpen? open)
        => session.EncryptData || (open?.TreeConnect.EncryptData ?? false);

    /// <summary>Bildet eine unerwartete .NET-Ausnahme auf einen passenden NTSTATUS ab.</summary>
    private static NtStatus MapException(Exception ex) => ex switch
    {
        UnauthorizedAccessException => NtStatus.AccessDenied,
        FileNotFoundException => NtStatus.ObjectNameNotFound,
        DirectoryNotFoundException => NtStatus.ObjectPathNotFound,
        PathTooLongException or ArgumentException or NotSupportedException => NtStatus.ObjectNameInvalid,
        _ => NtStatus.InvalidParameter,
    };

    private static string Hex(ReadOnlySpan<byte> data)
    {
        int n = Math.Min(data.Length, 96);
        return Convert.ToHexString(data[..n]) + (data.Length > n ? "…" : "");
    }

    // --- SMB1 → SMB2 Upgrade (Context §6.1) ---

    /// <summary>
    /// Antwort auf ein SMB1 SMB_COM_NEGOTIATE: eine SMB2-NEGOTIATE-Response mit Wildcard-Dialekt
    /// 0x02FF. Der Client schickt danach ein echtes SMB2-NEGOTIATE. Diese Antwort verändert den
    /// Connection-Zustand nicht (kein finaler Dialekt, kein Preauth-Hash).
    /// </summary>
    private byte[] BuildSmb1WildcardNegotiateResponse()
    {
        var securityMode = SmbSecurityMode.SigningEnabled;
        if (_server.Options.RequireMessageSigning) securityMode |= SmbSecurityMode.SigningRequired;

        byte[] securityBuffer = _server.Options.SpnegoNegotiator!.CreateInitialServerToken();

        var response = new NegotiateResponse
        {
            SecurityMode = securityMode,
            DialectRevision = SmbDialect.Wildcard2FF,
            ServerGuid = _server.Options.ServerGuid,
            Capabilities = Smb2Capabilities.None,
            MaxTransactSize = _server.Options.MaxTransactSize,
            MaxReadSize = _server.Options.MaxReadSize,
            MaxWriteSize = _server.Options.MaxWriteSize,
            SystemTime = DateTime.UtcNow.ToFileTimeUtc(),
            ServerStartTime = 0,
            SecurityBuffer = securityBuffer,
            NegotiateContexts = [],
        };

        var header = new Smb2Header
        {
            Command = SmbCommand.Negotiate,
            MessageId = 0,
            Flags = Smb2HeaderFlags.ServerToRedir,
            Status = NtStatus.Success,
            CreditRequestResponse = 1,
        };

        return Concat(header.ToArray(), response.ToBody());
    }

    // --- NEGOTIATE (Context §6) ---

    private ResponseSegment HandleNegotiate(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (connection.NegotiateDone)
            return BuildError(header, NtStatus.InvalidParameter); // nur ein NEGOTIATE je Connection.

        NegotiateRequest request = NegotiateRequest.Parse(segment, Smb2Header.Size);
        byte[] securityBuffer = _server.Options.SpnegoNegotiator!.CreateInitialServerToken();

        NegotiateResponse response = NegotiateProcessor.BuildResponse(connection, request, _server.Options, securityBuffer);
        connection.NegotiateDone = true;

        // Sequenzfenster initialisieren (Context §7).
        connection.SequenceWindowStart = header.MessageId + 1;
        connection.SequenceWindowSize = _server.Options.MaxCreditsPerResponse;

        Smb2Header respHeader = header.CreateResponse(NtStatus.Success);
        respHeader.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        byte[] body = response.ToBody();

        // Preauth-Hash (3.1.1): NEGOTIATE-Request, dann -Response (Context §6.4, §8.2).
        if (connection.Dialect == SmbDialect.Smb311)
        {
            connection.PreauthHash.Append(segment);
            byte[] fullResponse = Concat(respHeader.ToArray(), body);
            connection.PreauthHash.Append(fullResponse);
        }

        return ResponseSegment.Unsigned(respHeader, body);
    }

    // --- SESSION_SETUP (Context §8) ---

    private ResponseSegment HandleSessionSetup(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        SessionSetupRequest request = SessionSetupRequest.Parse(segment, Smb2Header.Size);
        bool is311 = connection.Dialect == SmbDialect.Smb311;

        SmbSession session;
        if (header.SessionId == 0)
        {
            ulong sessionId = _server.AllocateSessionId();
            session = new SmbSession
            {
                SessionId = sessionId,
                SessionGlobalId = _server.AllocateSessionGlobalId(),
                Connection = connection,
                AuthContext = _server.Options.SpnegoNegotiator!.CreateServerContext(),
                PreauthHash = is311 ? connection.PreauthHash.Clone() : null,
            };
            connection.Sessions[sessionId] = session;
            _server.SessionGlobalList[sessionId] = session;
        }
        else if (!connection.Sessions.TryGetValue(header.SessionId, out session!))
        {
            return BuildError(header, NtStatus.UserSessionDeleted);
        }

        // A SESSION_SETUP targeting an already-established (Valid) session is a re-authentication
        // attempt. Re-auth is not supported yet (the per-session GSS mechanism is already complete),
        // so reject it WITHOUT touching the live session. Previously the finished mechanism was
        // re-run, returned a failure, and CleanupFailedSession then tore down the still-valid
        // session — so a stray or duplicated SESSION_SETUP could drop an active session (and, with
        // an always-succeeding mechanism, silently re-derive and change its keys mid-stream).
        if (header.SessionId != 0 && session.State == SessionState.Valid)
            return BuildError(header, NtStatus.AccessDenied);

        // Preauth-Hash: Request einbeziehen (vor evtl. Key-Derivation), Context §8.2.
        session.PreauthHash?.Append(segment);

        GssResult auth = session.AuthContext!.Accept(request.SecurityBuffer);

        if (auth.NeedsMoreProcessing)
        {
            var more = new SessionSetupResponse { SecurityBuffer = auth.OutToken ?? [] };
            Smb2Header h = BuildSessionHeader(header, session, NtStatus.MoreProcessingRequired);
            byte[] body = more.ToBody();

            // Zwischen-Response wird mit in den Hash genommen (Context §8.2).
            if (is311)
            {
                byte[] full = Concat(h.ToArray(), body);
                session.PreauthHash?.Append(full);
            }
            return ResponseSegment.Unsigned(h, body);
        }

        if (!auth.IsSuccess)
        {
            CleanupFailedSession(connection, session);
            return BuildError(header, auth.Status);
        }

        // Erfolg: Identität/Policy übernehmen.
        ApplyIdentity(session, auth);

        if (RejectByPolicy(session, out NtStatus rejectStatus))
        {
            CleanupFailedSession(connection, session);
            return BuildError(header, rejectStatus);
        }

        DeriveSessionKeys(connection, session, auth.SessionKey!);

        // [REVIEW-2026-06] Enforce global RequireEncryption at the session level: if the server
        // demands encryption but this connection can't provide it (dialect < 3.0 or no cipher
        // negotiated), refuse instead of serving the session in cleartext. Without this, such a
        // session proceeded unencrypted and RejectUnencryptedAccess never caught it (it keys off
        // session.EncryptData, which stays false here). Mirrors the per-share check in TREE_CONNECT.
        if (_server.Options.RequireEncryption
            && !(connection.Dialect.IsSmb3OrLater() && connection.SupportsEncryption))
        {
            CleanupFailedSession(connection, session);
            return BuildError(header, NtStatus.AccessDenied);
        }

        session.State = SessionState.Valid;

        var sessionFlags = SessionResponseFlags.None;
        if (session.IsGuest) sessionFlags |= SessionResponseFlags.IsGuest;
        if (session.IsAnonymous) sessionFlags |= SessionResponseFlags.IsNull;
        if (session.EncryptData) sessionFlags |= SessionResponseFlags.EncryptData;

        var response = new SessionSetupResponse { SessionFlags = sessionFlags, SecurityBuffer = auth.OutToken ?? [] };
        Smb2Header respHeader = BuildSessionHeader(header, session, NtStatus.Success);
        byte[] respBody = response.ToBody();

        // Finale Response: signieren (außer Guest/Anonymous), NICHT mehr in den Hash (Context §8.2/§8.4).
        bool sign = session.SigningRequired && !session.IsGuest && !session.IsAnonymous;
        return sign
            ? ResponseSegment.Signed(respHeader, respBody, session)
            : ResponseSegment.Unsigned(respHeader, respBody);
    }

    private Smb2Header BuildSessionHeader(Smb2Header request, SmbSession session, NtStatus status)
    {
        Smb2Header h = request.CreateResponse(status);
        h.SessionId = session.SessionId;
        h.CreditRequestResponse = CreditManager.ComputeCreditGrant(request.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        return h;
    }

    private static void ApplyIdentity(SmbSession session, GssResult auth)
    {
        SecurityIdentity identity = auth.Identity!;
        session.Identity = identity;
        session.IsAnonymous = identity.IsAnonymous;
        session.IsGuest = identity.IsGuest;
    }

    private bool RejectByPolicy(SmbSession session, out NtStatus status)
    {
        status = NtStatus.Success;
        if (session.IsGuest && _server.Options.RejectGuestAccess) { status = NtStatus.AccessDenied; return true; }
        if (session.IsAnonymous && !_server.Options.AllowAnonymousAccess) { status = NtStatus.AccessDenied; return true; }
        return false;
    }

    private void DeriveSessionKeys(SmbConnection connection, SmbSession session, byte[] gssSessionKey)
    {
        session.FullSessionKey = gssSessionKey;
        session.SessionKey = gssSessionKey.Length >= 16 ? gssSessionKey[..16] : Pad16(gssSessionKey);

        // Signing-Pflicht: global oder vom Client verlangt; nie für Guest/Anonymous (Context §8.4).
        session.SigningRequired = connection.ShouldSign && !session.IsGuest && !session.IsAnonymous;
        // Globale Verschlüsselungs-Policy auf Session-Ebene (per-Share-Encryption greift beim TREE_CONNECT).
        session.EncryptData = _server.Options.RequireEncryption
                              && connection.SupportsEncryption
                              && connection.Dialect.IsSmb3OrLater();

        if (connection.Dialect.IsSmb3OrLater())
        {
            byte[] preauth = session.PreauthHash?.Value ?? new byte[64];
            Smb3SessionKeys keys = Smb3KeyDerivation.Derive(
                connection.Dialect, connection.CipherId, session.SessionKey, session.FullSessionKey, preauth);
            session.SigningKey = keys.SigningKey;
            session.EncryptionKey = keys.EncryptionKey;
            session.DecryptionKey = keys.DecryptionKey;
            session.ApplicationKey = keys.ApplicationKey;
        }
        else
        {
            // 2.0.2 / 2.1: kein KDF — Signing nutzt den vollen GSS-Key direkt (Context §8.3).
            session.SigningKey = session.FullSessionKey;
        }
    }

    private void CleanupFailedSession(SmbConnection connection, SmbSession session)
    {
        connection.Sessions.TryRemove(session.SessionId, out _);
        _server.SessionGlobalList.TryRemove(session.SessionId, out _);
    }

    // --- TREE_CONNECT (Context §12) ---

    private ResponseSegment HandleTreeConnect(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        TreeConnectRequest request = TreeConnectRequest.Parse(segment, Smb2Header.Size);
        if (!_server.Shares.TryGet(request.ShareName, out IShare share))
            return BuildError(header, NtStatus.BadNetworkName);

        // Autorisierungs-Hook (Context §12): Zugriff prüfen und gewährte Zugriffsmaske bestimmen.
        var accessContext = new ShareAccessContext
        {
            Identity = session.Identity ?? AnonymousIdentity,
            Share = share,
            Connection = connection,
        };
        ShareAccessResult decision = _server.Options.ShareAccessPolicy.AuthorizeConnect(accessContext);
        if (!decision.Allowed)
            return BuildError(header, decision.DenyStatus);

        // Verschlüsselungspflicht des Shares (SMB2_SHAREFLAG_ENCRYPT_DATA, §3.3.5.7): Verlangt der
        // Share Verschlüsselung, die Connection kann sie aber nicht (Dialekt < 3.0 oder kein Cipher
        // ausgehandelt) → Zugriff verweigern, statt unverschlüsselt zu liefern.
        bool encryptTree = share.EncryptData;
        if (encryptTree && !(connection.Dialect.IsSmb3OrLater() && connection.SupportsEncryption))
            return BuildError(header, NtStatus.AccessDenied);

        ulong treeId = connection.AllocateTreeId();
        var tree = new SmbTreeConnect
        {
            TreeId = treeId,
            Session = session,
            Share = share,
            MaximalAccess = (uint)decision.MaximalAccess,
            EncryptData = encryptTree,
        };
        session.TreeConnects[treeId] = tree;

        var shareFlags = ShareFlags.ManualCaching;
        if (tree.EncryptData) shareFlags |= ShareFlags.EncryptData;

        var response = new TreeConnectResponse
        {
            ShareType = (byte)share.Type,
            ShareFlags = shareFlags,
            Capabilities = 0,
            MaximalAccess = tree.MaximalAccess,
        };

        Smb2Header respHeader = header.CreateResponse(NtStatus.Success);
        respHeader.TreeId = (uint)treeId;
        respHeader.SessionId = session.SessionId;
        respHeader.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);

        return MaybeSigned(session, respHeader, response.ToBody());
    }

    private ResponseSegment HandleTreeDisconnect(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        session.TreeConnects.TryRemove(header.TreeId, out _);

        Smb2Header respHeader = header.CreateResponse(NtStatus.Success);
        respHeader.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        return MaybeSigned(session, respHeader, TreeDisconnectMessage.BuildResponseBody());
    }

    // --- LOGOFF / ECHO ---

    private ResponseSegment HandleLogoff(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        // [AUDIT-2026-06] LOGOFF prüfte zuvor — anders als alle anderen Session-Handler — KEINE
        // Signatur; ein eingeschleustes LOGOFF konnte eine signaturpflichtige Session abreißen.
        // Siehe docs/SECURITY_AUDIT.md (Finding M4).
        if (!VerifyInboundSignature(session, header, segment))
            return BuildError(header, NtStatus.AccessDenied);

        connection.Sessions.TryRemove(session.SessionId, out _);
        _server.SessionGlobalList.TryRemove(session.SessionId, out _);
        session.State = SessionState.Expired;

        Smb2Header respHeader = header.CreateResponse(NtStatus.Success);
        respHeader.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        return MaybeSigned(session, respHeader, LogoffMessage.BuildResponseBody());
    }

    private ResponseSegment HandleEcho(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        EchoMessage.ValidateRequest(segment[Smb2Header.Size..]);

        SmbSession? session = null;
        if (header.SessionId != 0)
        {
            if (!TryGetValidSession(connection, header.SessionId, out SmbSession s))
                return BuildError(header, NtStatus.UserSessionDeleted);
            session = s;
            if (!VerifyInboundSignature(session, header, segment))
                return BuildError(header, NtStatus.AccessDenied);
        }

        Smb2Header respHeader = header.CreateResponse(NtStatus.Success);
        respHeader.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        byte[] body = EchoMessage.BuildResponseBody();

        return session is { SigningRequired: true }
            ? ResponseSegment.Signed(respHeader, body, session)
            : ResponseSegment.Unsigned(respHeader, body);
    }

    // --- Hilfsfunktionen ---

    private bool TryGetValidSession(SmbConnection connection, ulong sessionId, out SmbSession session)
    {
        if (connection.Sessions.TryGetValue(sessionId, out session!) && session.State == SessionState.Valid)
            return true;
        session = null!;
        return false;
    }

    /// <summary>
    /// Prüft die Signatur eingehender Nachrichten, wenn die Session Signing verlangt
    /// (Context §10 Eingangsprüfung). Nicht-signierungspflichtige Sessions passieren.
    /// </summary>
    private bool VerifyInboundSignature(SmbSession session, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        // [AUDIT-2026-06] Verschlüsselt empfangene Frames sind durch das AEAD bereits authentifiziert
        // (§3.1.4.1) und tragen keine Signatur. Früher löschte der Host dafür session.SigningRequired
        // dauerhaft (Downgrade-Risiko, sobald RejectUnencryptedAccess aus war) — jetzt überspringen wir
        // nur die Prüfung dieses einen Frames, ohne die Session-Policy zu verändern.
        // Siehe docs/SECURITY_AUDIT.md (Finding M2).
        if (_frameWasEncrypted) return true;
        if (!session.SigningRequired) return true;
        if (!header.Flags.HasFlag(Smb2HeaderFlags.Signed)) return false;

        SmbSigningAlgorithmId alg = Smb2Signer.ResolveAlgorithm(session.Connection.Dialect, session.Connection.SigningAlgorithmId);
        bool isCancel = header.Command == SmbCommand.Cancel;
        return Smb2Signer.Verify(alg, session.SigningKey, segment, header.MessageId, isServer: false, isCancel);
    }

    private ResponseSegment MaybeSigned(SmbSession session, Smb2Header header, byte[] body)
        => session.SigningRequired
            ? ResponseSegment.Signed(header, body, session)
            : ResponseSegment.Unsigned(header, body);

    private static ResponseSegment BuildError(Smb2Header request, NtStatus status)
    {
        Smb2Header h = request.CreateResponse(status);
        return ResponseSegment.Unsigned(h, ErrorResponse.BuildBody());
    }

    /// <summary>Setzt die Segmente zur finalen Nachricht zusammen, patcht NextCommand und signiert.</summary>
    private static byte[] AssembleResponse(List<ResponseSegment> segments)
    {
        var writer = new GrowableWriter(256);
        for (int i = 0; i < segments.Count; i++)
        {
            ResponseSegment seg = segments[i];
            bool isLast = i == segments.Count - 1;

            int segStart = writer.Position;
            int segLength = Smb2Header.Size + seg.Body.Length;
            int padded = isLast ? segLength : Align8(segLength);
            seg.Header.NextCommand = isLast ? 0 : (uint)padded;

            writer.WriteBytes(seg.Header.ToArray());
            writer.WriteBytes(seg.Body);
            if (padded > segLength) writer.WriteZeros(padded - segLength);

            if (seg.Sign && seg.SigningSession is { } s)
            {
                Span<byte> segSpan = writer.WrittenSpan.Slice(segStart, padded);
                Smb2Header h = seg.Header;
                h.Flags |= Smb2HeaderFlags.Signed;
                // Flags-Feld im bereits geschriebenen Header aktualisieren (Offset 16).
                writer.PatchUInt32(segStart + 16, (uint)h.Flags);

                SmbSigningAlgorithmId alg = Smb2Signer.ResolveAlgorithm(s.Connection.Dialect, s.Connection.SigningAlgorithmId);
                Smb2Signer.SignInPlace(alg, s.SigningKey, segSpan, h.MessageId, isServer: true, isCancel: false);
            }
        }
        return writer.ToArray();
    }

    private static int Align8(int v) => (v + 7) & ~7;
    private static byte[] Concat(byte[] a, byte[] b) { var r = new byte[a.Length + b.Length]; a.CopyTo(r, 0); b.CopyTo(r, a.Length); return r; }
    private static byte[] Pad16(byte[] input) { var r = new byte[16]; Array.Copy(input, r, Math.Min(16, input.Length)); return r; }

    /// <summary>Eine fertige Antwort-Nachricht (Header + Body) plus Signier-Entscheidung.</summary>
    private readonly struct ResponseSegment
    {
        public Smb2Header Header { get; }
        public byte[] Body { get; }
        public bool Sign { get; }
        public SmbSession? SigningSession { get; }

        private ResponseSegment(Smb2Header header, byte[] body, bool sign, SmbSession? session)
        {
            Header = header; Body = body; Sign = sign; SigningSession = session;
        }

        public static ResponseSegment Unsigned(Smb2Header header, byte[] body) => new(header, body, false, null);
        public static ResponseSegment Signed(Smb2Header header, byte[] body, SmbSession session) => new(header, body, true, session);
    }
}
