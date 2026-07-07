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
/// Processes a complete (already un-NBSS-framed and optionally decrypted)
/// incoming SMB2 message and returns the response. Implements the receive pipeline
/// (Context §19.1) for the core commands: NEGOTIATE, SESSION_SETUP, TREE_CONNECT,
/// TREE_DISCONNECT, LOGOFF, ECHO. Other commands → <c>STATUS_NOT_SUPPORTED</c>.
/// Compound chains (NextCommand) are split and answered individually (Context §7).
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

    public Smb2Dispatcher(SmbServerState server, Action<string>? logger = null)
    {
        _server = server;
        _log = logger;
    }

    /// <summary>
    /// Synchronous convenience wrapper around <see cref="ProcessMessageAsync"/> — for tests and
    /// hosts without an async path. With purely synchronous backends (<see cref="SyncFileStore"/>)
    /// the ValueTask chain completes synchronously anyway.
    /// </summary>
    public byte[] ProcessMessage(SmbConnection connection, ReadOnlySpan<byte> message, bool transportEncrypted = false)
        => ProcessMessageAsync(connection, message.ToArray(), transportEncrypted).AsTask().GetAwaiter().GetResult();

    /// <summary>
    /// Processes an incoming message (one or more SMB2 messages chained via NextCommand).
    /// Returns the assembled response. <paramref name="transportEncrypted"/>
    /// indicates whether the message arrived via a TRANSFORM frame (encrypted) (§11).
    /// </summary>
    public async ValueTask<byte[]> ProcessMessageAsync(SmbConnection connection, ReadOnlyMemory<byte> message, bool transportEncrypted = false)
    {
        // SMB1 Multi-Protocol-Negotiate (§6.1): legacy clients (e.g. impacket) first send an
        // SMB1 SMB_COM_NEGOTIATE (ProtocolId FF 53 4D 42). Respond with an SMB2 NEGOTIATE response
        // with DialectRevision 0x02FF (wildcard); the real SMB2 NEGOTIATE follows after.
        if (SmbProtocolIds.IsSmb1(message.Span) && message.Length > 4 && message.Span[4] == 0x72 /* SMB_COM_NEGOTIATE */)
            return BuildSmb1WildcardNegotiateResponse();


        var segments = new List<ResponseSegment>();
        int offset = 0;
        ulong relatedSessionId = 0;
        uint relatedTreeId = 0;

        while (offset < message.Length)
        {
            Smb2Header header;
            try
            {
                header = Smb2Header.Read(message.Span[offset..]);
            }
            catch (SmbWireFormatException ex)
            {
                // Malformed header → generic error response (Context §19.1 step 6).
                _log?.Invoke($"[parse] invalid header → INVALID_PARAMETER: {ex.Message}; Bytes: {Hex(message.Span[offset..])}");

                segments.Add(BuildError(new Smb2Header { Command = SmbCommand.Negotiate }, NtStatus.InvalidParameter));
                break;
            }

            // Determine compound boundaries.
            int segmentLength = header.NextCommand != 0
                ? (int)header.NextCommand
                : message.Length - offset;
            ReadOnlyMemory<byte> segment = message.Slice(offset, segmentLength);

            // Related operation inherits SessionId/TreeId from the predecessor (Context §7).
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
            ResponseSegment? response = await DispatchOneAsync(connection, header, segment, transportEncrypted).ConfigureAwait(false);
            _log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} → {(response is { } r ? r.Header.Status.ToString() : "(no response)")}");

            if (response is { } seg) segments.Add(seg);

            if (header.NextCommand == 0) break;
            offset += segmentLength;
        }

        return AssembleResponse(connection, segments);
    }

    /// <summary>
    /// Processes a single segment. <paramref name="frameEncrypted"/> is passed as a parameter
    /// (not an instance field), so frames on the same connection can be processed concurrently
    /// without corrupting each other's encryption state.
    /// </summary>
    private async ValueTask<ResponseSegment?> DispatchOneAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted, bool preValidated = false)
    {
        try
        {
            // preValidated: TryBeginConcurrentFrame already checked encryption requirement and
            // sequence window in the read loop (A4) — do not double-consume.
            if (!preValidated)
            {
                // Check encryption requirement before the command is processed at all
                // (§3.3.5.2.11): if the session globally or the addressed tree requires
                // encryption and the request arrived unencrypted → reject.
                if (!frameEncrypted && RequiresEncryptedTransport(connection, header))
                    return BuildError(header, NtStatus.AccessDenied);

                // [AUDIT-2026-06] Validate MessageId against the sequence/credit window (§3.3.5.2.3).
                // Previously dead code (CreditManager.IsWithinWindow was never called) → replays and
                // wildly jumping MessageIds were accepted. See docs/SECURITY_AUDIT.md (Finding H2).
                if (!ValidateSequence(connection, header))
                    return BuildError(header, NtStatus.InvalidParameter);
            }

            // Make the authenticated caller available to a per-user IFileStore backend (ambient,
            // valid for this command only; reset in the finally below).
            SetAmbientCaller(connection, header);

            return header.Command switch
            {
                SmbCommand.Negotiate => HandleNegotiate(connection, header, segment.Span),
                SmbCommand.SessionSetup => HandleSessionSetup(connection, header, segment.Span),
                SmbCommand.TreeConnect => HandleTreeConnect(connection, header, segment.Span, frameEncrypted),
                SmbCommand.TreeDisconnect => HandleTreeDisconnect(connection, header, segment.Span, frameEncrypted),
                SmbCommand.Logoff => HandleLogoff(connection, header, segment.Span, frameEncrypted),
                SmbCommand.Echo => HandleEcho(connection, header, segment.Span, frameEncrypted),
                SmbCommand.Create => await HandleCreateAsync(connection, header, segment, frameEncrypted).ConfigureAwait(false),
                SmbCommand.Close => await HandleCloseAsync(connection, header, segment, frameEncrypted).ConfigureAwait(false),
                SmbCommand.Read => await HandleReadAsync(connection, header, segment, frameEncrypted).ConfigureAwait(false),
                SmbCommand.Write => await HandleWriteAsync(connection, header, segment, frameEncrypted).ConfigureAwait(false),
                SmbCommand.QueryDirectory => await HandleQueryDirectoryAsync(connection, header, segment, frameEncrypted).ConfigureAwait(false),
                SmbCommand.QueryInfo => await HandleQueryInfoAsync(connection, header, segment, frameEncrypted).ConfigureAwait(false),
                SmbCommand.SetInfo => await HandleSetInfoAsync(connection, header, segment, frameEncrypted).ConfigureAwait(false),
                SmbCommand.Flush => await HandleFlushAsync(connection, header, segment, frameEncrypted).ConfigureAwait(false),
                SmbCommand.Ioctl => await HandleIoctlAsync(connection, header, segment, frameEncrypted).ConfigureAwait(false),
                SmbCommand.Lock => HandleLock(connection, header, segment.Span, frameEncrypted),
                SmbCommand.Cancel => HandleCancel(connection, header, segment.Span),
                SmbCommand.ChangeNotify => HandleChangeNotify(connection, header, segment.Span, frameEncrypted),
                SmbCommand.OplockBreak => HandleOplockBreak(connection, header, segment.Span, frameEncrypted),
                _ => BuildError(header, NtStatus.NotSupported),
            };
        }
        catch (SmbWireFormatException ex)
        {
            _log?.Invoke($"[parse] {header.Command} → INVALID_PARAMETER: {ex.Message}; Bytes: {Hex(segment.Span)}");
            return BuildError(header, NtStatus.InvalidParameter);
        }
        catch (Exception ex)
        {
            // Safety net: a single failed command (e.g. a filesystem exception for an unusual path)
            // must NEVER tear down the whole connection. Map to a clean NTSTATUS instead of letting
            // the exception propagate to the read loop (where IOException silently counts as disconnect).
            _log?.Invoke($"[error] {header.Command} mid={header.MessageId} → {ex.GetType().Name}: {ex.Message}");
            return BuildError(header, MapException(ex));
        }
        finally
        {
            // Identity is ambient for one command only — never leak it to the next request on this flow.
            SmbCaller.Current = null;
        }
    }

    /// <summary>
    /// Publishes the session's authenticated identity as the ambient <see cref="SmbCaller"/> for the
    /// duration of this command, so a per-user <see cref="IFileStore"/> backend can resolve the user.
    /// No session yet (e.g. NEGOTIATE/SESSION_SETUP) → cleared.
    /// </summary>
    private static void SetAmbientCaller(SmbConnection connection, Smb2Header header)
    {
        SmbCaller.Current =
            connection.Sessions.TryGetValue(header.SessionId, out SmbSession? session) && session.Identity is { } id
                ? new CallerInfo(id.DomainName, id.UserName)
                : null;
    }

    /// <summary>
    /// Determines whether a request MUST arrive encrypted (RejectUnencryptedAccess, §3.3.5.2.11):
    /// when the addressed session is globally encrypted or the addressed tree requires EncryptData.
    /// NEGOTIATE/SESSION_SETUP are exempted — their token exchange runs in plaintext.
    /// If the session does not (yet) exist, the regular session check in the handler applies.
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
    /// [AUDIT-2026-06] Validates the MessageId against the valid sequence window and advances its lower
    /// bound (§3.3.5.2.3). Exceptions: before NEGOTIATE is complete; NEGOTIATE itself; CANCEL
    /// (references an already-consumed MessageId and carries no new one); related compound
    /// elements (bundled with the lead element). Requests arrive monotonically increasing per connection
    /// (TCP is ordered), so advancing the lower bound is sufficient.
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
    /// Does an (ASYNC) response need to be encrypted? ASYNC headers lack the TreeId, so
    /// the host cannot derive the per-share requirement from the bytes — we determine it here from
    /// the session (global) or the tree of the associated open and pass it to the send channel.
    /// </summary>
    private static bool ResponseNeedsEncryption(SmbSession session, SmbOpen? open)
        => session.EncryptData || (open?.TreeConnect.EncryptData ?? false);

    /// <summary>Maps an unexpected .NET exception to an appropriate NTSTATUS.</summary>
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
    /// Response to an SMB1 SMB_COM_NEGOTIATE: an SMB2 NEGOTIATE response with wildcard dialect
    /// 0x02FF. The client then sends a real SMB2 NEGOTIATE. This response does not modify
    /// connection state (no final dialect, no preauth hash).
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
            return BuildError(header, NtStatus.InvalidParameter); // only one NEGOTIATE per connection.

        NegotiateRequest request = NegotiateRequest.Parse(segment, Smb2Header.Size);

        // [AUDIT-2026-06] O3: a client offering SMB 3.1.1 MUST send a PreauthIntegrityCapabilities
        // context advertising a hash algorithm the server supports (SHA-512); otherwise the negotiate
        // is malformed and MUST be rejected (§3.3.5.4). Without this the preauth-integrity hash would
        // have no agreed algorithm.
        if (request.OffersSmb311 && !HasSupportedPreauthContext(request))
            return BuildError(header, NtStatus.InvalidParameter);

        byte[] securityBuffer = _server.Options.SpnegoNegotiator!.CreateInitialServerToken();

        NegotiateResponse response = NegotiateProcessor.BuildResponse(connection, request, _server.Options, securityBuffer);
        connection.NegotiateDone = true;

        // Initialize sequence window (Context §7).
        connection.SequenceWindowStart = header.MessageId + 1;
        connection.SequenceWindowSize = _server.Options.MaxCreditsPerResponse;

        Smb2Header respHeader = header.CreateResponse(NtStatus.Success);
        respHeader.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        byte[] body = response.ToBody();

        // Preauth hash (3.1.1): NEGOTIATE request, then response (Context §6.4, §8.2).
        if (connection.Dialect == SmbDialect.Smb311)
        {
            connection.PreauthHash.Append(segment);
            byte[] fullResponse = Concat(respHeader.ToArray(), body);
            connection.PreauthHash.Append(fullResponse);
        }

        return ResponseSegment.Unsigned(respHeader, body);
    }

    /// <summary>
    /// [AUDIT-2026-06] O3: true if the request carries a PreauthIntegrityCapabilities context that
    /// lists a hash algorithm the server supports (SHA-512). Required when SMB 3.1.1 is offered.
    /// </summary>
    private static bool HasSupportedPreauthContext(NegotiateRequest request)
    {
        foreach (NegotiateContext ctx in request.NegotiateContexts)
            if (ctx is PreauthIntegrityContext preauth
                && preauth.HashAlgorithms.Contains(PreauthHashAlgorithm.Sha512))
                return true;
        return false;
    }

    // --- SESSION_SETUP (Context §8) ---

    private ResponseSegment HandleSessionSetup(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
    {
        // [AUDIT-2026-06] O4: SESSION_SETUP is only valid once NEGOTIATE has completed (§3.3.5.5.1).
        // Before that the connection has no negotiated dialect/security state, so reject instead of
        // acting on an undefined state.
        if (!connection.NegotiateDone)
            return BuildError(header, NtStatus.InvalidParameter);

        SessionSetupRequest request = SessionSetupRequest.Parse(segment, Smb2Header.Size);
        bool is311 = connection.Dialect == SmbDialect.Smb311;

        // SMB 3.x session binding (multichannel, §3.3.5.5.2): a second connection joins an existing
        // session to aggregate throughput / provide failover. Handled on its own path — the session
        // is already authenticated, only a new channel (with its own signing key) is added.
        if (request.Flags.HasFlag(SessionSetupFlags.Binding))
            return HandleSessionBinding(connection, header, request, segment, is311);

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

        // Preauth hash: include request (before possible key derivation), Context §8.2.
        session.PreauthHash?.Append(segment);

        GssResult auth = session.AuthContext!.Accept(request.SecurityBuffer);

        if (auth.NeedsMoreProcessing)
        {
            var more = new SessionSetupResponse { SecurityBuffer = auth.OutToken ?? [] };
            Smb2Header h = BuildSessionHeader(header, session, NtStatus.MoreProcessingRequired);
            byte[] body = more.ToBody();

            // Intermediate response is also included in the hash (Context §8.2).
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

        // Success: apply identity/policy.
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

        // Register the primary channel (Context §8.1 Session.ChannelList). Its signing key is the
        // session signing key; further connections bind additional channels with their own keys.
        // Tracking it here also makes channel-aware teardown correct: the session survives until the
        // last channel closes. Only for 3.x, where multichannel exists.
        if (connection.Dialect.IsSmb3OrLater())
            session.Channels[connection.ConnectionId] = new SmbChannel { Connection = connection, SigningKey = session.SigningKey };

        var sessionFlags = SessionResponseFlags.None;
        if (session.IsGuest) sessionFlags |= SessionResponseFlags.IsGuest;
        if (session.IsAnonymous) sessionFlags |= SessionResponseFlags.IsNull;
        if (session.EncryptData) sessionFlags |= SessionResponseFlags.EncryptData;

        var response = new SessionSetupResponse { SessionFlags = sessionFlags, SecurityBuffer = auth.OutToken ?? [] };
        Smb2Header respHeader = BuildSessionHeader(header, session, NtStatus.Success);
        byte[] respBody = response.ToBody();

        // Final response: sign (except guest/anonymous), NOT included in hash anymore (Context §8.2/§8.4).
        bool sign = session.SigningRequired && !session.IsGuest && !session.IsAnonymous;
        return sign
            ? ResponseSegment.Signed(respHeader, respBody, session)
            : ResponseSegment.Unsigned(respHeader, respBody);
    }

    /// <summary>
    /// Handles a <c>SESSION_SETUP</c> carrying <c>SMB2_SESSION_FLAG_BINDING</c> (§3.3.5.5.2): a new
    /// connection joins an existing, already-authenticated session as an additional channel. The
    /// binding request must be signed under the session key (proving the new connection possesses it);
    /// the client re-authenticates over GSS (so the identity can be confirmed and a per-channel signing
    /// key derived, §3.3.5.5.3). On success the connection is registered as a channel and shares the
    /// session's identity, keys, tree connects and opens.
    /// </summary>
    private ResponseSegment HandleSessionBinding(SmbConnection connection, Smb2Header header,
        SessionSetupRequest request, ReadOnlySpan<byte> segment, bool is311)
    {
        // Multichannel is an SMB 3.x feature — reject binding on 2.x.
        if (!connection.Dialect.IsSmb3OrLater())
            return BuildError(header, NtStatus.RequestNotAccepted);

        // The target session must exist in the global table (it may live on another connection).
        if (header.SessionId == 0 ||
            !_server.SessionGlobalList.TryGetValue(header.SessionId, out SmbSession? session))
            return BuildError(header, NtStatus.UserSessionDeleted);

        // Binding a connection that already carries this session is not a new channel.
        if (connection.Sessions.ContainsKey(session.SessionId))
            return BuildError(header, NtStatus.RequestNotAccepted);

        // The session must have finished authenticating on its first channel before others bind.
        if (session.State != SessionState.Valid)
            return BuildError(header, NtStatus.InvalidParameter);

        // The channel must use the same dialect the session negotiated (§3.3.5.5.2).
        if (connection.Dialect != session.Connection.Dialect)
            return BuildError(header, NtStatus.InvalidParameter);

        // Defence in depth: only bind channels originating from the same client.
        if (!connection.ClientGuid.AsSpan().SequenceEqual(session.Connection.ClientGuid))
            return BuildError(header, NtStatus.AccessDenied);

        // The binding request MUST be signed and verify under the *session* signing key — this proves
        // the new connection holds the session key (§3.3.5.5.2). Encryption-only is not accepted here.
        if (!header.Flags.HasFlag(Smb2HeaderFlags.Signed))
            return BuildError(header, NtStatus.AccessDenied);
        SmbSigningAlgorithmId sesAlg = Smb2Signer.ResolveAlgorithm(session.Connection.Dialect, session.Connection.SigningAlgorithmId);
        if (!Smb2Signer.Verify(sesAlg, session.SigningKey, segment, header.MessageId, isServer: false, isCancel: false))
            return BuildError(header, NtStatus.AccessDenied);

        // Per-channel GSS state (fresh SPNEGO context + this channel's preauth hash) lives on the
        // connection across the (possibly multi-leg) exchange until the channel is established.
        ChannelBindInProgress bind = connection.PendingBindings.GetOrAdd(session.SessionId, _ =>
            new ChannelBindInProgress
            {
                AuthContext = _server.Options.SpnegoNegotiator!.CreateServerContext(),
                PreauthHash = is311 ? connection.PreauthHash.Clone() : null,
            });

        // 3.1.1: the channel signing key is bound to this channel's own preauth hash → include the request.
        bind.PreauthHash?.Append(segment);

        GssResult auth = bind.AuthContext.Accept(request.SecurityBuffer);

        if (auth.NeedsMoreProcessing)
        {
            var more = new SessionSetupResponse { SecurityBuffer = auth.OutToken ?? [] };
            Smb2Header mh = BuildSessionHeader(header, session, NtStatus.MoreProcessingRequired);
            byte[] mbody = more.ToBody();
            if (is311) bind.PreauthHash?.Append(Concat(mh.ToArray(), mbody));
            // Intermediate binding responses are signed with the session key (no channel yet); the
            // ResponseSegment resolves session.SigningKeyFor(connection), which falls back to it.
            return ResponseSegment.Signed(mh, mbody, session);
        }

        if (!auth.IsSuccess)
        {
            connection.PendingBindings.TryRemove(session.SessionId, out _);
            return BuildError(header, auth.Status);
        }

        // The re-authenticated identity MUST be the session's own — binding must not change the
        // principal (§3.3.5.5.2). Anonymous/guest sessions cannot host bound channels.
        if (!SameIdentity(session.Identity, auth.Identity))
        {
            connection.PendingBindings.TryRemove(session.SessionId, out _);
            return BuildError(header, NtStatus.AccessDenied);
        }

        connection.PendingBindings.TryRemove(session.SessionId, out _);

        // Derive the channel signing key from the *session* key — never the binding auth's session key
        // (§3.3.5.5.3). For 3.1.1 the channel's own preauth hash makes it distinct per channel; for
        // 3.0/3.0.2 the KDF has no preauth input, so it equals the session signing key.
        byte[] channelKey = DeriveChannelSigningKey(connection, session, bind.PreauthHash);
        session.Channels[connection.ConnectionId] = new SmbChannel { Connection = connection, SigningKey = channelKey };
        connection.Sessions[session.SessionId] = session;

        var flags = SessionResponseFlags.None;
        if (session.EncryptData) flags |= SessionResponseFlags.EncryptData;
        var response = new SessionSetupResponse { SessionFlags = flags, SecurityBuffer = auth.OutToken ?? [] };
        Smb2Header respHeader = BuildSessionHeader(header, session, NtStatus.Success);
        byte[] respBody = response.ToBody();

        // The final binding response is signed with the *new channel* key: the channel is already
        // registered above, so ResponseSegment resolves session.SigningKeyFor(connection) to it.
        return ResponseSegment.Signed(respHeader, respBody, session);
    }

    /// <summary>Derives the signing key for a bound channel (§3.3.5.5.3). See <see cref="HandleSessionBinding"/>.</summary>
    private static byte[] DeriveChannelSigningKey(SmbConnection connection, SmbSession session, PreauthIntegrityHash? channelPreauth)
    {
        byte[] preauth = channelPreauth?.Value ?? new byte[64];
        Smb3SessionKeys keys = Smb3KeyDerivation.Derive(
            connection.Dialect, connection.CipherId, session.SessionKey, session.FullSessionKey, preauth);
        return keys.SigningKey;
    }

    /// <summary>
    /// True when two identities denote the same non-anonymous principal (used to confirm a binding
    /// re-auth targets the session's own user). Prefers the user SID; falls back to Domain\User.
    /// </summary>
    private static bool SameIdentity(SecurityIdentity? a, SecurityIdentity? b)
    {
        if (a is null || b is null) return false;
        if (a.IsAnonymous || b.IsAnonymous || a.IsGuest || b.IsGuest) return false;
        if (a.UserSid is not null && b.UserSid is not null)
            return string.Equals(a.UserSid, b.UserSid, StringComparison.OrdinalIgnoreCase);
        return string.Equals(a.DomainName, b.DomainName, StringComparison.OrdinalIgnoreCase)
            && string.Equals(a.UserName, b.UserName, StringComparison.OrdinalIgnoreCase);
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

        // Signing requirement: global or requested by client; never for guest/anonymous (Context §8.4).
        session.SigningRequired = connection.ShouldSign && !session.IsGuest && !session.IsAnonymous;
        // Global encryption policy at session level (per-share encryption applies at TREE_CONNECT).
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
            // 2.0.2 / 2.1: no KDF — signing uses the full GSS key directly (Context §8.3).
            session.SigningKey = session.FullSessionKey;
        }
    }

    private void CleanupFailedSession(SmbConnection connection, SmbSession session)
    {
        connection.Sessions.TryRemove(session.SessionId, out _);
        _server.SessionGlobalList.TryRemove(session.SessionId, out _);
    }

    // --- TREE_CONNECT (Context §12) ---

    private ResponseSegment HandleTreeConnect(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        TreeConnectRequest request = TreeConnectRequest.Parse(segment, Smb2Header.Size);
        if (!_server.Shares.TryGet(request.ShareName, out IShare share))
            return BuildError(header, NtStatus.BadNetworkName);

        // Authorization hook (Context §12): check access and determine the granted access mask.
        var accessContext = new ShareAccessContext
        {
            Identity = session.Identity ?? AnonymousIdentity,
            Share = share,
            Connection = connection,
        };
        ShareAccessResult decision = _server.Options.ShareAccessPolicy.AuthorizeConnect(accessContext);
        if (!decision.Allowed)
            return BuildError(header, decision.DenyStatus);

        // Share encryption requirement (SMB2_SHAREFLAG_ENCRYPT_DATA, §3.3.5.7): if the share
        // requires encryption but the connection cannot provide it (dialect < 3.0 or no cipher
        // negotiated) → deny access instead of serving unencrypted.
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

    private ResponseSegment HandleTreeDisconnect(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        session.TreeConnects.TryRemove(header.TreeId, out _);

        Smb2Header respHeader = header.CreateResponse(NtStatus.Success);
        respHeader.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        return MaybeSigned(session, respHeader, TreeDisconnectMessage.BuildResponseBody());
    }

    // --- LOGOFF / ECHO ---

    private ResponseSegment HandleLogoff(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
    {
        if (!TryGetValidSession(connection, header.SessionId, out SmbSession session))
            return BuildError(header, NtStatus.UserSessionDeleted);
        // [AUDIT-2026-06] LOGOFF previously — unlike all other session handlers — did NOT verify
        // the signature; an injected LOGOFF could tear down a session that requires signing.
        // See docs/SECURITY_AUDIT.md (Finding M4).
        if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
            return BuildError(header, NtStatus.AccessDenied);

        CloseSessionOpens(session); // release handles/locks/oplocks/share-modes of this session (O5)
        connection.Sessions.TryRemove(session.SessionId, out _);
        _server.SessionGlobalList.TryRemove(session.SessionId, out _);
        session.Channels.Clear(); // LOGOFF tears down the whole session across all bound channels
        session.State = SessionState.Expired;

        Smb2Header respHeader = header.CreateResponse(NtStatus.Success);
        respHeader.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        return MaybeSigned(session, respHeader, LogoffMessage.BuildResponseBody());
    }

    private ResponseSegment HandleEcho(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
    {
        EchoMessage.ValidateRequest(segment[Smb2Header.Size..]);

        SmbSession? session = null;
        if (header.SessionId != 0)
        {
            if (!TryGetValidSession(connection, header.SessionId, out SmbSession s))
                return BuildError(header, NtStatus.UserSessionDeleted);
            session = s;
            if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
                return BuildError(header, NtStatus.AccessDenied);
        }

        Smb2Header respHeader = header.CreateResponse(NtStatus.Success);
        respHeader.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
        byte[] body = EchoMessage.BuildResponseBody();

        return session is { SigningRequired: true }
            ? ResponseSegment.Signed(respHeader, body, session)
            : ResponseSegment.Unsigned(respHeader, body);
    }

    // --- Helper functions ---

    private bool TryGetValidSession(SmbConnection connection, ulong sessionId, out SmbSession session)
    {
        if (connection.Sessions.TryGetValue(sessionId, out session!) && session.State == SessionState.Valid)
            return true;
        session = null!;
        return false;
    }

    /// <summary>
    /// Verifies the signature of incoming messages when the session requires signing
    /// (Context §10 inbound check). Sessions that do not require signing pass through.
    /// </summary>
    private static bool VerifyInboundSignature(SmbConnection connection, SmbSession session, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
    {
        // [AUDIT-2026-06] Frames received encrypted are already authenticated by AEAD
        // (§3.1.4.1) and carry no signature. Previously the host permanently cleared session.SigningRequired
        // for this (downgrade risk once RejectUnencryptedAccess was off) — now we only skip
        // the check for this one frame without changing the session policy.
        // See docs/SECURITY_AUDIT.md (Finding M2).
        if (frameEncrypted) return true;
        if (!session.SigningRequired) return true;
        if (!header.Flags.HasFlag(Smb2HeaderFlags.Signed)) return false;

        // Multichannel: verify with the key of the channel the request arrived on (per-channel 3.1.1
        // signing keys, §3.3.5.5.3); falls back to the session key for the single-channel case.
        SmbSigningAlgorithmId alg = Smb2Signer.ResolveAlgorithm(connection.Dialect, connection.SigningAlgorithmId);
        bool isCancel = header.Command == SmbCommand.Cancel;
        return Smb2Signer.Verify(alg, session.SigningKeyFor(connection), segment, header.MessageId, isServer: false, isCancel);
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

    /// <summary>
    /// Sends a completed out-of-band response (lease/oplock break, blocking-LOCK/CHANGE_NOTIFY final)
    /// on a surviving channel of the session (multichannel failover, M6.3): picks a live channel
    /// preferring <paramref name="preferred"/>, then signs/frames for that channel (per-channel key)
    /// and writes it. No-op if no channel can currently send.
    /// </summary>
    private static async Task SendOutOfBandAsync(SmbSession session, SmbConnection? preferred, ResponseSegment segment, bool encrypt)
    {
        SmbConnection? target = session.SelectSendChannel(preferred);
        if (target?.SendRawAsync is not { } sender) return;
        byte[] bytes = AssembleResponse(target, [segment]);
        try { await sender(bytes, encrypt).ConfigureAwait(false); }
        catch { /* channel dropped between selection and send — nothing to do */ }
    }

    /// <summary>Assembles segments into the final message, patches NextCommand and signs.</summary>
    private static byte[] AssembleResponse(SmbConnection connection, List<ResponseSegment> segments)
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
                // Update the flags field in the already-written header (offset 16).
                writer.PatchUInt32(segStart + 16, (uint)h.Flags);

                // Multichannel: sign with the key of the channel the response goes out on
                // (per-channel 3.1.1 signing keys, §3.3.5.5.3); falls back to the session key otherwise.
                SmbSigningAlgorithmId alg = Smb2Signer.ResolveAlgorithm(connection.Dialect, connection.SigningAlgorithmId);
                Smb2Signer.SignInPlace(alg, s.SigningKeyFor(connection), segSpan, h.MessageId, isServer: true, isCancel: false);
            }
        }
        return writer.ToArray();
    }

    private static int Align8(int v) => (v + 7) & ~7;
    private static byte[] Concat(byte[] a, byte[] b) { var r = new byte[a.Length + b.Length]; a.CopyTo(r, 0); b.CopyTo(r, a.Length); return r; }
    private static byte[] Pad16(byte[] input) { var r = new byte[16]; Array.Copy(input, r, Math.Min(16, input.Length)); return r; }

    /// <summary>A completed response message (header + body) plus signing decision.</summary>
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
