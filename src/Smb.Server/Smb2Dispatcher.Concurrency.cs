using System.Buffers.Binary;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;
using Smb.Server.Concurrency;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// Concurrent frame processing (docs/ASYNC_IO_ROADMAP.md A4, docs/ENTERPRISE_HARDENING_ROADMAP.md A2b):
/// the host classifies incoming frames in its read loop via <see cref="TryBeginConcurrentFrame"/>. Single
/// (non-compound) READ/WRITE frames may always be executed concurrently; with
/// <see cref="SmbServerOptions.ConcurrentMetadataOps"/> on, metadata ops
/// (CREATE/CLOSE/SET_INFO/QUERY_INFO/QUERY_DIRECTORY/FLUSH) join them. Responses may go back
/// out-of-order (correlation via MessageId, §3.3.4.1).
/// <para>
/// Correctness of concurrent metadata ops is enforced by a per-connection, per-Open reader/writer queue
/// (<see cref="_opScopes"/>): reservations are taken in frame-arrival order on the read loop
/// (<see cref="ReserveScope"/>) and granted per FIFO + shared/exclusive rules when the executing task runs
/// (<see cref="ExecutePreparedFrameAsync"/>). READ/WRITE/QUERY_INFO are shared (parallel on one Open);
/// CLOSE/SET_INFO/FLUSH/QUERY_DIRECTORY are exclusive (a CLOSE waits for inflight I/O of the same Open, and
/// QUERY_DIRECTORY is exclusive because it mutates the open's paging cursor). CREATE runs free (its FileId
/// does not exist yet). Lifecycle/compound commands are still handled strictly sequentially by the host,
/// which first drains all running frames (barrier) so session/tree/open lifecycle stays ordered.
/// </para>
/// </summary>
public sealed partial class Smb2Dispatcher
{
    /// <summary>Per-connection, per-Open ordering/exclusion for concurrent metadata ops (A2b).</summary>
    private readonly KeyedReaderWriterQueue<(ulong Persistent, ulong Volatile)> _opScopes = new();

    /// <summary>
    /// Pre-validated frame: header parsed, encryption requirement checked, and sequence window
    /// already consumed — ready for (potentially concurrent) execution. May carry a per-Open scope
    /// reservation (assigned by <see cref="ReserveScope"/> after the concurrency gate).
    /// </summary>
    public readonly struct PreparedFrame
    {
        internal PreparedFrame(
            Smb2Header header, ReadOnlyMemory<byte> message, bool encrypted,
            bool needsReservation, (ulong Persistent, ulong Volatile) scopeKey, LockMode scopeMode,
            KeyedReaderWriterQueue<(ulong Persistent, ulong Volatile)>.Reservation? reservation = null)
        {
            Header = header;
            Message = message;
            Encrypted = encrypted;
            NeedsReservation = needsReservation;
            ScopeKey = scopeKey;
            ScopeMode = scopeMode;
            Reservation = reservation;
        }

        internal Smb2Header Header { get; }
        internal ReadOnlyMemory<byte> Message { get; }
        internal bool Encrypted { get; }

        /// <summary>True if this frame must hold a per-Open scope while executing (all per-Open ops).</summary>
        internal bool NeedsReservation { get; }
        internal (ulong Persistent, ulong Volatile) ScopeKey { get; }
        internal LockMode ScopeMode { get; }
        internal KeyedReaderWriterQueue<(ulong Persistent, ulong Volatile)>.Reservation? Reservation { get; }

        internal PreparedFrame WithReservation(
            KeyedReaderWriterQueue<(ulong Persistent, ulong Volatile)>.Reservation reservation)
            => new(Header, Message, Encrypted, NeedsReservation, ScopeKey, ScopeMode, reservation);
    }

    /// <summary>
    /// Checks whether a frame may be executed concurrently and, on success, consumes its sequence window.
    /// MUST be called in the connection's read loop (in arrival order): <see cref="ValidateSequence"/>
    /// mutates <c>connection.SequenceWindowStart</c> and only stays ordered that way. Returns <c>false</c>
    /// for everything the sequential path should handle — including error cases (sequence window /
    /// encryption requirement / malformed body), so that path produces the correct error response.
    /// <para>Does <b>not</b> take the per-Open scope reservation — call <see cref="ReserveScope"/> for that
    /// after the caller's concurrency gate, so a gate-cancelled frame never orphans a reservation.</para>
    /// </summary>
    public bool TryBeginConcurrentFrame(SmbConnection connection, ReadOnlyMemory<byte> message, bool transportEncrypted, out PreparedFrame frame)
    {
        frame = default;
        if (!connection.NegotiateDone) return false;
        if (!SmbProtocolIds.IsSmb2(message.Span)) return false;

        Smb2Header header;
        try { header = Smb2Header.Read(message.Span); }
        catch (SmbWireFormatException) { return false; }

        if (header.NextCommand != 0) return false;                                  // Compound → sequential
        if (header.Flags.HasFlag(Smb2HeaderFlags.RelatedOperations)) return false;

        if (!TryClassifyConcurrent(header.Command, message.Span,
                out bool needsReservation, out (ulong, ulong) scopeKey, out LockMode scopeMode))
            return false;

        if (!transportEncrypted && RequiresEncryptedTransport(connection, header)) return false;

        // Check LAST: ValidateSequence consumes the window on success. If it fails, the sequential path
        // repeats the check (idempotent on failure) and responds.
        if (!ValidateSequence(connection, header)) return false;

        frame = new PreparedFrame(header, message, transportEncrypted, needsReservation, scopeKey, scopeMode);
        return true;
    }

    /// <summary>
    /// Takes the per-Open scope reservation for a prepared frame in arrival order. MUST be called on the
    /// read loop, right after the host's concurrency gate admits the frame (still ordered because the read
    /// loop is serial). A frame that needs no reservation (READ/WRITE with the metadata feature off, or
    /// CREATE) is returned unchanged.
    /// </summary>
    public PreparedFrame ReserveScope(PreparedFrame frame)
    {
        if (!frame.NeedsReservation) return frame;
        return frame.WithReservation(_opScopes.Reserve(frame.ScopeKey, frame.ScopeMode));
    }

    /// <summary>
    /// Executes a frame prepared by <see cref="TryBeginConcurrentFrame"/>. Safe to call concurrently. When
    /// the frame carries a scope reservation it is acquired first (granted per FIFO + shared/exclusive
    /// rules) and released when the op completes — success or error — via <c>using</c>. Returns the
    /// complete SMB2 response (empty = nothing to send).
    /// </summary>
    public async ValueTask<byte[]> ExecutePreparedFrameAsync(SmbConnection connection, PreparedFrame frame, CancellationToken cancellationToken = default)
    {
        Smb2Header header = frame.Header;
        _log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} tid={header.TreeId} len={frame.Message.Length} (concurrent)");

        ResponseSegment? response;
        if (frame.Reservation is { } reservation)
        {
            using var _ = await reservation.AcquireAsync(cancellationToken).ConfigureAwait(false);
            response = await DispatchOneAsync(connection, header, frame.Message, frame.Encrypted, preValidated: true).ConfigureAwait(false);
        }
        else
        {
            response = await DispatchOneAsync(connection, header, frame.Message, frame.Encrypted, preValidated: true).ConfigureAwait(false);
        }

        _log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} → {(response is { } r ? r.Header.Status.ToString() : "(no response)")}");
        return response is { } seg ? AssembleResponse(connection, [seg]) : [];
    }

    /// <summary>
    /// Classifies a single, non-compound frame for the concurrent path. Returns <c>false</c> for anything
    /// the sequential barrier path must handle. On success, <paramref name="needsReservation"/> indicates
    /// whether a per-Open scope must be held (with <paramref name="scopeKey"/>/<paramref name="scopeMode"/>).
    /// </summary>
    private bool TryClassifyConcurrent(SmbCommand command, ReadOnlySpan<byte> message,
        out bool needsReservation, out (ulong, ulong) scopeKey, out LockMode scopeMode)
    {
        needsReservation = false;
        scopeKey = default;
        scopeMode = LockMode.Shared;

        bool metadataConcurrency = _server.Options.ConcurrentMetadataOps;

        switch (command)
        {
            case SmbCommand.Read:
            case SmbCommand.Write:
                if (!metadataConcurrency) return true;      // legacy A4 path: eligible, no scope
                scopeMode = LockMode.Shared;
                break;

            case SmbCommand.QueryInfo:
                if (!metadataConcurrency) return false;
                scopeMode = LockMode.Shared;
                break;

            case SmbCommand.Close:
            case SmbCommand.Flush:
            case SmbCommand.SetInfo:
            case SmbCommand.QueryDirectory:                  // exclusive: mutates the open's paging cursor
                if (!metadataConcurrency) return false;
                scopeMode = LockMode.Exclusive;
                break;

            case SmbCommand.Create:
                // CREATE runs free: its FileId does not exist yet, so no other frame can reference the Open,
                // and every store it touches (share-mode, backend FS, Opens, lease/oplock) is atomic (A3).
                return metadataConcurrency;

            default:
                return false;
        }

        // Per-Open ops: extract the FileId that forms the scope key. A malformed body → sequential path.
        if (!TryReadFileId(command, message, out scopeKey)) return false;
        needsReservation = true;
        return true;
    }

    /// <summary>
    /// Reads the {Persistent, Volatile} FileId of a per-Open request for the concurrency scope key. Reuses
    /// the validated per-command parsers where they do not copy payload; reads READ/WRITE/FLUSH directly
    /// (no-copy) at their fixed offsets. Returns <c>false</c> on a malformed/short body.
    /// </summary>
    private static bool TryReadFileId(SmbCommand command, ReadOnlySpan<byte> message, out (ulong, ulong) fileId)
    {
        const int body = Smb2Header.Size; // 64
        try
        {
            switch (command)
            {
                case SmbCommand.Read:
                {
                    ReadMessage.Request r = ReadMessage.ParseRequest(message, body);
                    fileId = (r.PersistentId, r.VolatileId);
                    return true;
                }
                case SmbCommand.Write:
                {
                    // No-copy: WriteMessage.ParseRequest would copy the (potentially large) payload.
                    // WRITE body (§2.2.21): SS(2)+DataOffset(2)+Length(4)+Offset(8)+FileId(16) → FileId at body+16.
                    if (message.Length < body + 32) break;
                    if (BinaryPrimitives.ReadUInt16LittleEndian(message.Slice(body, 2)) != WriteMessage.RequestStructureSize) break;
                    ulong p = BinaryPrimitives.ReadUInt64LittleEndian(message.Slice(body + 16, 8));
                    ulong v = BinaryPrimitives.ReadUInt64LittleEndian(message.Slice(body + 24, 8));
                    fileId = (p, v);
                    return true;
                }
                case SmbCommand.Close:
                {
                    (ushort _, ulong p, ulong v) = CloseMessage.ParseRequest(message, body);
                    fileId = (p, v);
                    return true;
                }
                case SmbCommand.Flush:
                {
                    // FLUSH body (§2.2.17): SS(2)+Reserved1(2)+Reserved2(4)+FileId(16) → FileId at body+8. No parser.
                    if (message.Length < body + 24) break;
                    ulong p = BinaryPrimitives.ReadUInt64LittleEndian(message.Slice(body + 8, 8));
                    ulong v = BinaryPrimitives.ReadUInt64LittleEndian(message.Slice(body + 16, 8));
                    fileId = (p, v);
                    return true;
                }
                case SmbCommand.QueryDirectory:
                {
                    QueryDirectoryMessage.Request r = QueryDirectoryMessage.ParseRequest(message, body);
                    fileId = (r.PersistentId, r.VolatileId);
                    return true;
                }
                case SmbCommand.QueryInfo:
                {
                    QueryInfoMessage.Request r = QueryInfoMessage.ParseRequest(message, body);
                    fileId = (r.PersistentId, r.VolatileId);
                    return true;
                }
                case SmbCommand.SetInfo:
                {
                    SetInfoMessage.Request r = SetInfoMessage.ParseRequest(message, body);
                    fileId = (r.PersistentId, r.VolatileId);
                    return true;
                }
            }
        }
        catch (SmbWireFormatException)
        {
            // Malformed body → let the sequential path produce the proper error response.
        }

        fileId = default;
        return false;
    }
}
