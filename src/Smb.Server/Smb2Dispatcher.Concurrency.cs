using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// Concurrent READ/WRITE processing (docs/ASYNC_IO_ROADMAP.md, A4): the host classifies
/// incoming frames in its read loop via <see cref="TryBeginConcurrentFrame"/>; single
/// (non-compound) READ/WRITE frames may be executed concurrently
/// (<see cref="ExecutePreparedFrameAsync"/>), their responses may go back out-of-order
/// (correlation via MessageId, §3.3.4.1). All other commands are still handled strictly
/// sequentially by the host, which first drains all running frames (barrier) so that
/// session/tree/open state changes remain ordered.
/// </summary>
public sealed partial class Smb2Dispatcher
{
    /// <summary>
    /// Pre-validated frame: header parsed, encryption requirement checked, and sequence window
    /// already consumed — ready for (potentially concurrent) execution.
    /// </summary>
    public readonly struct PreparedFrame
    {
        internal PreparedFrame(Smb2Header header, ReadOnlyMemory<byte> message, bool encrypted)
        {
            Header = header;
            Message = message;
            Encrypted = encrypted;
        }

        internal Smb2Header Header { get; }
        internal ReadOnlyMemory<byte> Message { get; }
        internal bool Encrypted { get; }
    }

    /// <summary>
    /// Checks whether a frame may be executed concurrently and, on success, consumes its
    /// sequence window. MUST be called in the connection's read loop (in arrival order):
    /// <see cref="ValidateSequence"/> mutates <c>connection.SequenceWindowStart</c> and only
    /// stays ordered that way. Returns <c>false</c> for everything the sequential path should
    /// handle — including error cases (sequence window / encryption requirement), so that path
    /// produces the correct error response.
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
        if (header.Command is not (SmbCommand.Read or SmbCommand.Write)) return false;

        if (!transportEncrypted && RequiresEncryptedTransport(connection, header)) return false;

        // Check LAST: ValidateSequence consumes the window on success. If it fails,
        // the sequential path repeats the check (idempotent on failure) and responds.
        if (!ValidateSequence(connection, header)) return false;

        frame = new PreparedFrame(header, message, transportEncrypted);
        return true;
    }

    /// <summary>
    /// Executes a frame prepared by <see cref="TryBeginConcurrentFrame"/>. Safe to call
    /// concurrently (READ/WRITE handlers only use thread-safe state: ConcurrentDictionaries,
    /// gate-locked LockManager, Interlocked nonce, pure signing). Returns the complete
    /// SMB2 response (empty = nothing to send).
    /// </summary>
    public async ValueTask<byte[]> ExecutePreparedFrameAsync(SmbConnection connection, PreparedFrame frame)
    {
        Smb2Header header = frame.Header;
        _log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} tid={header.TreeId} len={frame.Message.Length} (concurrent)");
        ResponseSegment? response = await DispatchOneAsync(connection, header, frame.Message, frame.Encrypted, preValidated: true).ConfigureAwait(false);
        _log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} → {(response is { } r ? r.Header.Status.ToString() : "(no response)")}");
        return response is { } seg ? AssembleResponse([seg]) : [];
    }
}
