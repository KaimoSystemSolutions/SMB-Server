using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// Server-side copy FSCTLs (MS-SMB2 §2.2.31.1 / §2.2.32.1, Phase 5 / M5.1).
/// A client copies a range of one open (the source) into another open (the destination) without
/// pulling the data through the client: it first obtains a 24-byte <em>resume key</em> for the
/// source via FSCTL_SRV_REQUEST_RESUME_KEY, then issues FSCTL_SRV_COPYCHUNK on the destination
/// handle carrying that key plus a chunk list.
/// </summary>
public static class CopyChunkMessage
{
    /// <summary>FSCTL_SRV_REQUEST_RESUME_KEY — obtain the opaque source key (MS-SMB2 §2.2.31.3).</summary>
    public const uint FsctlSrvRequestResumeKey = 0x00140078;

    /// <summary>FSCTL_SRV_COPYCHUNK — server-side copy, requires the destination opened for read+write.</summary>
    public const uint FsctlSrvCopyChunk = 0x001440F2;

    /// <summary>FSCTL_SRV_COPYCHUNK_WRITE — as above but the destination only needs write access.</summary>
    public const uint FsctlSrvCopyChunkWrite = 0x001480F2;

    /// <summary>Length of a resume key (MS-SMB2 §2.2.31.3, fixed 24 bytes).</summary>
    public const int ResumeKeyLength = 24;

    // Server-side-copy limits (MS-SMB2 §2.2.31.1). On violation the server returns the limits in
    // a SRV_COPYCHUNK_RESPONSE together with STATUS_INVALID_PARAMETER so the client can re-chunk.
    public const uint MaxChunks = 16;
    public const uint MaxChunkSize = 1_048_576;      // 1 MiB per chunk
    public const uint MaxTotalSize = 16_777_216;     // 16 MiB per request

    private const int ChunkSize = 24;                // SRV_COPYCHUNK fixed size

    /// <summary>A single copy chunk (MS-SMB2 §2.2.31.1.1).</summary>
    public readonly record struct Chunk(ulong SourceOffset, ulong TargetOffset, uint Length);

    /// <summary>Parsed SRV_COPYCHUNK_COPY input buffer (MS-SMB2 §2.2.31.1).</summary>
    public readonly record struct CopyRequest(byte[] SourceKey, IReadOnlyList<Chunk> Chunks);

    /// <summary>Builds the SRV_REQUEST_RESUME_KEY response (24-byte key + empty context, MS-SMB2 §2.2.32.3).</summary>
    public static byte[] BuildResumeKeyResponse(ReadOnlySpan<byte> resumeKey)
    {
        if (resumeKey.Length != ResumeKeyLength)
            throw new ArgumentException($"Resume key must be {ResumeKeyLength} bytes.", nameof(resumeKey));

        var body = new byte[ResumeKeyLength + 4];    // ResumeKey + ContextLength(=0)
        var w = new SpanWriter(body);
        w.WriteBytes(resumeKey);
        w.WriteUInt32(0);                            // ContextLength
        return body;
    }

    /// <summary>Parses a SRV_COPYCHUNK_COPY input buffer (MS-SMB2 §2.2.31.1).</summary>
    public static CopyRequest ParseCopyRequest(ReadOnlySpan<byte> input)
    {
        var r = new SpanReader(input);
        byte[] sourceKey = r.ReadByteArray(ResumeKeyLength);
        uint chunkCount = r.ReadUInt32();
        r.ReadUInt32();                              // Reserved

        // Guard the count against the buffer before allocating (§2.2.31.1 caps it at 16 anyway).
        if ((long)chunkCount * ChunkSize > r.Remaining)
            throw new SmbWireFormatException("SRV_COPYCHUNK_COPY chunk array extends past the input buffer.");

        var chunks = new Chunk[chunkCount];
        for (uint i = 0; i < chunkCount; i++)
        {
            ulong src = r.ReadUInt64();
            ulong tgt = r.ReadUInt64();
            uint len = r.ReadUInt32();
            r.ReadUInt32();                          // Reserved
            chunks[i] = new Chunk(src, tgt, len);
        }

        return new CopyRequest(sourceKey, chunks);
    }

    /// <summary>Builds a SRV_COPYCHUNK_RESPONSE (MS-SMB2 §2.2.32.1, fixed 12 bytes).</summary>
    public static byte[] BuildCopyResponse(uint chunksWritten, uint chunkBytesWritten, uint totalBytesWritten)
    {
        var body = new byte[12];
        var w = new SpanWriter(body);
        w.WriteUInt32(chunksWritten);
        w.WriteUInt32(chunkBytesWritten);
        w.WriteUInt32(totalBytesWritten);
        return body;
    }

    /// <summary>
    /// The SRV_COPYCHUNK_RESPONSE returned together with STATUS_INVALID_PARAMETER when a request
    /// exceeds the server-side-copy limits (MS-SMB2 §3.3.5.15.6): it reports the maximums so the
    /// client can split the copy and retry.
    /// </summary>
    public static byte[] BuildLimitExceededResponse()
        => BuildCopyResponse(MaxChunks, MaxChunkSize, MaxTotalSize);
}
