using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Security;

namespace Smb.Server.Quota;

/// <summary>
/// [M11.1] Disk-quota seam (SMB2 QUERY_QUOTA_INFO / SET_QUOTA_INFO, §2.2.37/§2.2.39). Reports and
/// updates per-owner-SID quota state for a share, and enforces limits on write. The core stays
/// dependency-free and cross-platform; a deployment supplies a concrete provider that delegates to the
/// real OS quota system (NTFS quotas / ZFS user quotas), while the default
/// <see cref="NullQuotaProvider"/> reports "not supported" and enforces nothing.
/// </summary>
public interface IQuotaProvider
{
    /// <summary>
    /// Whether this provider actually manages quotas. When false, QUERY/SET_QUOTA_INFO return
    /// <c>STATUS_NOT_SUPPORTED</c> and <see cref="TryReserve"/> always permits the write.
    /// </summary>
    bool IsSupported { get; }

    /// <summary>
    /// Returns the quota records for <paramref name="share"/>. When <paramref name="sidFilter"/> is
    /// non-empty only those owner SIDs are returned (in the requested order); otherwise all records.
    /// </summary>
    IReadOnlyList<FileQuotaInformation> Query(IShare share, IReadOnlyList<Sid> sidFilter);

    /// <summary>
    /// Applies quota settings (per-owner threshold/limit) for <paramref name="share"/>. Returns
    /// <c>STATUS_SUCCESS</c> or an error status (e.g. <c>STATUS_NOT_SUPPORTED</c>).
    /// </summary>
    NtStatus Set(IShare share, IReadOnlyList<FileQuotaInformation> entries);

    /// <summary>
    /// Atomically reserves <paramref name="additionalBytes"/> of quota for <paramref name="owner"/> on
    /// <paramref name="share"/>. Returns false when it would exceed the owner's limit (the caller then
    /// fails the write with <c>STATUS_DISK_FULL</c>). A no-op provider returns true.
    /// </summary>
    bool TryReserve(IShare share, Sid owner, long additionalBytes);

    /// <summary>Returns previously reserved bytes (e.g. when the write ultimately failed).</summary>
    void Release(IShare share, Sid owner, long bytes);
}

/// <summary>Default provider: no quota management. QUERY/SET report not-supported, writes are never limited.</summary>
public sealed class NullQuotaProvider : IQuotaProvider
{
    public static readonly NullQuotaProvider Instance = new();

    public bool IsSupported => false;
    public IReadOnlyList<FileQuotaInformation> Query(IShare share, IReadOnlyList<Sid> sidFilter) => [];
    public NtStatus Set(IShare share, IReadOnlyList<FileQuotaInformation> entries) => NtStatus.NotSupported;
    public bool TryReserve(IShare share, Sid owner, long additionalBytes) => true;
    public void Release(IShare share, Sid owner, long bytes) { }
}
