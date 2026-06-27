using Smb.Protocol.Enums;

namespace Smb.Auth;

/// <summary>
/// Result of an auth step (Context §9.1). <see cref="Status"/> drives the SESSION_SETUP flow:
/// <c>MoreProcessingRequired</c> = another round-trip, <c>Success</c> = done (with
/// <see cref="SessionKey"/> and <see cref="Identity"/>), <c>LogonFailure</c>/<c>AccessDenied</c>
/// = rejected.
/// </summary>
public sealed class GssResult
{
    public required NtStatus Status { get; init; }

    /// <summary>Token to return to the client (in the SESSION_SETUP security buffer).</summary>
    public byte[]? OutToken { get; init; }

    /// <summary>GSS session key (≥16 bytes) — source of the SMB keys (Context §8.3). Only on success.</summary>
    public byte[]? SessionKey { get; init; }

    /// <summary>Authenticated identity. Only on success.</summary>
    public SecurityIdentity? Identity { get; init; }

    public bool IsSuccess => Status == NtStatus.Success;
    public bool NeedsMoreProcessing => Status == NtStatus.MoreProcessingRequired;

    public static GssResult Continue(byte[] outToken) =>
        new() { Status = NtStatus.MoreProcessingRequired, OutToken = outToken };

    public static GssResult Succeeded(byte[] sessionKey, SecurityIdentity identity, byte[]? outToken = null) =>
        new() { Status = NtStatus.Success, SessionKey = sessionKey, Identity = identity, OutToken = outToken };

    public static GssResult Failed(NtStatus status = NtStatus.LogonFailure, byte[]? outToken = null) =>
        new() { Status = status, OutToken = outToken };
}
