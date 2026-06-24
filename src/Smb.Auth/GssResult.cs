using Smb.Protocol.Enums;

namespace Smb.Auth;

/// <summary>
/// Ergebnis eines Auth-Schritts (Context §9.1). <see cref="Status"/> steuert den
/// SESSION_SETUP-Ablauf: <c>MoreProcessingRequired</c> = weiterer Roundtrip,
/// <c>Success</c> = fertig (mit <see cref="SessionKey"/> und <see cref="Identity"/>),
/// <c>LogonFailure</c>/<c>AccessDenied</c> = abgelehnt.
/// </summary>
public sealed class GssResult
{
    public required NtStatus Status { get; init; }

    /// <summary>An den Client zurückzugebender Token (im SESSION_SETUP-Security-Buffer).</summary>
    public byte[]? OutToken { get; init; }

    /// <summary>GSS-Session-Key (≥16 Byte) — Quelle der SMB-Keys (Context §8.3). Nur bei Success.</summary>
    public byte[]? SessionKey { get; init; }

    /// <summary>Authentifizierte Identität. Nur bei Success.</summary>
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
