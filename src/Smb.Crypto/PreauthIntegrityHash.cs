using System.Security.Cryptography;

namespace Smb.Crypto;

/// <summary>
/// Running preauth integrity hash for SMB 3.1.1 (Context §6.4, §8.2, MS-SMB2 §3.3.5.4).
/// <c>H = 0</c> (64 zero bytes); per message <c>H = SHA512(H ‖ message)</c>. Order:
/// NEGOTIATE req, NEGOTIATE resp, then each SESSION_SETUP req/resp up to the final successful
/// response (Context §8.2). An ordering mistake ⇒ "invalid signature".
/// </summary>
public sealed class PreauthIntegrityHash
{
    private byte[] _value = new byte[64];

    /// <summary>Current 64-byte hash value (copy).</summary>
    public byte[] Value => (byte[])_value.Clone();

    /// <summary>Current hash value as a span (no copy) — for key derivation.</summary>
    public ReadOnlySpan<byte> ValueSpan => _value;

    /// <summary>Advances <c>H = SHA512(H ‖ message)</c>.</summary>
    public void Append(ReadOnlySpan<byte> message)
    {
        // [AUDIT-2026-06] previously: identical dead ternary branch (combinedLen<=4096 ? new[] : new[]).
        int combinedLen = _value.Length + message.Length;
        byte[] buffer = new byte[combinedLen];
        _value.CopyTo(buffer, 0);
        message.CopyTo(buffer.AsSpan(_value.Length));
        _value = SHA512.HashData(buffer);
    }

    /// <summary>Creates an independent copy of the current state (e.g. connection → session, Context §8.2).</summary>
    public PreauthIntegrityHash Clone() => new() { _value = (byte[])_value.Clone() };
}
