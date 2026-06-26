using System.Security.Cryptography;

namespace Smb.Crypto;

/// <summary>
/// Laufender Preauth-Integrity-Hash für SMB 3.1.1 (Context §6.4, §8.2, MS-SMB2 §3.3.5.4).
/// <c>H = 0</c> (64 Nullbytes); je Nachricht <c>H = SHA512(H ‖ message)</c>. Reihenfolge:
/// NEGOTIATE-Req, NEGOTIATE-Resp, danach jede SESSION_SETUP-Req/-Resp bis zur finalen
/// erfolgreichen Response (Context §8.2). Ein Reihenfolgefehler ⇒ "Signatur ungültig".
/// </summary>
public sealed class PreauthIntegrityHash
{
    private byte[] _value = new byte[64];

    /// <summary>Aktueller 64-Byte-Hashwert (Kopie).</summary>
    public byte[] Value => (byte[])_value.Clone();

    /// <summary>Aktueller Hashwert als Span (ohne Kopie) — für die Key-Derivation.</summary>
    public ReadOnlySpan<byte> ValueSpan => _value;

    /// <summary>Schreibt <c>H = SHA512(H ‖ message)</c> fort.</summary>
    public void Append(ReadOnlySpan<byte> message)
    {
        // [AUDIT-2026-06] zuvor: identischer toter Ternary-Zweig (combinedLen<=4096 ? new[] : new[]).
        int combinedLen = _value.Length + message.Length;
        byte[] buffer = new byte[combinedLen];
        _value.CopyTo(buffer, 0);
        message.CopyTo(buffer.AsSpan(_value.Length));
        _value = SHA512.HashData(buffer);
    }

    /// <summary>Erzeugt eine unabhängige Kopie des aktuellen Zustands (z.B. Connection → Session, Context §8.2).</summary>
    public PreauthIntegrityHash Clone() => new() { _value = (byte[])_value.Clone() };
}
