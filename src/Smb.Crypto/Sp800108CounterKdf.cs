using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Smb.Crypto;

/// <summary>
/// SP800-108 counter-mode KDF with PRF = HMAC-SHA256 (Context §8.3, MS-SMB2 §3.1.4.2).
/// Fixed input per iteration: <c>[i]₄ ‖ Label ‖ 0x00 ‖ Context ‖ [L]₄</c> (counter and L as
/// 32-bit big-endian, r = 32). Label/context are passed as bytes; the SMB labels are
/// NUL-terminated (see <see cref="Smb3KeyDerivation"/>).
/// </summary>
public static class Sp800108CounterKdf
{
    private const int PrfOutputBytes = 32; // HMAC-SHA256

    /// <summary>
    /// Derives <paramref name="outputBytes"/> key bytes from <paramref name="keyDerivationKey"/>.
    /// </summary>
    public static byte[] DeriveKey(
        ReadOnlySpan<byte> keyDerivationKey,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> context,
        int outputBytes)
    {
        if (outputBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputBytes));

        int lengthInBits = outputBytes * 8;
        int iterations = (outputBytes + PrfOutputBytes - 1) / PrfOutputBytes;

        // Fixed input without counter: Label ‖ 0x00 ‖ Context ‖ [L]₄
        int fixedLen = label.Length + 1 + context.Length + 4;
        Span<byte> input = stackalloc byte[4 + fixedLen];
        label.CopyTo(input[4..]);
        input[4 + label.Length] = 0x00;
        context.CopyTo(input[(4 + label.Length + 1)..]);
        BinaryPrimitives.WriteUInt32BigEndian(input[(4 + label.Length + 1 + context.Length)..], (uint)lengthInBits);

        using var hmac = new HMACSHA256(keyDerivationKey.ToArray());
        var output = new byte[iterations * PrfOutputBytes];
        Span<byte> block = stackalloc byte[PrfOutputBytes];

        for (int i = 1; i <= iterations; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(input[..4], (uint)i);
            if (!hmac.TryComputeHash(input, block, out _))
                throw new CryptographicException("HMAC computation failed.");
            block.CopyTo(output.AsSpan((i - 1) * PrfOutputBytes));
        }

        if (output.Length == outputBytes) return output;
        var trimmed = new byte[outputBytes];
        Array.Copy(output, trimmed, outputBytes);
        return trimmed;
    }
}
