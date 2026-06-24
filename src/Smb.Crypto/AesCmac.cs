using System.Security.Cryptography;

namespace Smb.Crypto;

/// <summary>
/// AES-CMAC nach RFC 4493 (Context §10: Signing für SMB 3.0/3.0.2 und 3.1.1-AES-CMAC).
/// Die .NET-BCL bietet in net8.0 kein eigenständiges AES-CMAC, daher hier auf Basis von
/// AES-ECB-Einzelblock-Verschlüsselung implementiert. Verifizierbar gegen die
/// RFC-4493-Testvektoren (siehe Tests).
/// </summary>
public static class AesCmac
{
    private const int BlockSize = 16;
    private const byte Rb = 0x87; // Konstante für den 128-Bit-Block (RFC 4493 §2.3).

    /// <summary>Berechnet das 16-Byte-AES-CMAC über <paramref name="message"/> mit <paramref name="key"/>.</summary>
    public static byte[] Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        var mac = new byte[BlockSize];
        Compute(key, message, mac);
        return mac;
    }

    /// <summary>Berechnet AES-CMAC in den bereitgestellten 16-Byte-Puffer.</summary>
    public static void Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> destination)
    {
        if (destination.Length < BlockSize)
            throw new ArgumentException("Ziel benötigt mindestens 16 Byte.", nameof(destination));

        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key.ToArray();

        // Subkeys K1/K2 ableiten (RFC 4493 §2.3).
        Span<byte> l = stackalloc byte[BlockSize];
        Span<byte> zero = stackalloc byte[BlockSize];
        zero.Clear();
        aes.EncryptEcb(zero, l, PaddingMode.None);

        Span<byte> k1 = stackalloc byte[BlockSize];
        Span<byte> k2 = stackalloc byte[BlockSize];
        LeftShiftWithRb(l, k1);
        LeftShiftWithRb(k1, k2);

        int n = message.Length == 0 ? 1 : (message.Length + BlockSize - 1) / BlockSize;
        bool lastBlockComplete = message.Length != 0 && message.Length % BlockSize == 0;

        Span<byte> lastBlock = stackalloc byte[BlockSize];
        int lastBlockStart = (n - 1) * BlockSize;

        if (lastBlockComplete)
        {
            // M_last = M_n XOR K1
            Xor(message.Slice(lastBlockStart, BlockSize), k1, lastBlock);
        }
        else
        {
            // M_last = padding(M_n) XOR K2 ; padding = data ‖ 0x80 ‖ 0x00…
            int rem = message.Length - lastBlockStart;
            lastBlock.Clear();
            message.Slice(lastBlockStart, rem).CopyTo(lastBlock);
            lastBlock[rem] = 0x80;
            Xor(lastBlock, k2, lastBlock);
        }

        Span<byte> x = stackalloc byte[BlockSize];
        x.Clear();
        Span<byte> y = stackalloc byte[BlockSize];

        for (int i = 0; i < n - 1; i++)
        {
            Xor(x, message.Slice(i * BlockSize, BlockSize), y);
            aes.EncryptEcb(y, x, PaddingMode.None);
        }

        Xor(x, lastBlock, y);
        aes.EncryptEcb(y, x, PaddingMode.None);
        x.CopyTo(destination[..BlockSize]);
    }

    private static void Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> dst)
    {
        for (int i = 0; i < BlockSize; i++) dst[i] = (byte)(a[i] ^ b[i]);
    }

    /// <summary>Linksshift um 1 Bit; bei gesetztem MSB zusätzlich XOR mit Rb (RFC 4493 §2.3).</summary>
    private static void LeftShiftWithRb(ReadOnlySpan<byte> input, Span<byte> output)
    {
        byte overflow = (byte)((input[0] & 0x80) != 0 ? 1 : 0);
        for (int i = 0; i < BlockSize; i++)
        {
            byte carry = (byte)(i + 1 < BlockSize ? (input[i + 1] >> 7) & 1 : 0);
            output[i] = (byte)((input[i] << 1) | carry);
        }
        if (overflow == 1) output[BlockSize - 1] ^= Rb;
    }
}
