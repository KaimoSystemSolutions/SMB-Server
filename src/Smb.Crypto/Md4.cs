namespace Smb.Crypto;

/// <summary>
/// MD4 (RFC 1320). Not included in the .NET BCL, but needed for the NT hash
/// (<c>MD4(UTF16LE(password))</c>) and thus for NTLMv2 (Context §9.3). Only for this
/// NTLM-internal computation — not used as a general-purpose hash function.
/// Verifiable against the RFC 1320 test vectors (see tests).
/// </summary>
public static class Md4
{
    public static byte[] Compute(ReadOnlySpan<byte> input)
    {
        uint a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;

        // Padding: 0x80, then zeros until length ≡ 56 (mod 64), then the 64-bit bit length (LE).
        long bitLen = (long)input.Length * 8;
        int padded = ((input.Length + 8) / 64 + 1) * 64;
        var msg = new byte[padded];
        input.CopyTo(msg);
        msg[input.Length] = 0x80;
        for (int i = 0; i < 8; i++)
            msg[padded - 8 + i] = (byte)(bitLen >> (8 * i));

        Span<uint> x = stackalloc uint[16];
        for (int off = 0; off < padded; off += 64)
        {
            for (int i = 0; i < 16; i++)
            {
                int j = off + i * 4;
                x[i] = (uint)(msg[j] | (msg[j + 1] << 8) | (msg[j + 2] << 16) | (msg[j + 3] << 24));
            }

            uint aa = a, bb = b, cc = c, dd = d;

            // Round 1
            foreach (int k in new[] { 0, 4, 8, 12 })
            {
                a = Round1(a, b, c, d, x[k + 0], 3);
                d = Round1(d, a, b, c, x[k + 1], 7);
                c = Round1(c, d, a, b, x[k + 2], 11);
                b = Round1(b, c, d, a, x[k + 3], 19);
            }
            // Round 2
            foreach (int k in new[] { 0, 1, 2, 3 })
            {
                a = Round2(a, b, c, d, x[k + 0], 3);
                d = Round2(d, a, b, c, x[k + 4], 5);
                c = Round2(c, d, a, b, x[k + 8], 9);
                b = Round2(b, c, d, a, x[k + 12], 13);
            }
            // Round 3
            foreach (int k in new[] { 0, 2, 1, 3 })
            {
                a = Round3(a, b, c, d, x[k + 0], 3);
                d = Round3(d, a, b, c, x[k + 8], 9);
                c = Round3(c, d, a, b, x[k + 4], 11);
                b = Round3(b, c, d, a, x[k + 12], 15);
            }

            a += aa; b += bb; c += cc; d += dd;
        }

        var result = new byte[16];
        WriteLe(result, 0, a);
        WriteLe(result, 4, b);
        WriteLe(result, 8, c);
        WriteLe(result, 12, d);
        return result;
    }

    private static uint Round1(uint a, uint b, uint c, uint d, uint xk, int s)
        => Rol(a + F(b, c, d) + xk, s);

    private static uint Round2(uint a, uint b, uint c, uint d, uint xk, int s)
        => Rol(a + G(b, c, d) + xk + 0x5A827999u, s);

    private static uint Round3(uint a, uint b, uint c, uint d, uint xk, int s)
        => Rol(a + H(b, c, d) + xk + 0x6ED9EBA1u, s);

    private static uint F(uint x, uint y, uint z) => (x & y) | (~x & z);
    private static uint G(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);
    private static uint H(uint x, uint y, uint z) => x ^ y ^ z;
    private static uint Rol(uint v, int s) => (v << s) | (v >> (32 - s));

    private static void WriteLe(byte[] buf, int off, uint v)
    {
        buf[off] = (byte)v;
        buf[off + 1] = (byte)(v >> 8);
        buf[off + 2] = (byte)(v >> 16);
        buf[off + 3] = (byte)(v >> 24);
    }
}
