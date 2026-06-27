namespace Smb.Crypto;

/// <summary>
/// RC4 stream cipher. Needed exclusively for the NTLM key exchange
/// (<c>ExportedSessionKey = RC4(KeyExchangeKey, EncryptedRandomSessionKey)</c>, MS-NLMP §3.4.5.2,
/// Context §9.3). Not included in the .NET BCL; use only for this NTLM-internal purpose.
/// </summary>
public static class Rc4
{
    public static byte[] Transform(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        Span<byte> s = stackalloc byte[256];
        for (int i = 0; i < 256; i++) s[i] = (byte)i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) & 0xFF;
            (s[i], s[j]) = (s[j], s[i]);
        }

        var output = new byte[data.Length];
        int a = 0, b = 0;
        for (int k = 0; k < data.Length; k++)
        {
            a = (a + 1) & 0xFF;
            b = (b + s[a]) & 0xFF;
            (s[a], s[b]) = (s[b], s[a]);
            byte keyStream = s[(s[a] + s[b]) & 0xFF];
            output[k] = (byte)(data[k] ^ keyStream);
        }
        return output;
    }
}
