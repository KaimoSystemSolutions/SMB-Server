using Smb.Crypto;
using Xunit;

namespace Smb.Tests;

/// <summary>Known-answer tests (KAT) against official RFC vectors (Context §22).</summary>
public class CryptoVectorTests
{
    private static byte[] Hex(string hex)
    {
        hex = hex.Replace(" ", "");
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    // --- AES-CMAC: RFC 4493 §4 Testvektoren (Key = 2b7e1516…). ---

    private static readonly byte[] CmacKey = Hex("2b7e151628aed2a6abf7158809cf4f3c");

    [Fact]
    public void AesCmac_Rfc4493_EmptyMessage()
        => Assert.Equal(Hex("bb1d6929e95937287fa37d129b756746"),
                        AesCmac.Compute(CmacKey, ReadOnlySpan<byte>.Empty));

    [Fact]
    public void AesCmac_Rfc4493_16ByteMessage()
        => Assert.Equal(Hex("070a16b46b4d4144f79bdd9dd04a287c"),
                        AesCmac.Compute(CmacKey, Hex("6bc1bee22e409f96e93d7e117393172a")));

    [Fact]
    public void AesCmac_Rfc4493_40ByteMessage()
        => Assert.Equal(Hex("dfa66747de9ae63030ca32611497c827"),
            AesCmac.Compute(CmacKey, Hex(
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411")));

    [Fact]
    public void AesCmac_Rfc4493_64ByteMessage()
        => Assert.Equal(Hex("51f0bebf7e3b9d92fc49741779363cfe"),
            AesCmac.Compute(CmacKey, Hex(
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411e5fbc1191a0a52ef" +
                "f69f2445df4f9b17ad2b417be66c3710")));

    // --- MD4: RFC 1320 Appendix A.5 Testvektoren. ---

    [Theory]
    [InlineData("", "31d6cfe0d16ae931b73c59d7e0c089c0")]
    [InlineData("a", "bde52cb31de33e46245e05fbdbd6fb24")]
    [InlineData("abc", "a448017aaf21d8525fc10ae87aa6729d")]
    [InlineData("message digest", "d9130a8164549fe818874806e1c7014b")]
    [InlineData("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9")]
    public void Md4_Rfc1320(string input, string expectedHex)
        => Assert.Equal(Hex(expectedHex), Md4.Compute(System.Text.Encoding.ASCII.GetBytes(input)));

    [Fact]
    public void NtHash_OfEmptyPassword_IsWellKnownValue()
        => Assert.Equal(Hex("31d6cfe0d16ae931b73c59d7e0c089c0"), NtlmCryptography.NtHash(""));

    // --- NTOWFv2: MS-NLMP §4.2.2 example (User/Domain/Password). ---

    [Fact]
    public void NtowfV2_MsNlmpExample()
    {
        byte[] ntowf = NtlmCryptography.NtowfV2FromPassword("Password", "User", "Domain");
        Assert.Equal(Hex("0c868a403bfd7a93a3001ef22ef02e3f"), ntowf);
    }
}
