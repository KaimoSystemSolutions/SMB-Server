using Smb.Auth.Ldap;
using Xunit;

namespace Smb.Tests;

/// <summary>Phase 2 / M2.2 increment A — binary ↔ string SID conversion (MS-DTYP §2.4.2.2).</summary>
public class SidConverterTests
{
    // S-1-5-32-544 (BUILTIN\Administrators) — independently verifiable binary form.
    private static readonly byte[] BuiltinAdminsBinary =
    [
        0x01, 0x02,                                     // revision 1, 2 sub-authorities
        0x00, 0x00, 0x00, 0x00, 0x00, 0x05,             // authority = 5 (NT)
        0x20, 0x00, 0x00, 0x00,                         // 32
        0x20, 0x02, 0x00, 0x00,                         // 544
    ];
    private const string BuiltinAdminsSid = "S-1-5-32-544";

    [Fact]
    public void BinaryToString_WellKnownSid()
    {
        Assert.True(SidConverter.TryToString(new byte[] { 0x01, 0x01, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0 }, out string sid));
        Assert.Equal("S-1-5-18", sid); // Local System
    }

    [Fact]
    public void BinaryToString_BuiltinAdmins()
    {
        Assert.True(SidConverter.TryToString(BuiltinAdminsBinary, out string sid));
        Assert.Equal(BuiltinAdminsSid, sid);
    }

    [Fact]
    public void StringToBinary_RoundTrips()
    {
        Assert.True(SidConverter.TryToBinary(BuiltinAdminsSid, out byte[] binary));
        Assert.Equal(BuiltinAdminsBinary, binary);

        Assert.True(SidConverter.TryToString(binary, out string back));
        Assert.Equal(BuiltinAdminsSid, back);
    }

    [Fact]
    public void DomainSid_StringRoundTrips()
    {
        const string domainSid = "S-1-5-21-1004336348-1177238915-682003330-512";
        Assert.True(SidConverter.TryToBinary(domainSid, out byte[] binary));
        Assert.Equal(8 + 4 * 5, binary.Length);         // 5 sub-authorities
        Assert.True(SidConverter.TryToString(binary, out string back));
        Assert.Equal(domainSid, back);
    }

    [Theory]
    [InlineData("S-1-0-0")]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-21-1-2-3-1000")]
    public void RoundTrip_VariousSids(string sid)
    {
        Assert.True(SidConverter.TryToBinary(sid, out byte[] binary));
        Assert.True(SidConverter.TryToString(binary, out string back));
        Assert.Equal(sid, back);
    }

    [Fact]
    public void LargeAuthority_UsesHexForm()
    {
        // Authority > 2^32 is printed as 0x-hex (MS-DTYP display rule).
        const string sid = "S-1-0x010000000000-1-2";
        Assert.True(SidConverter.TryToBinary(sid, out byte[] binary));
        Assert.True(SidConverter.TryToString(binary, out string back));
        Assert.Equal(sid, back);
    }

    [Fact]
    public void ToLdapFilterValue_EscapesEachByte()
    {
        string escaped = SidConverter.ToLdapFilterValue(new byte[] { 0x01, 0x05, 0x00, 0xAB });
        Assert.Equal(@"\01\05\00\ab", escaped);
    }

    [Theory]
    [InlineData(new byte[] { 0x01 })]                       // too short
    [InlineData(new byte[] { 0x01, 0x02, 0, 0, 0, 0, 0, 5, 0x15, 0, 0, 0 })] // count=2 but only 1 sub present
    public void TryToString_RejectsMalformed(byte[] bad)
    {
        Assert.False(SidConverter.TryToString(bad, out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("X-1-5-18")]
    [InlineData("S-1")]
    [InlineData("S-1-5-notanumber")]
    public void TryToBinary_RejectsMalformed(string? bad)
    {
        Assert.False(SidConverter.TryToBinary(bad, out _));
    }
}
