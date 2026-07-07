using Smb.Protocol.Security;
using Smb.Protocol.Wire;
using Xunit;

namespace Smb.Tests;

/// <summary>Phase 3 / M3.1 increment A — the <see cref="Sid"/> value type (MS-DTYP §2.4.2).</summary>
public class SidTests
{
    // S-1-5-32-544 (BUILTIN\Administrators) — independently verifiable binary form.
    private static readonly byte[] BuiltinAdminsBinary =
    [
        0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,   // rev 1, 2 subs, authority 5
        0x20, 0x00, 0x00, 0x00,                            // 32
        0x20, 0x02, 0x00, 0x00,                            // 544
    ];

    [Fact]
    public void Binary_RoundTrips()
    {
        Sid sid = Sid.Parse(BuiltinAdminsBinary, out int consumed);

        Assert.Equal(BuiltinAdminsBinary.Length, consumed);
        Assert.Equal("S-1-5-32-544", sid.ToString());
        Assert.Equal(BuiltinAdminsBinary.Length, sid.BinaryLength);
        Assert.Equal(BuiltinAdminsBinary, sid.ToBytes());
    }

    [Fact]
    public void String_RoundTrips()
    {
        Sid sid = Sid.FromString("S-1-5-21-1004336348-1177238915-682003330-512");
        Assert.Equal(5, sid.SubAuthorities.Count);
        Assert.Equal("S-1-5-21-1004336348-1177238915-682003330-512", sid.ToString());

        byte[] binary = sid.ToBytes();
        Assert.Equal(sid, Sid.Parse(binary));
    }

    [Theory]
    [InlineData("S-1-0-0")]           // Null SID
    [InlineData("S-1-1-0")]           // Everyone
    [InlineData("S-1-5-18")]          // Local System
    [InlineData("S-1-5-32-544")]      // BUILTIN\Administrators
    [InlineData("S-1-5-21-1-2-3-1000")]
    public void RoundTrip_Various(string sid)
    {
        Sid parsed = Sid.FromString(sid);
        Assert.Equal(sid, parsed.ToString());
        Assert.Equal(parsed, Sid.Parse(parsed.ToBytes()));
    }

    [Fact]
    public void Write_ProducesExactBinary()
    {
        Sid sid = Sid.FromString("S-1-5-32-544");
        var buffer = new byte[sid.BinaryLength];
        var w = new SpanWriter(buffer);
        sid.Write(ref w);
        Assert.Equal(BuiltinAdminsBinary, buffer);
    }

    [Fact]
    public void Equality_AndHashCode()
    {
        Sid a = Sid.FromString("S-1-5-32-544");
        Sid b = Sid.Parse(BuiltinAdminsBinary);
        Sid c = Sid.FromString("S-1-5-32-545");

        Assert.True(a == b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.True(a != c);
        Assert.True(new HashSet<Sid> { a, b, c }.Count == 2);
    }

    [Fact]
    public void LargeAuthority_UsesHexForm()
    {
        Sid sid = Sid.FromString("S-1-0x010000000000-1-2");
        Assert.Equal("S-1-0x010000000000-1-2", sid.ToString());
        Assert.Equal(sid, Sid.Parse(sid.ToBytes()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("X-1-5-18")]
    [InlineData("S-1")]
    [InlineData("S-1-5-x")]
    public void TryParse_RejectsMalformed(string bad)
        => Assert.False(Sid.TryParse(bad, out _));

    [Fact]
    public void Parse_TooShort_Throws()
        => Assert.Throws<SmbWireFormatException>(() => Sid.Parse(new byte[] { 0x01, 0x02, 0x00 }));
}
