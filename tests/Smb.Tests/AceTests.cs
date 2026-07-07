using Smb.Protocol.Security;
using Xunit;

namespace Smb.Tests;

/// <summary>Phase 3 / M3.1 increment B — the <see cref="Ace"/> access control entry (MS-DTYP §2.4.4).</summary>
public class AceTests
{
    private static readonly Sid Everyone = Sid.FromString("S-1-1-0");
    private const uint GenericAll = 0x10000000;
    private const uint FileRead = 0x00120089;

    [Fact]
    public void AllowAce_RoundTrips()
    {
        Ace ace = Ace.Allow(Everyone, FileRead, AceFlags.ContainerInherit | AceFlags.ObjectInherit);

        byte[] bytes = ace.ToBytes();
        Assert.Equal(ace.BinaryLength, bytes.Length);
        Assert.Equal(0, bytes.Length % 4);                 // DWORD-aligned

        Ace parsed = Ace.Parse(bytes, out int consumed);
        Assert.Equal(bytes.Length, consumed);
        Assert.Equal(AceType.AccessAllowed, parsed.Type);
        Assert.Equal(AceFlags.ContainerInherit | AceFlags.ObjectInherit, parsed.Flags);
        Assert.Equal(FileRead, parsed.AccessMask);
        Assert.Equal(Everyone, parsed.Sid);
    }

    [Fact]
    public void DenyAce_RoundTrips()
    {
        Ace ace = Ace.Deny(Sid.FromString("S-1-5-32-546"), GenericAll);
        Ace parsed = Ace.Parse(ace.ToBytes(), out _);
        Assert.Equal(AceType.AccessDenied, parsed.Type);
        Assert.Equal(GenericAll, parsed.AccessMask);
        Assert.Equal(Sid.FromString("S-1-5-32-546"), parsed.Sid);
    }

    [Fact]
    public void ParsesKnownBinary()
    {
        // ACCESS_ALLOWED_ACE for S-1-1-0 (Everyone), mask 0x001F01FF (full), no flags.
        byte[] bytes =
        [
            0x00, 0x00, 0x14, 0x00,             // type=allowed, flags=0, size=20
            0xFF, 0x01, 0x1F, 0x00,             // mask 0x001F01FF
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // S-1-1-0
        ];
        Ace ace = Ace.Parse(bytes, out int consumed);
        Assert.Equal(20, consumed);
        Assert.Equal(0x001F01FFu, ace.AccessMask);
        Assert.Equal("S-1-1-0", ace.Sid!.ToString());
        Assert.Equal(bytes, ace.ToBytes());
    }

    [Fact]
    public void UnknownAceType_IsPreservedVerbatim()
    {
        // An object ACE (type 0x05) we don't model — must round-trip losslessly via RawData.
        byte[] bytes = [0x05, 0x00, 0x08, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        Ace ace = Ace.Parse(bytes, out _);
        Assert.False(ace.IsBasic);
        Assert.Null(ace.Sid);
        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, ace.RawData);
        Assert.Equal(bytes, ace.ToBytes());
    }

    [Fact]
    public void Audit_SetsAuditType()
    {
        Ace ace = Ace.Audit(Everyone, FileRead, AceFlags.FailedAccess);
        Assert.Equal(AceType.SystemAudit, ace.Type);
        Assert.Equal(AceType.SystemAudit, Ace.Parse(ace.ToBytes(), out _).Type);
    }
}
