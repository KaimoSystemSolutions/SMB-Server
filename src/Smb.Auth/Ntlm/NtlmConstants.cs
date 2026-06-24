namespace Smb.Auth.Ntlm;

/// <summary>NTLMSSP-Signatur und Message-Typen (MS-NLMP §2.2).</summary>
public static class NtlmConstants
{
    /// <summary>"NTLMSSP\0".</summary>
    public static ReadOnlySpan<byte> Signature => [0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00];

    public const uint MessageTypeNegotiate = 1;
    public const uint MessageTypeChallenge = 2;
    public const uint MessageTypeAuthenticate = 3;

    /// <summary>Prüft, ob ein Token mit der NTLMSSP-Signatur beginnt (raw NTLM ohne SPNEGO).</summary>
    public static bool IsNtlmSsp(ReadOnlySpan<byte> token)
        => token.Length >= 8 && token[..8].SequenceEqual(Signature);
}

/// <summary>NTLM NegotiateFlags (MS-NLMP §2.2.2.5), nur die hier relevanten.</summary>
[Flags]
public enum NtlmNegotiateFlags : uint
{
    NegotiateUnicode = 0x00000001,
    NegotiateOem = 0x00000002,
    RequestTarget = 0x00000004,
    NegotiateSign = 0x00000010,
    NegotiateSeal = 0x00000020,
    NegotiateNtlm = 0x00000200,
    NegotiateAlwaysSign = 0x00008000,
    TargetTypeDomain = 0x00010000,
    TargetTypeServer = 0x00020000,
    NegotiateExtendedSessionSecurity = 0x00080000,
    NegotiateTargetInfo = 0x00800000,
    NegotiateVersion = 0x02000000,
    Negotiate128 = 0x20000000,
    NegotiateKeyExchange = 0x40000000,
    Negotiate56 = 0x80000000,
}

/// <summary>AV-Pair-IDs in TargetInfo (MS-NLMP §2.2.2.1).</summary>
public enum NtlmAvId : ushort
{
    EOL = 0x0000,
    NbComputerName = 0x0001,
    NbDomainName = 0x0002,
    DnsComputerName = 0x0003,
    DnsDomainName = 0x0004,
    DnsTreeName = 0x0005,
    Flags = 0x0006,
    Timestamp = 0x0007,
    SingleHost = 0x0008,
    TargetName = 0x0009,
    ChannelBindings = 0x000A,
}
