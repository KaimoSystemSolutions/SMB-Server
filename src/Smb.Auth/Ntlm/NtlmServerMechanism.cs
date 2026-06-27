using System.Security.Cryptography;
using System.Text;
using Smb.Crypto;
using Smb.Protocol.Enums;

namespace Smb.Auth.Ntlm;

/// <summary>NTLM server configuration (names for TargetInfo).</summary>
public sealed class NtlmServerOptions
{
    public string NetbiosDomainName { get; set; } = "WORKGROUP";
    public string NetbiosComputerName { get; set; } = Environment.MachineName.ToUpperInvariant();
    public string DnsDomainName { get; set; } = "workgroup";
    public string DnsComputerName { get; set; } = Environment.MachineName.ToLowerInvariant();
}

/// <summary>
/// Server-side NTLMv2 mechanism (Context §9.3, MS-NLMP §3.3.2). Two-stage:
/// NEGOTIATE → CHALLENGE → AUTHENTICATE. Verifies the NTProofStr against the NT hash provided via
/// <see cref="IIdentityBackend"/> and derives the ExportedSessionKey (GSS session key).
/// NTLMv2 only (Context §20).
/// </summary>
public sealed class NtlmServerMechanism : IGssMechanism
{
    private enum Stage { ExpectNegotiate, ExpectAuthenticate, Done }

    private readonly IIdentityBackend _backend;
    private readonly NtlmServerOptions _options;
    private Stage _stage = Stage.ExpectNegotiate;
    private byte[] _serverChallenge = [];

    public NtlmServerMechanism(IIdentityBackend backend, NtlmServerOptions options)
    {
        _backend = backend;
        _options = options;
    }

    public string MechOid => Oids.GssOids.Ntlm;
    public bool IsComplete => _stage == Stage.Done;

    public GssResult Accept(ReadOnlySpan<byte> inToken)
    {
        return _stage switch
        {
            Stage.ExpectNegotiate => HandleNegotiate(inToken),
            Stage.ExpectAuthenticate => HandleAuthenticate(inToken),
            _ => GssResult.Failed(NtStatus.AccessDenied),
        };
    }

    private GssResult HandleNegotiate(ReadOnlySpan<byte> inToken)
    {
        // (The NEGOTIATE_MESSAGE is only read for its flags; its content is otherwise not needed.)
        _serverChallenge = RandomNumberGenerator.GetBytes(8);

        byte[] targetInfo = NtlmAvPairs.Encode(
        [
            new NtlmAvPair(NtlmAvId.NbDomainName, Encoding.Unicode.GetBytes(_options.NetbiosDomainName)),
            new NtlmAvPair(NtlmAvId.NbComputerName, Encoding.Unicode.GetBytes(_options.NetbiosComputerName)),
            new NtlmAvPair(NtlmAvId.DnsDomainName, Encoding.Unicode.GetBytes(_options.DnsDomainName)),
            new NtlmAvPair(NtlmAvId.DnsComputerName, Encoding.Unicode.GetBytes(_options.DnsComputerName)),
            new NtlmAvPair(NtlmAvId.Timestamp, BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc())),
        ]);

        var challenge = new NtlmChallengeMessage
        {
            ServerChallenge = _serverChallenge,
            TargetName = _options.NetbiosDomainName,
            Flags = NtlmNegotiateFlags.NegotiateUnicode | NtlmNegotiateFlags.NegotiateNtlm
                  | NtlmNegotiateFlags.RequestTarget | NtlmNegotiateFlags.NegotiateTargetInfo
                  | NtlmNegotiateFlags.TargetTypeDomain | NtlmNegotiateFlags.NegotiateExtendedSessionSecurity
                  | NtlmNegotiateFlags.NegotiateAlwaysSign | NtlmNegotiateFlags.Negotiate128
                  | NtlmNegotiateFlags.Negotiate56 | NtlmNegotiateFlags.NegotiateKeyExchange,
            TargetInfo = targetInfo,
        };

        _stage = Stage.ExpectAuthenticate;
        return GssResult.Continue(challenge.ToArray());
    }

    private GssResult HandleAuthenticate(ReadOnlySpan<byte> inToken)
    {
        _stage = Stage.Done;

        NtlmAuthenticateMessage auth;
        try { auth = NtlmAuthenticateMessage.Parse(inToken); }
        catch (FormatException) { return GssResult.Failed(NtStatus.InvalidParameter); }

        if (auth.NtChallengeResponse.Length < 16)
            return GssResult.Failed(NtStatus.LogonFailure);

        if (!_backend.TryGetNtHash(auth.DomainName, auth.UserName, out byte[] ntHash))
            return GssResult.Failed(NtStatus.LogonFailure);

        // Recompute the NTProofStr independently and compare in constant time (Context §9.3).
        byte[] ntowfV2 = NtlmCryptography.NtowfV2(ntHash, auth.UserName, auth.DomainName);
        byte[] expectedProof = NtlmCryptography.NtProofString(ntowfV2, _serverChallenge, auth.ClientChallengeBlob);

        if (!CryptographicOperations.FixedTimeEquals(expectedProof, auth.NtProofString))
            return GssResult.Failed(NtStatus.LogonFailure);

        // Derive keys.
        byte[] sessionBaseKey = NtlmCryptography.SessionBaseKey(ntowfV2, expectedProof);
        bool keyExch = auth.Flags.HasFlag(NtlmNegotiateFlags.NegotiateKeyExchange);
        byte[] exportedSessionKey = NtlmCryptography.ExportedSessionKey(
            sessionBaseKey, keyExch, auth.EncryptedRandomSessionKey);

        SecurityIdentity identity;
        try { identity = _backend.Resolve(auth.DomainName, auth.UserName); }
        catch (KeyNotFoundException) { return GssResult.Failed(NtStatus.LogonFailure); }

        return GssResult.Succeeded(exportedSessionKey, identity);
    }
}
