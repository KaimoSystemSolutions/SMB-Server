using System.Security.Cryptography;
using System.Text;
using Smb.Crypto;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Auth.Ntlm;

/// <summary>NTLM server configuration (names for TargetInfo).</summary>
public sealed class NtlmServerOptions
{
    public string NetbiosDomainName { get; set; } = "WORKGROUP";
    public string NetbiosComputerName { get; set; } = Environment.MachineName.ToUpperInvariant();
    public string DnsDomainName { get; set; } = "workgroup";
    public string DnsComputerName { get; set; } = Environment.MachineName.ToLowerInvariant();

    /// <summary>
    /// [AUDIT-2026-06] O1: when true, an AUTHENTICATE_MESSAGE <b>must</b> carry a valid MIC — a client
    /// that does not announce/provide one is rejected. When false (default, for compatibility with
    /// older clients), the MIC is verified only when the client announces it via <c>MsvAvFlags</c>.
    /// Either way, a present-but-invalid MIC is always rejected (downgrade protection, MS-NLMP §3.2.5.1.2).
    /// <para>
    /// The <c>MsvAvFlags</c> announcement itself cannot be stripped by a MITM: it lives in the NTLMv2
    /// <c>temp</c> blob covered by the NTProofStr, so tampering breaks authentication before the MIC path.
    /// The only case the default misses is a pre-timestamp client that never sends a MIC. <b>Recommended
    /// for high-security deployments:</b> set this to <c>true</c> — all modern clients (Windows 7+, Samba,
    /// macOS) always send a MIC. See docs/SECURITY_AUDIT.md (Reviewed &amp; OK).
    /// </para>
    /// </summary>
    public bool RequireMessageIntegrity { get; set; }
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

    // Raw NEGOTIATE and CHALLENGE messages, kept for the O1 MIC check
    // (MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE ‖ CHALLENGE ‖ AUTHENTICATE-with-zero-MIC)).
    private byte[] _negotiateMessage = [];
    private byte[] _challengeMessage = [];

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
        // Keep the raw NEGOTIATE_MESSAGE for the MIC computation (O1).
        _negotiateMessage = inToken.ToArray();
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
        _challengeMessage = challenge.ToArray();
        return GssResult.Continue(_challengeMessage);
    }

    private GssResult HandleAuthenticate(ReadOnlySpan<byte> inToken)
    {
        _stage = Stage.Done;

        NtlmAuthenticateMessage auth;
        // [REVIEW-2026-07] A malformed AUTHENTICATE (bad signature/type, truncated fixed fields, or a
        // field offset/length pointing outside the message) must fail on the defined path, never throw
        // out of the mechanism. FormatException covers signature/type/bounds; SmbWireFormatException
        // covers a SpanReader underflow on a truncated message.
        try { auth = NtlmAuthenticateMessage.Parse(inToken); }
        catch (Exception ex) when (ex is FormatException or SmbWireFormatException)
        {
            return GssResult.Failed(NtStatus.InvalidParameter);
        }

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

        // [AUDIT-2026-06] O1: MIC verification (downgrade protection). Verify when the client announced
        // a MIC via MsvAvFlags, or unconditionally in strict mode. A present-but-wrong MIC is rejected.
        bool micAnnounced = ClientAnnouncedMic(auth.ClientChallengeBlob);
        if (micAnnounced || _options.RequireMessageIntegrity)
        {
            if (!micAnnounced)
                return GssResult.Failed(NtStatus.LogonFailure); // strict mode: MIC required but absent
            if (!VerifyMic(exportedSessionKey, inToken, auth.Mic))
                return GssResult.Failed(NtStatus.LogonFailure);
        }

        SecurityIdentity identity;
        try { identity = _backend.Resolve(auth.DomainName, auth.UserName); }
        catch (KeyNotFoundException) { return GssResult.Failed(NtStatus.LogonFailure); }

        return GssResult.Succeeded(exportedSessionKey, identity);
    }

    /// <summary>
    /// True if the client set the <c>MIC provided</c> bit (0x2) in its <c>MsvAvFlags</c> AV pair, which
    /// lives in the NTLMv2 client challenge ("temp") starting at offset 28 (after RespType/Reserved/
    /// Timestamp/ClientChallenge/Reserved), MS-NLMP §2.2.2.7/§3.1.5.1.2.
    /// </summary>
    private static bool ClientAnnouncedMic(ReadOnlySpan<byte> clientChallengeBlob)
    {
        const int avPairsOffset = 28;
        if (clientChallengeBlob.Length <= avPairsOffset) return false;
        foreach (NtlmAvPair pair in NtlmAvPairs.Decode(clientChallengeBlob[avPairsOffset..]))
            if (pair.Id == NtlmAvId.Flags && pair.Value.Length >= 4)
                return (BitConverter.ToUInt32(pair.Value, 0) & 0x2) != 0;
        return false;
    }

    /// <summary>
    /// Recomputes the MIC over NEGOTIATE ‖ CHALLENGE ‖ AUTHENTICATE (with the 16-byte MIC field at
    /// offset 72 zeroed) and compares it in constant time with the one the client sent.
    /// </summary>
    private bool VerifyMic(byte[] exportedSessionKey, ReadOnlySpan<byte> authenticateMessage, byte[] receivedMic)
    {
        const int micOffset = 72;
        if (_negotiateMessage.Length == 0 || _challengeMessage.Length == 0) return false;
        if (authenticateMessage.Length < micOffset + 16) return false;

        byte[] withZeroMic = authenticateMessage.ToArray();
        Array.Clear(withZeroMic, micOffset, 16);
        byte[] expected = NtlmCryptography.ComputeMic(
            exportedSessionKey, _negotiateMessage, _challengeMessage, withZeroMic);
        return CryptographicOperations.FixedTimeEquals(expected, receivedMic);
    }
}
