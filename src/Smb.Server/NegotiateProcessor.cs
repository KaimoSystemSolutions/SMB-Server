using System.Security.Cryptography;
using Smb.Protocol.Compression;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// Processes SMB2 NEGOTIATE (Context §6): selects the highest common dialect, negotiates
/// negotiate contexts for 3.1.1 (preauth hash, cipher, signing algorithm) and builds
/// the response. Updates connection state (dialect, crypto IDs, SecurityMode) in the process.
/// </summary>
public static class NegotiateProcessor
{
    /// <summary>
    /// Selects the highest mutually supported dialect from the client list in the range
    /// [MinDialect, MaxDialect]. Returns <see cref="SmbDialect.None"/> if no common
    /// dialect exists.
    /// </summary>
    public static SmbDialect SelectDialect(IReadOnlyList<SmbDialect> clientDialects, SmbServerOptions options)
    {
        SmbDialect best = SmbDialect.None;
        foreach (SmbDialect d in clientDialects)
        {
            if (d == SmbDialect.Wildcard2FF) continue;
            if (!IsKnown(d)) continue;
            if (d < options.MinDialect || d > options.MaxDialect) continue;
            if ((ushort)d > (ushort)best) best = d;
        }
        return best;
    }

    /// <summary>
    /// Processes the negotiate request, mutates <paramref name="connection"/> and builds the
    /// response body. <paramref name="securityBuffer"/> = SPNEGO NegTokenInit2 (§9).
    /// </summary>
    public static NegotiateResponse BuildResponse(
        SmbConnection connection,
        NegotiateRequest request,
        SmbServerOptions options,
        byte[] securityBuffer)
    {
        SmbDialect dialect = SelectDialect(request.Dialects, options);
        if (dialect == SmbDialect.None)
            throw new InvalidOperationException("No common dialect with the client.");

        connection.Dialect = dialect;
        connection.ClientGuid = request.ClientGuid;
        connection.ClientCapabilities = request.Capabilities;
        connection.ClientSecurityMode = request.SecurityMode;

        // Server SecurityMode: signing always offered; required according to policy.
        var serverSecurityMode = SmbSecurityMode.SigningEnabled;
        if (options.RequireMessageSigning) serverSecurityMode |= SmbSecurityMode.SigningRequired;
        connection.ServerSecurityMode = serverSecurityMode;
        connection.ShouldSign = options.RequireMessageSigning
            || request.SecurityMode.HasFlag(SmbSecurityMode.SigningRequired);

        // Large MTU / multi-credit only when BOTH sides offer it (from 2.1 onward). Older/
        // simpler clients (e.g. pysmb) do not set the capability bit and cannot receive large
        // response frames (17-bit NBSS framing, max 128 KiB). Without large MTU the maximum
        // sizes are therefore capped at 64 KiB (like Windows, MS-SMB2 §3.3.5.4).
        bool largeMtu = dialect.SupportsLargeMtu()
                        && request.Capabilities.HasFlag(Smb2Capabilities.LargeMtu);
        connection.SupportsMultiCredit = largeMtu;

        const uint smallBuffer = 0x10000; // 64 KiB default without large MTU.
        connection.MaxReadSize = largeMtu ? options.MaxReadSize : Math.Min(options.MaxReadSize, smallBuffer);
        connection.MaxWriteSize = largeMtu ? options.MaxWriteSize : Math.Min(options.MaxWriteSize, smallBuffer);
        connection.MaxTransactSize = largeMtu ? options.MaxTransactSize : Math.Min(options.MaxTransactSize, smallBuffer);

        // Server capabilities.
        var caps = Smb2Capabilities.None;
        if (largeMtu) caps |= Smb2Capabilities.LargeMtu;

        // Multichannel is a 3.x feature (Phase 6). Advertising the capability tells the client it may
        // open additional connections and bind them to the session (§3.3.5.5.2) after discovering the
        // server's interfaces via FSCTL_QUERY_NETWORK_INTERFACE_INFO.
        if (options.EnableMultichannel && dialect.IsSmb3OrLater())
            caps |= Smb2Capabilities.MultiChannel;

        // DFS (Phase 7): when a namespace is configured, advertise SMB2_GLOBAL_CAP_DFS so clients issue
        // FSCTL_DFS_GET_REFERRALS for paths under a DFS-flagged share. Valid for all SMB2 dialects.
        if (options.DfsNamespace is not null)
            caps |= Smb2Capabilities.Dfs;

        var responseContexts = new List<NegotiateContext>();

        if (dialect == SmbDialect.Smb311)
        {
            NegotiateSmb311Contexts(connection, request, options, responseContexts);
        }
        else if (dialect is SmbDialect.Smb300 or SmbDialect.Smb302)
        {
            // Encryption via capability bit (AES-128-CCM is the only cipher for 3.0/3.0.2).
            bool clientWantsEncryption = request.Capabilities.HasFlag(Smb2Capabilities.Encryption);
            if (clientWantsEncryption || options.RequireEncryption)
            {
                caps |= Smb2Capabilities.Encryption;
                connection.CipherId = SmbCipherId.Aes128Ccm;
                connection.SupportsEncryption = true;
            }
            connection.SigningAlgorithmId = SmbSigningAlgorithmId.AesCmac;
        }
        else
        {
            // 2.0.2 / 2.1: HMAC-SHA256 signing, no encryption.
            connection.SigningAlgorithmId = SmbSigningAlgorithmId.HmacSha256;
        }

        connection.ServerCapabilities = caps;

        return new NegotiateResponse
        {
            SecurityMode = serverSecurityMode,
            DialectRevision = dialect,
            ServerGuid = options.ServerGuid,
            Capabilities = caps,
            MaxTransactSize = connection.MaxTransactSize,
            MaxReadSize = connection.MaxReadSize,
            MaxWriteSize = connection.MaxWriteSize,
            SystemTime = DateTime.UtcNow.ToFileTimeUtc(),
            ServerStartTime = 0,
            SecurityBuffer = securityBuffer,
            NegotiateContexts = responseContexts,
        };
    }

    private static void NegotiateSmb311Contexts(
        SmbConnection connection,
        NegotiateRequest request,
        SmbServerOptions options,
        List<NegotiateContext> responseContexts)
    {
        // --- PREAUTH_INTEGRITY: required. SHA-512 only. Server salt random. ---
        connection.PreauthIntegrityHashId = PreauthHashAlgorithm.Sha512;
        responseContexts.Add(new PreauthIntegrityContext
        {
            HashAlgorithms = [PreauthHashAlgorithm.Sha512],
            Salt = RandomNumberGenerator.GetBytes(32),
        });

        // --- ENCRYPTION: choose a cipher from the client list according to server preference. ---
        EncryptionContext? clientEnc = request.NegotiateContexts.OfType<EncryptionContext>().FirstOrDefault();
        if (clientEnc is not null)
        {
            SmbCipherId chosen = PickByPreference(options.CipherPreference, clientEnc.Ciphers);
            if (chosen != SmbCipherId.None)
            {
                connection.CipherId = chosen;
                connection.SupportsEncryption = true;
                responseContexts.Add(new EncryptionContext { Ciphers = [chosen] });
            }
        }

        // --- SIGNING: choose an algorithm according to server preference; default AES-CMAC. ---
        SigningContext? clientSign = request.NegotiateContexts.OfType<SigningContext>().FirstOrDefault();
        if (clientSign is not null)
        {
            SmbSigningAlgorithmId chosen = PickSigning(options.SigningPreference, clientSign.Algorithms);
            connection.SigningAlgorithmId = chosen;
            responseContexts.Add(new SigningContext { Algorithms = [chosen] });
        }
        else
        {
            connection.SigningAlgorithmId = SmbSigningAlgorithmId.AesCmac; // Default without context.
        }

        // --- COMPRESSION (M10.3): advertise the algorithms we can actually produce/decode that the
        //     client also offered, in server-preference order. The first becomes the outbound choice;
        //     any advertised algorithm may arrive inbound and is decodable. Unchained framing only
        //     (SMB2_COMPRESSION_FLAG_NONE) — chaining is not advertised. ---
        CompressionContext? clientComp = request.NegotiateContexts.OfType<CompressionContext>().FirstOrDefault();
        if (options.EnableCompression && clientComp is not null)
        {
            List<SmbCompressionAlgorithm> agreed = PickCompression(options.CompressionPreference, clientComp.Algorithms);
            if (agreed.Count > 0)
            {
                // Advertise everything we can decode (so the peer may send any of them), but pick the
                // outbound algorithm from the subset we can also produce. A decode-only algorithm
                // (e.g. LZ77+Huffman) is still received; if nothing agreed is encodable we send plain.
                connection.CompressionAlgorithm = agreed.FirstOrDefault(SmbCompressor.IsEncodable, SmbCompressionAlgorithm.None);
                responseContexts.Add(new CompressionContext { Flags = 0, Algorithms = agreed });
            }
        }
    }

    /// <summary>
    /// Intersects the server preference, the client's offered algorithms and the codecs this build can
    /// decode (<see cref="SmbCompressor.DecodableAlgorithms"/>), preserving server-preference order.
    /// </summary>
    private static List<SmbCompressionAlgorithm> PickCompression(
        IReadOnlyList<SmbCompressionAlgorithm> serverPref, IReadOnlyList<SmbCompressionAlgorithm> clientList)
    {
        var agreed = new List<SmbCompressionAlgorithm>();
        foreach (SmbCompressionAlgorithm pref in serverPref)
            if (SmbCompressor.IsDecodable(pref) && clientList.Contains(pref) && !agreed.Contains(pref))
                agreed.Add(pref);
        return agreed;
    }

    private static SmbCipherId PickByPreference(IReadOnlyList<SmbCipherId> serverPref, IReadOnlyList<SmbCipherId> clientList)
    {
        foreach (SmbCipherId pref in serverPref)
            if (clientList.Contains(pref)) return pref;
        return SmbCipherId.None;
    }

    private static SmbSigningAlgorithmId PickSigning(IReadOnlyList<SmbSigningAlgorithmId> serverPref, IReadOnlyList<SmbSigningAlgorithmId> clientList)
    {
        foreach (SmbSigningAlgorithmId pref in serverPref)
            if (clientList.Contains(pref)) return pref;
        // Fallback: first mentioned by client, otherwise AES-CMAC.
        return clientList.Count > 0 ? clientList[0] : SmbSigningAlgorithmId.AesCmac;
    }

    private static bool IsKnown(SmbDialect d) => d is
        SmbDialect.Smb202 or SmbDialect.Smb210 or
        SmbDialect.Smb300 or SmbDialect.Smb302 or SmbDialect.Smb311;
}
