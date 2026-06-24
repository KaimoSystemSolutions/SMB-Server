using System.Security.Cryptography;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.State;

namespace Smb.Server;

/// <summary>
/// Verarbeitet SMB2 NEGOTIATE (Context §6): wählt den höchsten gemeinsamen Dialekt, handelt
/// bei 3.1.1 die Negotiate-Contexts aus (Preauth-Hash, Cipher, Signing-Algorithmus) und baut
/// die Response. Aktualisiert dabei den Connection-Zustand (Dialekt, Krypto-IDs, SecurityMode).
/// </summary>
public static class NegotiateProcessor
{
    /// <summary>
    /// Wählt den höchsten gemeinsam unterstützten Dialekt aus der Client-Liste im Bereich
    /// [MinDialect, MaxDialect]. Liefert <see cref="SmbDialect.None"/>, wenn kein gemeinsamer
    /// Dialekt existiert.
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
    /// Verarbeitet den Negotiate-Request, mutiert <paramref name="connection"/> und baut den
    /// Response-Body. <paramref name="securityBuffer"/> = SPNEGO NegTokenInit2 (§9).
    /// </summary>
    public static NegotiateResponse BuildResponse(
        SmbConnection connection,
        NegotiateRequest request,
        SmbServerOptions options,
        byte[] securityBuffer)
    {
        SmbDialect dialect = SelectDialect(request.Dialects, options);
        if (dialect == SmbDialect.None)
            throw new InvalidOperationException("Kein gemeinsamer Dialekt mit dem Client.");

        connection.Dialect = dialect;
        connection.ClientGuid = request.ClientGuid;
        connection.ClientCapabilities = request.Capabilities;
        connection.ClientSecurityMode = request.SecurityMode;

        // SecurityMode des Servers: Signing immer angeboten; erforderlich gemäß Policy.
        var serverSecurityMode = SmbSecurityMode.SigningEnabled;
        if (options.RequireMessageSigning) serverSecurityMode |= SmbSecurityMode.SigningRequired;
        connection.ServerSecurityMode = serverSecurityMode;
        connection.ShouldSign = options.RequireMessageSigning
            || request.SecurityMode.HasFlag(SmbSecurityMode.SigningRequired);

        // Large MTU / Multi-Credit nur, wenn BEIDE Seiten es anbieten (ab 2.1). Ältere/
        // einfachere Clients (z.B. pysmb) setzen das Capability-Bit nicht und können große
        // Antwort-Frames nicht empfangen (17-Bit-NBSS-Framing, max. 128 KiB). Ohne Large MTU
        // werden die Maximalgrößen daher auf 64 KiB gedeckelt (so wie Windows, MS-SMB2 §3.3.5.4).
        bool largeMtu = dialect.SupportsLargeMtu()
                        && request.Capabilities.HasFlag(Smb2Capabilities.LargeMtu);
        connection.SupportsMultiCredit = largeMtu;

        const uint smallBuffer = 0x10000; // 64 KiB Default ohne Large MTU.
        connection.MaxReadSize = largeMtu ? options.MaxReadSize : Math.Min(options.MaxReadSize, smallBuffer);
        connection.MaxWriteSize = largeMtu ? options.MaxWriteSize : Math.Min(options.MaxWriteSize, smallBuffer);
        connection.MaxTransactSize = largeMtu ? options.MaxTransactSize : Math.Min(options.MaxTransactSize, smallBuffer);

        // Capabilities des Servers.
        var caps = Smb2Capabilities.None;
        if (largeMtu) caps |= Smb2Capabilities.LargeMtu;

        var responseContexts = new List<NegotiateContext>();

        if (dialect == SmbDialect.Smb311)
        {
            NegotiateSmb311Contexts(connection, request, options, responseContexts);
        }
        else if (dialect is SmbDialect.Smb300 or SmbDialect.Smb302)
        {
            // Encryption via Capability-Bit (AES-128-CCM ist der einzige Cipher für 3.0/3.0.2).
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
            // 2.0.2 / 2.1: HMAC-SHA256-Signing, keine Verschlüsselung.
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
        // --- PREAUTH_INTEGRITY: Pflicht. Nur SHA-512. Server-Salt zufällig. ---
        connection.PreauthIntegrityHashId = PreauthHashAlgorithm.Sha512;
        responseContexts.Add(new PreauthIntegrityContext
        {
            HashAlgorithms = [PreauthHashAlgorithm.Sha512],
            Salt = RandomNumberGenerator.GetBytes(32),
        });

        // --- ENCRYPTION: einen Cipher gemäß Server-Präferenz aus der Client-Liste wählen. ---
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

        // --- SIGNING: einen Algorithmus gemäß Server-Präferenz wählen; Default AES-CMAC. ---
        SigningContext? clientSign = request.NegotiateContexts.OfType<SigningContext>().FirstOrDefault();
        if (clientSign is not null)
        {
            SmbSigningAlgorithmId chosen = PickSigning(options.SigningPreference, clientSign.Algorithms);
            connection.SigningAlgorithmId = chosen;
            responseContexts.Add(new SigningContext { Algorithms = [chosen] });
        }
        else
        {
            connection.SigningAlgorithmId = SmbSigningAlgorithmId.AesCmac; // Default ohne Context.
        }
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
        // Fallback: erster vom Client genannter, sonst AES-CMAC.
        return clientList.Count > 0 ? clientList[0] : SmbSigningAlgorithmId.AesCmac;
    }

    private static bool IsKnown(SmbDialect d) => d is
        SmbDialect.Smb202 or SmbDialect.Smb210 or
        SmbDialect.Smb300 or SmbDialect.Smb302 or SmbDialect.Smb311;
}
