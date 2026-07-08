using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Smb.Host;

/// <summary>
/// [M10.1] Configuration for SMB-over-TLS: the transport (TCP) stream of every connection on the
/// listener is wrapped in an <see cref="SslStream"/> before any NBSS/SMB2 bytes are exchanged, so
/// the whole SMB conversation runs inside a TLS tunnel (comparable to SMB-over-QUIC's TLS 1.3
/// requirement, but over TCP). This is a pure transport wrapper — it is independent of, and layered
/// beneath, SMB3 signing/encryption, which still apply on the plaintext SMB frames.
/// <para>
/// Enable it via <see cref="SmbServerBuilder.UseTls(X509Certificate2, Action{SmbTlsOptions}?)"/>.
/// When TLS is configured a client must complete the TLS handshake first; a plain-TCP client that
/// sends NBSS immediately fails the handshake and is dropped. Run TLS on a dedicated port (Windows
/// uses 445 for plain SMB; a common convention for SMB-over-TLS is a separate port such as 8445).
/// </para>
/// </summary>
public sealed class SmbTlsOptions
{
    /// <summary>
    /// The server certificate presented in the TLS handshake. Required. Must contain a private key
    /// (use a PFX / <see cref="X509Certificate2"/> with the key attached).
    /// </summary>
    public required X509Certificate2 ServerCertificate { get; set; }

    /// <summary>
    /// Require the client to present a certificate (mutual TLS) for an additional layer of
    /// authentication beyond SMB's SPNEGO/GSS. Default <c>false</c>. When <c>true</c>, a client
    /// without a certificate — or one rejected by <see cref="ClientCertificateValidation"/> — fails
    /// the handshake and the connection is dropped.
    /// </summary>
    public bool RequireClientCertificate { get; set; }

    /// <summary>
    /// Optional validation callback for the client certificate (mutual TLS). When null the platform
    /// default chain validation applies. Provide a callback to pin a CA, check a thumbprint, or accept
    /// a self-signed client certificate. Only consulted when the client presents a certificate.
    /// </summary>
    public RemoteCertificateValidationCallback? ClientCertificateValidation { get; set; }

    /// <summary>
    /// TLS protocol versions offered to clients. Default TLS 1.2 + TLS 1.3 (older versions are
    /// deliberately excluded). Narrow this to <see cref="SslProtocols.Tls13"/> only for a hardened
    /// deployment.
    /// </summary>
    public SslProtocols EnabledProtocols { get; set; } = SslProtocols.Tls12 | SslProtocols.Tls13;

    /// <summary>
    /// Maximum time allowed for the TLS handshake on a new connection before it is aborted (slow-loris
    /// / half-open protection at the transport layer). Default 15 s.
    /// </summary>
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Escape hatch for full control over the handshake: invoked with the
    /// <see cref="SslServerAuthenticationOptions"/> built from the properties above, immediately
    /// before <c>AuthenticateAsServerAsync</c>. Use it to set ALPN, a certificate-selection callback,
    /// cipher-suite policy, etc. Anything set here overrides the derived values.
    /// </summary>
    public Action<SslServerAuthenticationOptions>? ConfigureAuthentication { get; set; }

    /// <summary>Builds the <see cref="SslServerAuthenticationOptions"/> for a handshake from this config.</summary>
    internal SslServerAuthenticationOptions BuildAuthenticationOptions()
    {
        var auth = new SslServerAuthenticationOptions
        {
            ServerCertificate = ServerCertificate,
            ClientCertificateRequired = RequireClientCertificate,
            EnabledSslProtocols = EnabledProtocols,
            RemoteCertificateValidationCallback = ClientCertificateValidation,
        };
        ConfigureAuthentication?.Invoke(auth);
        return auth;
    }

    /// <summary>Validates the TLS configuration and throws on misconfiguration.</summary>
    internal void Validate()
    {
        if (ServerCertificate is null)
            throw new InvalidOperationException("SmbTlsOptions.ServerCertificate is required.");
        if (!ServerCertificate.HasPrivateKey)
            throw new InvalidOperationException("SmbTlsOptions.ServerCertificate must contain a private key.");
    }
}
