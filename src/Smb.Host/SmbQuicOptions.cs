using System.Net.Quic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

// System.Net.Quic is platform-annotated ([SupportedOSPlatform] linux/macOS/windows). All entry points
// are reached only behind the runtime QuicListener.IsSupported guard (SmbQuicListener.StartAsync throws
// otherwise), which is the sanctioned availability check for QUIC — so CA1416 is suppressed here.
#pragma warning disable CA1416

namespace Smb.Host;

/// <summary>
/// [M10.2] Configuration for SMB over QUIC (MS-SMB2 §2.1 QUIC transport; Windows Server 2022+ parity).
/// QUIC is a UDP-based transport that carries the same 4-byte-length-prefixed SMB2 framing as direct
/// TCP, but with a mandatory, built-in TLS 1.3 handshake — so the transport is always encrypted and
/// server-authenticated, and (optionally) client-authenticated by certificate. Each inbound
/// bidirectional QUIC stream is served as one SMB2 connection.
/// <para>
/// QUIC support depends on the native MsQuic library (built into Windows 11 / Server 2022+; on Linux
/// it needs the <c>libmsquic</c> package). It is therefore an <b>optional, additional</b> listener —
/// <see cref="System.Net.Quic.QuicListener.IsSupported"/> is checked at start, and TCP remains the
/// always-available default. Enable via
/// <see cref="SmbServerBuilder.UseQuic(X509Certificate2, int, Action{SmbQuicOptions}?)"/>; QUIC
/// conventionally runs on UDP port 443.
/// </para>
/// </summary>
public sealed class SmbQuicOptions
{
    /// <summary>The ALPN protocol identifier for SMB over QUIC (MS-SMB2): "smb".</summary>
    public static readonly SslApplicationProtocol SmbAlpn = new("smb");

    /// <summary>
    /// The server certificate presented in the QUIC (TLS 1.3) handshake. Required, must contain a
    /// private key. QUIC has no unauthenticated mode, so a certificate is always mandatory (unlike TCP,
    /// where TLS is opt-in).
    /// </summary>
    public required X509Certificate2 ServerCertificate { get; set; }

    /// <summary>
    /// Require the client to present a certificate for an additional authentication layer beyond SMB's
    /// SPNEGO/GSS. Default <c>false</c>. A required-but-absent or rejected client certificate fails the
    /// handshake and the connection is dropped.
    /// </summary>
    public bool RequireClientCertificate { get; set; }

    /// <summary>
    /// Optional validation callback for the client certificate. When null the platform default chain
    /// validation applies. Provide a callback to pin a CA, check a thumbprint, or accept a self-signed
    /// client certificate.
    /// </summary>
    public RemoteCertificateValidationCallback? ClientCertificateValidation { get; set; }

    /// <summary>
    /// ALPN protocols advertised by the listener. Defaults to the single SMB identifier
    /// (<see cref="SmbAlpn"/>). Rarely needs changing.
    /// </summary>
    public IReadOnlyList<SslApplicationProtocol> ApplicationProtocols { get; set; } = [SmbAlpn];

    /// <summary>
    /// Maximum concurrent inbound bidirectional streams a single QUIC connection may open (each maps to
    /// one SMB2 connection). SMB uses one stream per connection; the default 256 leaves generous head
    /// room while bounding per-connection resource use.
    /// </summary>
    public int MaxInboundStreams { get; set; } = 256;

    /// <summary>
    /// QUIC transport idle timeout (no traffic) before the connection is closed. <see cref="TimeSpan.Zero"/>
    /// (default) uses the MsQuic default. SMB's own idle/session timeouts (M8.2) apply on top.
    /// </summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// Escape hatch for full control over the TLS 1.3 handshake: invoked with the
    /// <see cref="SslServerAuthenticationOptions"/> derived from the properties above, immediately
    /// before it is handed to the QUIC listener. Anything set here overrides the derived values.
    /// </summary>
    public Action<SslServerAuthenticationOptions>? ConfigureAuthentication { get; set; }

    /// <summary>Builds the per-connection server options (TLS + stream limits) for the QUIC listener.</summary>
    internal QuicServerConnectionOptions BuildServerConnectionOptions()
    {
        var auth = new SslServerAuthenticationOptions
        {
            ServerCertificate = ServerCertificate,
            ClientCertificateRequired = RequireClientCertificate,
            RemoteCertificateValidationCallback = ClientCertificateValidation,
            ApplicationProtocols = [.. ApplicationProtocols],
            // QUIC mandates TLS 1.3; the stack enforces it regardless of EnabledSslProtocols.
        };
        ConfigureAuthentication?.Invoke(auth);

        return new QuicServerConnectionOptions
        {
            DefaultStreamErrorCode = 0,
            DefaultCloseErrorCode = 0,
            IdleTimeout = IdleTimeout,
            MaxInboundBidirectionalStreams = MaxInboundStreams,
            MaxInboundUnidirectionalStreams = 0, // SMB over QUIC uses bidirectional streams only
            ServerAuthenticationOptions = auth,
        };
    }

    /// <summary>Validates the QUIC configuration and throws on misconfiguration.</summary>
    internal void Validate()
    {
        if (ServerCertificate is null)
            throw new InvalidOperationException("SmbQuicOptions.ServerCertificate is required.");
        if (!ServerCertificate.HasPrivateKey)
            throw new InvalidOperationException("SmbQuicOptions.ServerCertificate must contain a private key.");
        if (ApplicationProtocols is not { Count: > 0 })
            throw new InvalidOperationException("SmbQuicOptions.ApplicationProtocols must list at least one ALPN protocol.");
    }
}
