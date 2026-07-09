using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Smb.Auth;
using Smb.FileSystem;
using Smb.Host;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// [M10.1] SMB-over-TLS transport tests: a client must complete a TLS handshake before any SMB2
/// byte is exchanged; NEGOTIATE then flows through the encrypted tunnel. Mutual TLS (client
/// certificate) is exercised for both the accept and reject paths.
/// </summary>
public class TlsTransportTests
{
    [Fact]
    public async Task Server_OverTls_CompletesHandshake_AndAnswersNegotiate()
    {
        using X509Certificate2 serverCert = CreateSelfSignedCert("CN=smb-tls-test");
        await using SmbServer server = BuildTlsServer(serverCert);
        await server.StartAsync();
        int port = server.Endpoint.Port;

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        await using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false,
            userCertificateValidationCallback: (_, _, _, _) => true); // trust the self-signed server cert
        await ssl.AuthenticateAsClientAsync("localhost");

        Assert.True(ssl.IsAuthenticated);
        Assert.True(ssl.IsEncrypted);

        await AssertNegotiateSucceedsAsync(ssl);
        await server.StopAsync();
    }

    [Fact]
    public async Task Server_RequiringClientCertificate_RejectsClientWithout()
    {
        using X509Certificate2 serverCert = CreateSelfSignedCert("CN=smb-tls-mtls");
        await using SmbServer server = BuildTlsServer(serverCert, tls =>
        {
            tls.RequireClientCertificate = true;
            // A realistic mTLS validator: reject when no client certificate is presented. (A blanket
            // "return true" would accept the null cert that TLS 1.3 surfaces for a certificate-less client.)
            tls.ClientCertificateValidation = (_, cert, _, _) => cert is not null;
        });
        await server.StartAsync();
        int port = server.Endpoint.Port;

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        await using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false,
            userCertificateValidationCallback: (_, _, _, _) => true);

        // No client certificate presented → the connection must never become usable. Depending on the
        // negotiated TLS version the failure surfaces during the handshake (TLS 1.2) or on the first I/O
        // afterwards (TLS 1.3 completes the client leg before the server rejects the empty certificate),
        // so assert the whole handshake-then-NEGOTIATE flow throws rather than the handshake alone.
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await ssl.AuthenticateAsClientAsync("localhost");
            byte[] negotiate = TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311], ciphers: [SmbCipherId.Aes128Gcm]);
            await ssl.WriteAsync(NbssFrame.Wrap(negotiate));
            await ssl.FlushAsync();
            var prefix = new byte[4];
            await ssl.ReadExactlyAsync(prefix); // server dropped the connection → EndOfStream/IOException
        });
        await server.StopAsync();
    }

    [Fact]
    public async Task Server_WithMutualTls_AcceptsPresentedClientCertificate()
    {
        using X509Certificate2 serverCert = CreateSelfSignedCert("CN=smb-tls-mtls-ok");
        using X509Certificate2 clientCert = CreateSelfSignedCert("CN=smb-tls-client");
        // The validator runs on the server's handshake thread; use a TCS so the test observes the
        // presented certificate with proper synchronization (TLS 1.3 lets the client leg finish first).
        var seenClientCert = new TaskCompletionSource<X509Certificate2?>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using SmbServer server = BuildTlsServer(serverCert, tls =>
        {
            tls.RequireClientCertificate = true;
            tls.ClientCertificateValidation = (_, cert, _, _) =>
            {
                seenClientCert.TrySetResult(cert as X509Certificate2);
                return cert is not null; // accept the (self-signed) client cert; a real deployment pins it
            };
        });
        await server.StartAsync();
        int port = server.Endpoint.Port;

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        await using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false,
            userCertificateValidationCallback: (_, _, _, _) => true);
        var authOptions = new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            ClientCertificates = [clientCert],
        };
        await ssl.AuthenticateAsClientAsync(authOptions);

        Assert.True(ssl.IsMutuallyAuthenticated);
        // NEGOTIATE also proves the server kept the connection (client cert accepted).
        await AssertNegotiateSucceedsAsync(ssl);

        X509Certificate2? presented = await seenClientCert.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.NotNull(presented);
        Assert.Equal(clientCert.Thumbprint, presented!.Thumbprint);
        await server.StopAsync();
    }

    [Fact]
    public void DelegatingTlsClientIdentityMapper_InvokesDelegate()
    {
        using X509Certificate2 cert = CreateSelfSignedCert("CN=smb-tls-map-unit");
        var identity = new SecurityIdentity { DomainName = "CERT", UserName = "unit" };
        ITlsClientIdentityMapper mapper = new DelegatingTlsClientIdentityMapper(_ => identity);
        Assert.Same(identity, mapper.Map(cert));
    }

    [Fact]
    public async Task Server_WithClientIdentityMapper_MapsPresentedCertificate()
    {
        using X509Certificate2 serverCert = CreateSelfSignedCert("CN=smb-tls-map-srv");
        using X509Certificate2 clientCert = CreateSelfSignedCert("CN=smb-tls-map-client");
        // The mapper runs on the server after the handshake; capture the cert it received via a TCS.
        var mappedFrom = new TaskCompletionSource<X509Certificate2>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using SmbServer server = BuildTlsServer(serverCert, tls =>
        {
            tls.RequireClientCertificate = true;
            tls.ClientCertificateValidation = (_, cert, _, _) => cert is not null;
            tls.ClientIdentityMapper = new DelegatingTlsClientIdentityMapper(cert =>
            {
                mappedFrom.TrySetResult(cert);
                return new SecurityIdentity { DomainName = "CERT", UserName = cert.GetNameInfo(X509NameType.SimpleName, false) };
            });
        });
        await server.StartAsync();
        int port = server.Endpoint.Port;

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        await using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false,
            userCertificateValidationCallback: (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            ClientCertificates = [clientCert],
        });
        await AssertNegotiateSucceedsAsync(ssl); // drive a round-trip so the server-side capture has run

        X509Certificate2 seen = await mappedFrom.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(clientCert.Thumbprint, seen.Thumbprint); // mapper received the presented client cert
        await server.StopAsync();
    }

    [Fact]
    public void UseTls_WithCertificateLackingPrivateKey_Throws()
    {
        using X509Certificate2 withKey = CreateSelfSignedCert("CN=smb-tls-nokey");
        // A public-only certificate (private key stripped) must be rejected at Build().
        using X509Certificate2 publicOnly = X509CertificateLoader.LoadCertificate(withKey.Export(X509ContentType.Cert));

        SmbServerBuilder builder = SmbServerBuilder.Create()
            .WithEndpoint(IPAddress.Loopback, 0)
            .UseDevAuthentication()
            .UseTls(publicOnly);

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    // --- helpers ------------------------------------------------------------

    private static SmbServer BuildTlsServer(X509Certificate2 cert, Action<SmbTlsOptions>? configure = null)
        => SmbServerBuilder.Create()
            .WithEndpoint(IPAddress.Loopback, 0)
            .UseDevAuthentication()
            .AddShare(new Share { Name = "Data", Type = ShareType.Disk })
            .UseTls(cert, configure)
            .Build();

    /// <summary>Sends a NEGOTIATE over the (already-authenticated TLS) stream and asserts a valid response.</summary>
    private static async Task AssertNegotiateSucceedsAsync(Stream stream)
    {
        byte[] negotiate = TestHelpers.BuildNegotiateRequest(
            [SmbDialect.Smb210, SmbDialect.Smb300, SmbDialect.Smb311],
            ciphers: [SmbCipherId.Aes128Gcm]);
        await stream.WriteAsync(NbssFrame.Wrap(negotiate));
        await stream.FlushAsync();

        var prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix);
        int length = NbssFrame.ReadLength(prefix);
        Assert.True(length is > 0 and < 65536);

        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload);

        Smb2Header header = Smb2Header.Read(payload);
        Assert.Equal(SmbCommand.Negotiate, header.Command);
        Assert.Equal(NtStatus.Success, header.Status);
        Assert.True(header.Flags.HasFlag(Smb2HeaderFlags.ServerToRedir));
    }

    /// <summary>
    /// Creates an ephemeral self-signed certificate (with private key) for the loopback host. Exported
    /// to PFX and re-imported so SChannel can use the private key for a server-side handshake on Windows.
    /// </summary>
    private static X509Certificate2 CreateSelfSignedCert(string subjectName)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2")], critical: false)); // server + client auth

        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        req.CertificateExtensions.Add(san.Build());

        using X509Certificate2 cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        // Round-trip through PFX so the key is usable by the platform TLS stack (Windows SChannel).
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), password: null,
            keyStorageFlags: X509KeyStorageFlags.Exportable);
    }
}
