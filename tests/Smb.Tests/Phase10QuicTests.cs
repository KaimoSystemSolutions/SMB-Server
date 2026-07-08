using System.Buffers.Binary;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Host;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// [M10.2] SMB over QUIC transport tests. QUIC carries the same 4-byte-length-prefixed SMB2 framing
/// as direct TCP over a mandatory TLS 1.3 handshake, with each inbound bidirectional stream served as
/// one SMB2 connection. Gated on <see cref="QuicListener.IsSupported"/> (MsQuic availability).
/// </summary>
#pragma warning disable CA1416 // guarded by QuicListener.IsSupported at the top of each test
public class Phase10QuicTests
{
    [Fact]
    public async Task Quic_CompletesHandshake_AndAnswersNegotiate()
    {
        if (!QuicListener.IsSupported) return; // QUIC/MsQuic unavailable → skip (e.g. Linux without libmsquic)

        using X509Certificate2 cert = CreateSelfSignedCert("CN=smb-quic-test");
        await using SmbServer server = BuildQuicServer(cert);
        await server.StartAsync();

        await using QuicConnection conn = await ConnectAsync(server.QuicEndpoint!);
        await using QuicStream stream = await conn.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        await SendFramed(stream, TestHelpers.BuildNegotiateRequest(
            [SmbDialect.Smb210, SmbDialect.Smb300, SmbDialect.Smb311], ciphers: [SmbCipherId.Aes128Gcm]));
        byte[] resp = await ReadFramed(stream);

        Smb2Header header = Smb2Header.Read(resp);
        Assert.Equal(SmbCommand.Negotiate, header.Command);
        Assert.Equal(NtStatus.Success, header.Status);
        Assert.True(header.Flags.HasFlag(Smb2HeaderFlags.ServerToRedir));

        await server.StopAsync();
    }

    [Fact]
    public async Task Quic_FullReadFlow_OverStream()
    {
        if (!QuicListener.IsSupported) return; // QUIC/MsQuic unavailable → skip (e.g. Linux without libmsquic)

        byte[] fileContent = Encoding.ASCII.GetBytes("hello over quic — a file served through a QUIC stream");
        string dir = Path.Combine(Path.GetTempPath(), "smbquic_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllBytes(Path.Combine(dir, "q.txt"), fileContent);
            using X509Certificate2 cert = CreateSelfSignedCert("CN=smb-quic-read");
            await using SmbServer server = SmbServerBuilder.Create()
                .WithEndpoint(IPAddress.Loopback, 0)
                .UseDevAuthentication()
                .AddShare(Share.CreateIpc())
                .AddShare(new Share { Name = "Data", Type = ShareType.Disk, FileStore = new LocalFileStore(dir, readOnly: true) })
                .UseQuic(cert, port: 0)
                .Build();
            await server.StartAsync();

            await using QuicConnection conn = await ConnectAsync(server.QuicEndpoint!);
            await using QuicStream stream = await conn.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

            await SendFramed(stream, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311], ciphers: [SmbCipherId.Aes128Gcm]));
            await ReadFramed(stream);
            await SendFramed(stream, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
            ulong sid = Smb2Header.Read(await ReadFramed(stream)).SessionId;

            await SendFramed(stream, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\server\Data"));
            uint tid = Smb2Header.Read(await ReadFramed(stream)).TreeId;

            await SendFramed(stream, TestHelpers.BuildCreateRequest(3, sid, tid, "q.txt",
                desiredAccess: 0x00000001, disposition: (uint)CreateDisposition.Open,
                options: (uint)CreateOptions.NonDirectoryFile));
            byte[] create = await ReadFramed(stream);
            Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
            int body = Smb2Header.Size;
            ulong p = BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8));
            ulong v = BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8));

            await SendFramed(stream, TestHelpers.BuildReadRequest(4, sid, tid, p, v, (uint)fileContent.Length, 0));
            byte[] readResp = await ReadFramed(stream);
            Assert.Equal(NtStatus.Success, Smb2Header.Read(readResp).Status);

            int dataOffset = readResp[body + 2];
            int dataLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(readResp.AsSpan(body + 4, 4));
            Assert.Equal(fileContent, readResp.AsSpan(dataOffset, dataLength).ToArray());

            await server.StopAsync();
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public async Task Quic_MutualTls_AcceptsPresentedClientCertificate()
    {
        if (!QuicListener.IsSupported) return; // QUIC/MsQuic unavailable → skip (e.g. Linux without libmsquic)

        using X509Certificate2 serverCert = CreateSelfSignedCert("CN=smb-quic-mtls");
        using X509Certificate2 clientCert = CreateSelfSignedCert("CN=smb-quic-client");
        var seen = new TaskCompletionSource<X509Certificate2?>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using SmbServer server = BuildQuicServer(serverCert, quic =>
        {
            quic.RequireClientCertificate = true;
            quic.ClientCertificateValidation = (_, cert, _, _) =>
            {
                seen.TrySetResult(cert as X509Certificate2);
                return cert is not null;
            };
        });
        await server.StartAsync();

        await using QuicConnection conn = await ConnectAsync(server.QuicEndpoint!, clientCert);
        await using QuicStream stream = await conn.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        await SendFramed(stream, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311], ciphers: [SmbCipherId.Aes128Gcm]));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(await ReadFramed(stream)).Status);

        X509Certificate2? presented = await seen.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.NotNull(presented);
        Assert.Equal(clientCert.Thumbprint, presented!.Thumbprint);

        await server.StopAsync();
    }

    [Fact]
    public async Task Quic_RequiringClientCertificate_RejectsClientWithout()
    {
        if (!QuicListener.IsSupported) return; // QUIC/MsQuic unavailable → skip (e.g. Linux without libmsquic)

        using X509Certificate2 serverCert = CreateSelfSignedCert("CN=smb-quic-mtls-reject");
        await using SmbServer server = BuildQuicServer(serverCert, quic =>
        {
            quic.RequireClientCertificate = true;
            quic.ClientCertificateValidation = (_, cert, _, _) => cert is not null;
        });
        await server.StartAsync();

        // No client certificate → the QUIC/TLS 1.3 handshake must fail (connect or first stream I/O throws).
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await using QuicConnection conn = await ConnectAsync(server.QuicEndpoint!);
            await using QuicStream stream = await conn.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            await SendFramed(stream, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311], ciphers: [SmbCipherId.Aes128Gcm]));
            await ReadFramed(stream);
        });

        await server.StopAsync();
    }

    [Fact]
    public void UseQuic_WithCertificateLackingPrivateKey_ThrowsAtBuild()
    {
        using X509Certificate2 withKey = CreateSelfSignedCert("CN=smb-quic-nokey");
        using X509Certificate2 publicOnly = X509CertificateLoader.LoadCertificate(withKey.Export(X509ContentType.Cert));

        SmbServerBuilder builder = SmbServerBuilder.Create()
            .WithEndpoint(IPAddress.Loopback, 0)
            .UseDevAuthentication()
            .UseQuic(publicOnly, port: 0);

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    // --- helpers ------------------------------------------------------------

    private static SmbServer BuildQuicServer(X509Certificate2 cert, Action<SmbQuicOptions>? configure = null)
        => SmbServerBuilder.Create()
            .WithEndpoint(IPAddress.Loopback, 0)
            .UseDevAuthentication()
            .AddShare(new Share { Name = "Data", Type = ShareType.Disk })
            .UseQuic(cert, port: 0, configure)
            .Build();

    private static async Task<QuicConnection> ConnectAsync(IPEndPoint endpoint, X509Certificate2? clientCert = null)
    {
        var ssl = new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            ApplicationProtocols = [SmbQuicOptions.SmbAlpn],
            RemoteCertificateValidationCallback = (_, _, _, _) => true, // trust the self-signed server cert
        };
        if (clientCert is not null) ssl.ClientCertificates = [clientCert];

        var options = new QuicClientConnectionOptions
        {
            RemoteEndPoint = endpoint,
            DefaultStreamErrorCode = 0,
            DefaultCloseErrorCode = 0,
            ClientAuthenticationOptions = ssl,
        };
        return await QuicConnection.ConnectAsync(options);
    }

    private static async Task SendFramed(QuicStream stream, byte[] message)
    {
        await stream.WriteAsync(NbssFrame.Wrap(message));
        await stream.FlushAsync();
    }

    private static async Task<byte[]> ReadFramed(QuicStream stream)
    {
        var prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix);
        var payload = new byte[NbssFrame.ReadLength(prefix)];
        await stream.ReadExactlyAsync(payload);
        return payload;
    }

    private static X509Certificate2 CreateSelfSignedCert(string subjectName)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2")], critical: false));

        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        req.CertificateExtensions.Add(san.Build());

        using X509Certificate2 cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), password: null,
            keyStorageFlags: X509KeyStorageFlags.Exportable);
    }
}
