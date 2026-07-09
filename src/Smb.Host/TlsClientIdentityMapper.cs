using System.Security.Cryptography.X509Certificates;
using Smb.Auth;

namespace Smb.Host;

/// <summary>
/// [M10.1] Maps a validated mutual-TLS client certificate to an SMB <see cref="SecurityIdentity"/>.
/// <para>
/// This is the seam that <b>surfaces</b> a transport-authenticated client certificate to the SMB
/// layer (in the same spirit as the injectable <c>IKerberosTicketValidator</c> and <c>ILdapSearcher</c>
/// seams — the library owns no certificate-to-principal policy). The host runs it once per connection,
/// right after the TLS handshake accepts the certificate, and stores the result on
/// <c>SmbConnection.TransportAssertedIdentity</c> alongside <c>SmbConnection.ClientCertificate</c>.
/// </para>
/// The mapped identity is a <i>transport assertion</i>: it is made available to authorization and
/// audit and to a consumer's own <c>IIdentityBackend</c>, but it does not by itself complete an SMB
/// session — SPNEGO still runs, so the session key and signing posture are unchanged. A consumer that
/// wants certificate-based session authentication builds on this deliberately (the transport-trust and
/// session-key implications are theirs to own).
/// </summary>
public interface ITlsClientIdentityMapper
{
    /// <summary>
    /// Returns the SMB identity for <paramref name="clientCertificate"/>, or <c>null</c> to assert no
    /// identity (the certificate is still recorded on the connection). Called only for a certificate
    /// the TLS layer already validated. Should not throw for an unrecognized certificate — return
    /// <c>null</c> instead.
    /// </summary>
    SecurityIdentity? Map(X509Certificate2 clientCertificate);
}

/// <summary>Adapts a delegate to <see cref="ITlsClientIdentityMapper"/> for inline wiring.</summary>
public sealed class DelegatingTlsClientIdentityMapper(Func<X509Certificate2, SecurityIdentity?> map) : ITlsClientIdentityMapper
{
    private readonly Func<X509Certificate2, SecurityIdentity?> _map = map ?? throw new ArgumentNullException(nameof(map));

    public SecurityIdentity? Map(X509Certificate2 clientCertificate) => _map(clientCertificate);
}
