using System.DirectoryServices.Protocols;
using System.Net;
using SdsScope = System.DirectoryServices.Protocols.SearchScope;

namespace Smb.Auth.Ldap;

/// <summary>
/// Connection settings for <see cref="DirectoryServicesLdapSearcher"/>: which domain controller to bind
/// to and how. Separate from <see cref="LdapIdentityBackendOptions"/> (which holds only search/mapping
/// config) so the identity backend stays transport-agnostic.
/// </summary>
public sealed class LdapConnectionOptions
{
    /// <summary>Domain controller host (or comma-separated failover list), e.g. <c>dc01.corp.example.com</c>. Required.</summary>
    public required string Server { get; init; }

    /// <summary>LDAP port. 389 for plain/StartTLS, 636 for LDAPS.</summary>
    public int Port { get; init; } = 389;

    /// <summary>Use LDAPS (SSL/TLS on the wire). Set the port to 636 accordingly.</summary>
    public bool UseSsl { get; init; }

    /// <summary>Bind mechanism. Negotiate (Kerberos/NTLM) by default; use <see cref="AuthType.Basic"/> for simple bind.</summary>
    public AuthType AuthType { get; init; } = AuthType.Negotiate;

    /// <summary>Bind credentials. <c>null</c> binds as the current process identity (Windows/Negotiate).</summary>
    public NetworkCredential? Credential { get; init; }

    /// <summary>Per-request timeout.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// <see cref="ILdapSearcher"/> backed by <c>System.DirectoryServices.Protocols</c> (M2.2, increment E).
/// This is the concrete network binding to a directory server; it is the <b>only</b> piece that carries
/// the external LDAP dependency, which is why it lives in a separate opt-in assembly. Wire it into the
/// identity backend:
/// <code>
/// using var searcher = new DirectoryServicesLdapSearcher(
///     new LdapConnectionOptions { Server = "dc01.corp.example.com", Port = 636, UseSsl = true });
/// var backend = new LdapIdentityBackend(
///     searcher, new LdapIdentityBackendOptions { SearchBase = "DC=corp,DC=example,DC=com" });
/// </code>
/// The connection is created and bound in the constructor and reused for every search. The type is
/// thread-safe for concurrent searches to the extent <c>LdapConnection</c> is (it serializes requests
/// internally); create additional instances for higher parallelism.
/// </summary>
public sealed class DirectoryServicesLdapSearcher : ILdapSearcher, IDisposable
{
    private readonly LdapConnection _connection;

    public DirectoryServicesLdapSearcher(LdapConnectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.Server))
            throw new ArgumentException("Server is required.", nameof(options));

        var identifier = new LdapDirectoryIdentifier(options.Server, options.Port);
        _connection = options.Credential is null
            ? new LdapConnection(identifier)
            : new LdapConnection(identifier, options.Credential, options.AuthType);

        _connection.AuthType = options.AuthType;
        _connection.SessionOptions.ProtocolVersion = 3;
        _connection.SessionOptions.SecureSocketLayer = options.UseSsl;
        _connection.Timeout = options.Timeout;
        _connection.Bind();
    }

    public IReadOnlyList<LdapEntry> Search(string baseDn, string filter, LdapSearchScope scope, IReadOnlyList<string> attributes)
    {
        var request = new SearchRequest(baseDn, filter, MapScope(scope), attributes is null ? null : [.. attributes]);
        var response = (SearchResponse)_connection.SendRequest(request);

        var entries = new List<LdapEntry>(response.Entries.Count);
        foreach (SearchResultEntry entry in response.Entries)
            entries.Add(Convert(entry));
        return entries;
    }

    private static LdapEntry Convert(SearchResultEntry entry)
    {
        var attributes = new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase);
        foreach (string name in entry.Attributes.AttributeNames)
        {
            // Always pull raw bytes: binary attributes (objectSid, tokenGroups) must not be stringified;
            // textual attributes come back as their UTF-8 octets, which LdapEntry decodes on demand.
            object[] raw = entry.Attributes[name].GetValues(typeof(byte[]));
            var values = new byte[raw.Length][];
            for (int i = 0; i < raw.Length; i++) values[i] = (byte[])raw[i];
            attributes[name] = values;
        }
        return new LdapEntry(entry.DistinguishedName, attributes);
    }

    private static SdsScope MapScope(LdapSearchScope scope) => scope switch
    {
        LdapSearchScope.Base => SdsScope.Base,
        LdapSearchScope.OneLevel => SdsScope.OneLevel,
        _ => SdsScope.Subtree,
    };

    public void Dispose() => _connection.Dispose();
}
