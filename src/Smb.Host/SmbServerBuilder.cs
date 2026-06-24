using System.Net;
using Smb.Auth;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.FileSystem.Versioning;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.Authorization;

namespace Smb.Host;

/// <summary>
/// Fluent-Builder für einen <see cref="SmbServer"/> mit sicheren Defaults (Context §20).
/// Macht die Lib "einfach und dynamisch" nutzbar: Endpoint, Auth-Provider und Shares
/// werden deklarativ zusammengesteckt.
/// </summary>
public sealed class SmbServerBuilder
{
    private readonly SmbServerOptions _options = new();
    private IPEndPoint _endpoint = new(IPAddress.Any, 445);
    private Action<string>? _log;

    public static SmbServerBuilder Create() => new();

    /// <summary>Setzt den Lausch-Endpunkt (Default 0.0.0.0:445).</summary>
    public SmbServerBuilder WithEndpoint(IPAddress address, int port)
    {
        _endpoint = new IPEndPoint(address, port);
        return this;
    }

    public SmbServerBuilder WithEndpoint(IPEndPoint endpoint)
    {
        _endpoint = endpoint;
        return this;
    }

    /// <summary>Setzt den Servernamen (Anzeige/NETNAME).</summary>
    public SmbServerBuilder WithServerName(string name)
    {
        _options.ServerName = name;
        return this;
    }

    /// <summary>Begrenzt den Dialektbereich (Default 2.0.2 … 3.1.1).</summary>
    public SmbServerBuilder WithDialectRange(SmbDialect min, SmbDialect max)
    {
        _options.MinDialect = min;
        _options.MaxDialect = max;
        return this;
    }

    /// <summary>Signing erzwingen (Default true) oder lockern.</summary>
    public SmbServerBuilder RequireSigning(bool require = true)
    {
        _options.RequireMessageSigning = require;
        return this;
    }

    /// <summary>Verschlüsselung global verlangen (Default false; pro Share aktivierbar).</summary>
    public SmbServerBuilder RequireEncryption(bool require = true)
    {
        _options.RequireEncryption = require;
        return this;
    }

    /// <summary>Setzt den Auth-Provider (SPNEGO/GSS) — z.B. NTLM/Kerberos (Context §9).</summary>
    public SmbServerBuilder UseAuthentication(ISpnegoNegotiator negotiator)
    {
        _options.SpnegoNegotiator = negotiator;
        return this;
    }

    /// <summary><b>Nur Test/Dev:</b> akzeptiert jede Auth anonym. In Produktion nicht verwenden (Context §8.4).</summary>
    public SmbServerBuilder UseDevAuthentication()
    {
        _options.SpnegoNegotiator = new DevSpnegoNegotiator();
        _options.AllowAnonymousAccess = true;
        _options.RequireMessageSigning = false;
        return this;
    }

    /// <summary>Fügt einen Share hinzu.</summary>
    public SmbServerBuilder AddShare(IShare share)
    {
        _options.Shares.Add(share);
        return this;
    }

    /// <summary>
    /// Fügt einen schreibbaren Disk-Share mit Versionierung („Vorherige Versionen") hinzu: ein
    /// <see cref="LocalFileStore"/> über <paramref name="directory"/>, umhüllt von einem
    /// <see cref="VersioningFileStore"/>. Überschriebene Datei-Inhalte bleiben als Snapshots
    /// über <c>@GMT-…</c>-Pfade und FSCTL_SRV_ENUMERATE_SNAPSHOTS abrufbar.
    /// </summary>
    public SmbServerBuilder AddVersionedShare(
        string name, string directory, bool encrypt = false, string remark = "", int maxVersionsPerFile = 64)
    {
        var store = new VersioningFileStore(new LocalFileStore(directory, readOnly: false), maxVersionsPerFile);
        _options.Shares.Add(new Share
        {
            Name = name,
            Type = ShareType.Disk,
            FileStore = store,
            EncryptData = encrypt,
            Remark = remark,
        });
        return this;
    }

    /// <summary>
    /// Setzt die Autorisierungs-Policy (Share-Sichtbarkeit + Zugriffsprüfung beim TREE_CONNECT).
    /// </summary>
    public SmbServerBuilder UseShareAuthorization(IShareAccessPolicy policy)
    {
        _options.ShareAccessPolicy = policy;
        return this;
    }

    /// <summary>
    /// Hakt die Autorisierung per Lambda ein — ideal für eigene Fileserver-Logik:
    /// <paramref name="authorizeConnect"/> entscheidet Zugriff + Zugriffsmaske beim TREE_CONNECT,
    /// <paramref name="isVisible"/> filtert die Share-Anzeige (Default: alle sichtbar).
    /// </summary>
    public SmbServerBuilder UseShareAuthorization(
        Func<ShareAccessContext, ShareAccessResult> authorizeConnect,
        Func<ShareAccessContext, bool>? isVisible = null)
    {
        _options.ShareAccessPolicy = new DelegateSharePolicy(authorizeConnect, isVisible);
        return this;
    }

    /// <summary>Konfiguriert die Optionen direkt (für Feineinstellungen).</summary>
    public SmbServerBuilder Configure(Action<SmbServerOptions> configure)
    {
        configure(_options);
        return this;
    }

    /// <summary>Setzt einen Log-Callback (z.B. Konsole).</summary>
    public SmbServerBuilder WithLogger(Action<string> log)
    {
        _log = log;
        return this;
    }

    public SmbServer Build() => new(_options, _endpoint, _log);
}
