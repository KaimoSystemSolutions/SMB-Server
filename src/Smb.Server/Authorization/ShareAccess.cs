using Smb.Auth;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Server.State;

namespace Smb.Server.Authorization;

/// <summary>
/// Kontext einer Share-Autorisierungsentscheidung. Enthält die authentifizierte Identität,
/// den betroffenen Share und (sofern vorhanden) die Verbindung — damit kann eine Policy nach
/// User, Gruppen-SID, Dialekt, ClientGuid usw. unterscheiden.
/// </summary>
public sealed class ShareAccessContext
{
    public required SecurityIdentity Identity { get; init; }
    public required IShare Share { get; init; }

    /// <summary>Verbindung (für Dialekt/ClientGuid/Verschlüsselungsstatus). Bei reiner Enumeration ggf. null.</summary>
    public SmbConnection? Connection { get; init; }

    /// <summary>Bequemer Zugriff auf den Share-Namen.</summary>
    public string ShareName => Share.Name;
}

/// <summary>Ergebnis einer Verbindungs-Autorisierung (Context §12: Zugriff prüfen, MaximalAccess liefern).</summary>
public sealed class ShareAccessResult
{
    public bool Allowed { get; private init; }

    /// <summary>Gewährte Zugriffsmaske (nur relevant bei <see cref="Allowed"/>). Begrenzt auch den späteren Datei-Zugriff.</summary>
    public SmbAccessMask MaximalAccess { get; private init; }

    /// <summary>NTSTATUS bei Ablehnung (Default <c>STATUS_ACCESS_DENIED</c>, Context §12).</summary>
    public NtStatus DenyStatus { get; private init; }

    /// <summary>Erlaubt die Verbindung mit der angegebenen (Default: vollen) Zugriffsmaske.</summary>
    public static ShareAccessResult Grant(SmbAccessMask maximalAccess = SmbAccessMask.FullAccess)
        => new() { Allowed = true, MaximalAccess = maximalAccess };

    /// <summary>Lehnt die Verbindung ab.</summary>
    public static ShareAccessResult Deny(NtStatus status = NtStatus.AccessDenied)
        => new() { Allowed = false, DenyStatus = status };
}

/// <summary>
/// <b>Einhak-Punkt für Autorisierung.</b> Wird vom Server konsultiert, um
/// (a) bei der Share-Auflistung zu filtern (<see cref="IsVisible"/>, Access-Based Enumeration)
/// und (b) beim TREE_CONNECT Zugriff + Zugriffsmaske zu bestimmen
/// (<see cref="AuthorizeConnect"/>, Context §12). Eigene Implementierung setzen, um z.B. nur
/// bestimmten Usern/Gruppen Zugriff zu geben.
/// </summary>
public interface IShareAccessPolicy
{
    /// <summary>True, wenn der Share dem User in einer Auflistung angezeigt werden darf.</summary>
    bool IsVisible(ShareAccessContext context);

    /// <summary>Entscheidet über die TREE_CONNECT-Verbindung und liefert die gewährte Zugriffsmaske.</summary>
    ShareAccessResult AuthorizeConnect(ShareAccessContext context);
}

/// <summary>Default-Policy: alle Shares sichtbar, voller Zugriff für jede gültige Session (bisheriges Verhalten).</summary>
public sealed class AllowAllSharePolicy : IShareAccessPolicy
{
    public bool IsVisible(ShareAccessContext context) => true;
    public ShareAccessResult AuthorizeConnect(ShareAccessContext context) => ShareAccessResult.Grant();
}

/// <summary>
/// Delegate-basierte Policy — erlaubt das Einhaken per Lambda, ohne eine Klasse zu schreiben:
/// <code>
/// new DelegateSharePolicy(
///     isVisible:  ctx => ctx.Identity.UserName == "alice" || ctx.ShareName != "Secret",
///     authorize:  ctx => ctx.Identity.GroupSids.Contains(AdminSid)
///                         ? ShareAccessResult.Grant()
///                         : ShareAccessResult.Grant(SmbAccessMask.ReadOnly));
/// </code>
/// </summary>
public sealed class DelegateSharePolicy : IShareAccessPolicy
{
    private readonly Func<ShareAccessContext, bool> _isVisible;
    private readonly Func<ShareAccessContext, ShareAccessResult> _authorize;

    public DelegateSharePolicy(
        Func<ShareAccessContext, ShareAccessResult> authorize,
        Func<ShareAccessContext, bool>? isVisible = null)
    {
        _authorize = authorize;
        _isVisible = isVisible ?? (_ => true);
    }

    public bool IsVisible(ShareAccessContext context) => _isVisible(context);
    public ShareAccessResult AuthorizeConnect(ShareAccessContext context) => _authorize(context);
}
