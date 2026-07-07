namespace Smb.Protocol.Security;

/// <summary>Common well-known SIDs (MS-DTYP §2.4.2.4) used when building/evaluating ACLs.</summary>
public static class WellKnownSids
{
    /// <summary>S-1-0-0 — the Null SID.</summary>
    public static Sid Null { get; } = Sid.Create(0, 0);

    /// <summary>S-1-1-0 — Everyone (World).</summary>
    public static Sid Everyone { get; } = Sid.Create(1, 0);

    /// <summary>S-1-3-0 — Creator Owner (placeholder in inheritable ACEs).</summary>
    public static Sid CreatorOwner { get; } = Sid.Create(3, 0);

    /// <summary>S-1-3-1 — Creator Group.</summary>
    public static Sid CreatorGroup { get; } = Sid.Create(3, 1);

    /// <summary>S-1-5-11 — Authenticated Users.</summary>
    public static Sid AuthenticatedUsers { get; } = Sid.Create(5, 11);

    /// <summary>S-1-5-18 — Local System.</summary>
    public static Sid LocalSystem { get; } = Sid.Create(5, 18);

    /// <summary>S-1-5-32-544 — BUILTIN\Administrators.</summary>
    public static Sid BuiltinAdministrators { get; } = Sid.Create(5, 32, 544);

    /// <summary>S-1-5-32-545 — BUILTIN\Users.</summary>
    public static Sid BuiltinUsers { get; } = Sid.Create(5, 32, 545);
}
