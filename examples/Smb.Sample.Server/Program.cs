using System.Net;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Host;
using Smb.Protocol.Enums;
using Smb.Sample.Server;
using Smb.Server.Authorization;

// =============================================================================
//  Beispiel: SMB-Server mit echtem NTLM-Login + ordner-basiertem Share.
//
//  Start:   dotnet run --project examples/Smb.Sample.Server
//  Es startet den Server, führt einen TCP-Selbsttest aus (Login → Listing → Datei
//  lesen) und bleibt dann laufen, damit man auch extern verbinden kann.
//
//  Port 445 ist unter Windows i.d.R. belegt → Beispiel nutzt 4445.
// =============================================================================

const string Domain = "WORKGROUP";
const string User = "demo";
const string Password = "demo123";        // Demo-Credentials
const int Port = 4445;

// --- Relativer Share-Ordner (neben der Binärdatei: examples/.../shared) -------
string shareDir = Path.Combine(AppContext.BaseDirectory, "shared");
Directory.CreateDirectory(shareDir);

// --- Versionierter Share ("Vorherige Versionen") ------------------------------
string versionDir = Path.Combine(AppContext.BaseDirectory, "versioned");
Directory.CreateDirectory(versionDir);

// --- Share mit EIGENER Versionierung (Override-Demo, siehe DemoExternalVersionStore) ---
string customDir = Path.Combine(AppContext.BaseDirectory, "custom_versioned");
string customVersionStore = Path.Combine(AppContext.BaseDirectory, "custom_versions_store");
Directory.CreateDirectory(customDir);

// --- Eigene Lock-Verwaltung mit persistentem Audit-Trail (Override-Demo, siehe DemoAuditingLockManager) ---
string lockAuditFile = Path.Combine(AppContext.BaseDirectory, "locks", "lock_audit.log");

// --- Benutzer-DB (lokal; später per LDAP/AD austauschbar) ---------------------
var identities = new InMemoryIdentityBackend()
    .AddUser(Domain, User, Password, userSid: "S-1-5-21-100-200-300-1001");

// --- Server bauen -------------------------------------------------------------
await using SmbServer server = SmbServerBuilder.Create()
    .WithEndpoint(IPAddress.Loopback, Port)
    .WithServerName("SAMPLE")
    .RequireSigning(false)  // Demo schlank halten; in Produktion: true
    .UseAuthentication(new NtlmSpnegoNegotiator(identities, new NtlmServerOptions { NetbiosDomainName = Domain }))
    .UseShareAuthorization(
        authorizeConnect: ctx => ShareAccessResult.Grant(SmbAccessMask.FullAccess),
        isVisible: _ => true)
    .AddShare(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(shareDir, readOnly: false) })
    // Variante A — Lib-Default: eine Zeile, In-Memory-Versionierung.
    .AddVersionedShare("Versions", versionDir, remark: "Vorherige Versionen (Lib-Default)")
    // Variante B — eigene Implementierung einklinken: derselbe Share-Mechanismus, aber ein
    // selbstgebauter IFileStore/ISnapshotStore mit persistentem Versionsspeicher.
    .AddShare(new Share
    {
        Name = "CustomVersions",
        Type = ShareType.Disk,
        Remark = "Vorherige Versionen (eigene Impl)",
        FileStore = new DemoExternalVersionStore(
            new LocalFileStore(customDir, readOnly: false),
            customVersionStore,
            msg => Console.WriteLine($"[customver] {msg}")),
    })
    // Eigene Lock-Verwaltung einklinken (Default wäre der prozesslokale InMemoryLockManager).
    .UseLockManager(new DemoAuditingLockManager(lockAuditFile, log: msg => Console.WriteLine($"[locks] {msg}")))
    .WithLogger(msg => Console.WriteLine($"[server] {msg}"))
    .Build();

await server.StartAsync();
Console.WriteLine($"Share 'Files':          {shareDir}");
Console.WriteLine($"Share 'Versions':       {versionDir} (Lib-Default, In-Memory)");
Console.WriteLine($"Share 'CustomVersions': {customDir} (eigene Impl, persistent → {customVersionStore})");
Console.WriteLine($"Lock-Audit:             {lockAuditFile} (eigener ILockManager)");
Console.WriteLine($"Anmeldung:              {Domain}\\{User} / {Password}");
Console.WriteLine();

// --- Selbsttest: über TCP einloggen, Verzeichnis listen, Datei lesen ----------
Console.WriteLine("=== Selbsttest (echter TCP-Client) ===");
try
{
    using var client = new DemoClient();
    await client.ConnectAsync("127.0.0.1", Port);

    bool loggedIn = await client.LoginAsync(Domain, User, Password);
    Console.WriteLine($"Login als {Domain}\\{User}: {(loggedIn ? "OK" : "FEHLGESCHLAGEN")}");

    bool wrongLogin = await TryWrongLogin();
    Console.WriteLine($"Login mit falschem Passwort wird abgelehnt: {(wrongLogin ? "OK" : "unerwartet akzeptiert")}");

    if (loggedIn && await client.TreeConnectAsync(@"\\SAMPLE\Files"))
    {
        IReadOnlyList<string> files = await client.ListDirectoryAsync();
        Console.WriteLine("Dateien im Share: " + string.Join(", ", files));

        string? content = await client.ReadFileAsync("welcome.txt");
        Console.WriteLine("Inhalt von welcome.txt:");
        Console.WriteLine("---");
        Console.WriteLine(content?.TrimEnd());
        Console.WriteLine("---");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Selbsttest-Fehler: {ex.Message}");
}
Console.WriteLine("=== Selbsttest Ende ===");
Console.WriteLine();

// --- Laufend halten -----------------------------------------------------------
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
Console.WriteLine($"Server läuft auf {server.Endpoint}. Strg+C zum Beenden.");
try { await Task.Delay(Timeout.Infinite, cts.Token); }
catch (OperationCanceledException) { }
await server.StopAsync();

async Task<bool> TryWrongLogin()
{
    using var c = new DemoClient();
    await c.ConnectAsync("127.0.0.1", Port);
    return !await c.LoginAsync(Domain, User, "falsch");
}
