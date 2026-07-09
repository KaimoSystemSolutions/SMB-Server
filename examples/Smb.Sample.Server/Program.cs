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
//  Example: SMB server with real NTLM login + folder-based share.
//
//  Start:   dotnet run --project examples/Smb.Sample.Server
//  Starts the server, runs a TCP self-test (login → listing → file read)
//  and then keeps running so you can also connect externally.
//
//  Port 445 is typically occupied on Windows → example uses 4445.
// =============================================================================

const string Domain = "WORKGROUP";
const string User = "demo";
const string Password = "demo123";        // Demo credentials
const int Port = 4445;

// --- Relative share folder (next to the binary: examples/.../shared) ----------
string shareDir = Path.Combine(AppContext.BaseDirectory, "shared");
Directory.CreateDirectory(shareDir);

// --- Versioned share ("Previous Versions") ------------------------------------
string versionDir = Path.Combine(AppContext.BaseDirectory, "versioned");
Directory.CreateDirectory(versionDir);

// --- Share with CUSTOM versioning (override demo, see DemoExternalVersionStore) ---
string customDir = Path.Combine(AppContext.BaseDirectory, "custom_versioned");
string customVersionStore = Path.Combine(AppContext.BaseDirectory, "custom_versions_store");
Directory.CreateDirectory(customDir);

// --- Custom lock management with persistent audit trail (override demo, see DemoAuditingLockManager) ---
string lockAuditFile = Path.Combine(AppContext.BaseDirectory, "locks", "lock_audit.log");

// --- User database (local; replaceable later via LDAP/AD) ---------------------
var identities = new InMemoryIdentityBackend()
    .AddUser(Domain, User, Password, userSid: "S-1-5-21-100-200-300-1001");

// --- Build server -------------------------------------------------------------
await using SmbServer server = SmbServerBuilder.Create()
    .WithEndpoint(IPAddress.Loopback, Port)
    .WithServerName("SAMPLE")
    .RequireSigning(false)  // Keep demo lean; in production: true
    .UseAuthentication(new NtlmSpnegoNegotiator(identities, new NtlmServerOptions { NetbiosDomainName = Domain }))
    .UseShareAuthorization(
        authorizeConnect: ctx => ShareAccessResult.Grant(SmbAccessMask.FullAccess),
        isVisible: _ => true)
    .AddShare(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(shareDir, readOnly: false) })
    // Variant A — lib default: one line, in-memory versioning.
    .AddVersionedShare("Versions", versionDir, remark: "Previous Versions (lib default)")
    // Variant B — plug in a custom implementation: same share mechanism but a
    // custom IFileStore/ISnapshotStore with persistent version storage.
    .AddShare(new Share
    {
        Name = "CustomVersions",
        Type = ShareType.Disk,
        Remark = "Previous Versions (custom impl)",
        FileStore = new DemoExternalVersionStore(
            new LocalFileStore(customDir, readOnly: false),
            customVersionStore,
            msg => Console.WriteLine($"[customver] {msg}")),
    })
    // Plug in custom lock management (default would be the process-local InMemoryLockManager).
    .UseLockManager(new DemoAuditingLockManager(lockAuditFile, log: msg => Console.WriteLine($"[locks] {msg}")))
    .WithLogger(msg => Console.WriteLine($"[server] {msg}"))
    .Build();

await server.StartAsync();
Console.WriteLine($"Share 'Files':          {shareDir}");
Console.WriteLine($"Share 'Versions':       {versionDir} (lib default, in-memory)");
Console.WriteLine($"Share 'CustomVersions': {customDir} (custom impl, persistent → {customVersionStore})");
Console.WriteLine($"Lock audit:             {lockAuditFile} (custom ILockManager)");
Console.WriteLine($"Login:                  {Domain}\\{User} / {Password}");
Console.WriteLine();

// --- Self-test: log in via TCP, list directory, read file ---------------------
Console.WriteLine("=== Self-test (real TCP client) ===");
try
{
    using var client = new DemoClient();
    await client.ConnectAsync("127.0.0.1", Port);

    bool loggedIn = await client.LoginAsync(Domain, User, Password);
    Console.WriteLine($"Login as {Domain}\\{User}: {(loggedIn ? "OK" : "FAILED")}");

    bool wrongLogin = await TryWrongLogin();
    Console.WriteLine($"Login with wrong password rejected: {(wrongLogin ? "OK" : "unexpectedly accepted")}");

    if (loggedIn && await client.TreeConnectAsync(@"\\SAMPLE\Files"))
    {
        IReadOnlyList<string> files = await client.ListDirectoryAsync();
        Console.WriteLine("Files in share: " + string.Join(", ", files));

        string? content = await client.ReadFileAsync("welcome.txt");
        Console.WriteLine("Contents of welcome.txt:");
        Console.WriteLine("---");
        Console.WriteLine(content?.TrimEnd());
        Console.WriteLine("---");

        // Write path: create a file, write to it, read it back, verify, then delete it again.
        const string probe = "selftest-write.txt";
        const string payload = "written by the self-test";
        bool wrote = await client.WriteFileAsync(probe, payload);
        string? readBack = await client.ReadFileAsync(probe);
        bool verified = wrote && readBack == payload;
        Console.WriteLine($"Write → read-back roundtrip ({probe}): {(verified ? "OK" : "FAILED")}");

        bool deleted = await client.DeleteFileAsync(probe);
        Console.WriteLine($"Delete ({probe}): {(deleted ? "OK" : "FAILED")}");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Self-test error: {ex.Message}");
}
Console.WriteLine("=== Self-test end ===");
Console.WriteLine();

// --- Keep running -------------------------------------------------------------
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
Console.WriteLine($"Server running on {server.Endpoint}. Ctrl+C to stop.");
try { await Task.Delay(Timeout.Infinite, cts.Token); }
catch (OperationCanceledException) { }
await server.StopAsync();

async Task<bool> TryWrongLogin()
{
    using var c = new DemoClient();
    await c.ConnectAsync("127.0.0.1", Port);
    return !await c.LoginAsync(Domain, User, "wrong");
}
