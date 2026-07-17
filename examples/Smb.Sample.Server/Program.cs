using System.Net;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Host;
using Smb.Protocol.Enums;
using Smb.Protocol.Security;
using Smb.Sample.Server;
using Smb.Server.Authorization;
using Smb.Server.Dfs;
using Smb.Server.Diagnostics;
using Smb.Server.Durable;
using Smb.Server.Leases;
using Smb.Server.Multichannel;
using Smb.Server.Notification;
using Smb.Server.Oplocks;
using Smb.Server.Quota;
using Smb.Server.Sharing;

// =============================================================================
//  Example: SMB server that walks through (almost) EVERY configurable knob of
//  SmbServerBuilder / SmbServerOptions, each with a short comment on what it does.
//
//  Start:   dotnet run --project examples/Smb.Sample.Server
//  Starts the server, runs a TCP self-test (login → listing → file read/write)
//  and then keeps running so you can also connect externally.
//
//  Port 445 is typically occupied on Windows → example uses 4445.
//
//  Most settings below are set to their secure library DEFAULT on purpose and
//  are shown explicitly only so the full configuration surface is visible in one
//  place. In your own server you only set what you want to change — the fluent
//  builder gives you secure defaults out of the box.
// =============================================================================

const string Domain = "WORKGROUP";
const string User = "demo";
const string Password = "demo123";        // Demo credentials
const int Port = 445;
const string DemoUserSid = "S-1-5-21-100-200-300-1001";

// --- Folders backing the demo shares (created next to the binary) -------------
string shareDir = Path.Combine(AppContext.BaseDirectory, "shared");
string versionDir = Path.Combine(AppContext.BaseDirectory, "versioned");
string customDir = Path.Combine(AppContext.BaseDirectory, "custom_versioned");
string customVersionStore = Path.Combine(AppContext.BaseDirectory, "custom_versions_store");
string readOnlyDir = Path.Combine(AppContext.BaseDirectory, "readonly");
string dfsRootDir = Path.Combine(AppContext.BaseDirectory, "dfsroot");
string lockAuditFile = Path.Combine(AppContext.BaseDirectory, "locks", "lock_audit.log");
foreach (string dir in new[] { shareDir, versionDir, customDir, readOnlyDir, dfsRootDir })
    Directory.CreateDirectory(dir);

// --- Diagnostic log sink -----------------------------------------------------
// Every server message goes to the console AND to a file next to the binary, so a client-interop
// problem ("VS Code / Notepad cannot open the file", "folder does not exist on this computer") can be
// investigated after the fact: reproduce the failure, then read the log. Look for lines starting with
// [FAIL] — those are the requests the server DECLINED, i.e. exactly what the app tripped over.
//
// The write goes through a background consumer thread, never inline on the request path: the logger is
// called from every command handler, and doing synchronous, flushing disk I/O there would serialize the
// server's request threads behind the disk — the very latency this server is built to avoid (a slow log
// would look like the freezes the interop suite guards against). Producers only enqueue a string.
// Timestamped per run so a fresh start (including a test-suite launch of this same binary) never
// overwrites an earlier capture. A convenience copy at the stable name always points at the newest run.
string logPath = Path.Combine(AppContext.BaseDirectory, $"sample-server-{DateTime.Now:yyyyMMdd-HHmmss}.log");
var logQueue = new System.Collections.Concurrent.BlockingCollection<string>(new System.Collections.Concurrent.ConcurrentQueue<string>());
var logDrained = new ManualResetEventSlim(false);
var logThread = new Thread(() =>
{
    using var w = new StreamWriter(logPath, append: false);
    foreach (string line in logQueue.GetConsumingEnumerable())
    {
        Console.WriteLine(line);
        w.WriteLine(line);
        if (logQueue.Count == 0) w.Flush(); // flush once the burst is drained — the tail is what a repro needs
    }
    w.Flush();
    logDrained.Set();
}) { IsBackground = true, Name = "sample-server-log" };
logThread.Start();
void ServerLog(string msg) => logQueue.Add($"{DateTimeOffset.Now:HH:mm:ss.fff} [server] {msg}");

// --- User database (local; replaceable later via LDAP/AD) ---------------------
var identities = new InMemoryIdentityBackend()
    .AddUser(Domain, User, Password, userSid: DemoUserSid);

// --- Health/perf counters we keep a reference to, to print a snapshot later ---
var metrics = new SmbServerMetrics();

// --- Disk-quota provider (M11.1): seed a 1 GiB limit for the demo user --------
var quota = new InMemoryQuotaProvider();
quota.SetLimit("Files", Sid.FromString(DemoUserSid), limit: 1L * 1024 * 1024 * 1024);

// --- Stand-alone DFS namespace (Phase 7): one root + one link -----------------
var dfs = new StandaloneDfsNamespace(defaultTtlSeconds: 300)
    .AddRoot(@"\SAMPLE\DfsRoot", @"\SAMPLE\DfsRoot")
    .AddLink(@"\SAMPLE\DfsRoot\Public", @"\SAMPLE\Files");

// --- Build server -------------------------------------------------------------
await using SmbServer server = SmbServerBuilder.Create()

    // ── Endpoint & identity ────────────────────────────────────────────────
    .WithEndpoint(IPAddress.Loopback, Port)              // listen address:port (default 0.0.0.0:445)
    .WithServerName("SAMPLE")                            // NETNAME shown to clients
    .WithServerGuid(Guid.Parse("11111111-2222-3333-4444-555555555555")) // stable across restarts

    // ── Protocol & crypto policy ───────────────────────────────────────────
    .WithDialectRange(SmbDialect.Smb202, SmbDialect.Smb311) // accepted dialect range
    .RequireSigning(false)                              // demo is lean; PRODUCTION: true
    .RequireEncryption(false)                           // global encryption off (can be per-share)
    .RejectUnencryptedAccess()                          // enc-required session/tree rejects plaintext
    .RejectGuestAccess()                                // no guest fallback (secure default)
    // .AllowAnonymousAccess()                          // leave OFF unless a NULL session must connect
    .WithCipherPreference(                              // SMB3 encryption cipher order
        SmbCipherId.Aes128Gcm, SmbCipherId.Aes256Gcm, SmbCipherId.Aes128Ccm, SmbCipherId.Aes256Ccm)
    .WithSigningPreference(                             // SMB3 signing algorithm order
        SmbSigningAlgorithmId.AesGmac, SmbSigningAlgorithmId.AesCmac, SmbSigningAlgorithmId.HmacSha256)
    .WithMaxIoSizes(maxReadSize: 8 << 20, maxWriteSize: 8 << 20, maxTransactSize: 8 << 20)

    // ── Authentication (SPNEGO/GSS) ────────────────────────────────────────
    .UseAuthentication(new NtlmSpnegoNegotiator(identities, new NtlmServerOptions { NetbiosDomainName = Domain }))
    // .UseDevAuthentication()                          // TEST-ONLY: accepts anyone, disables signing

    // ── Authorization (share visibility + TREE_CONNECT access mask) ────────
    .UseShareAuthorization(
        authorizeConnect: ctx => ShareAccessResult.Grant(SmbAccessMask.FullAccess),
        isVisible: _ => true)

    // ── Shares ─────────────────────────────────────────────────────────────
    // Simple writable disk share with a description ("Remark").
    .AddDiskShare("Files", shareDir, remark: "Main demo share (read/write)")
    // Read-only disk share. Flip `encrypt`/`continuousAvailability` on for forced per-share SMB3
    // encryption and persistent (CA) handles respectively.
    .AddDiskShare("ReadOnly", readOnlyDir, readOnly: true, remark: "Read-only share",
        encrypt: false, continuousAvailability: false)
    // Versioned share ("Previous Versions") — lib default, in-memory snapshots.
    .AddVersionedShare("Versions", versionDir, remark: "Previous Versions (lib default)")
    // Versioned share with a CUSTOM persistent IFileStore/ISnapshotStore (see DemoExternalVersionStore).
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
    // DFS root share — TREE_CONNECT carries DFS flags so clients issue referrals (resolved via UseDfsNamespace).
    .AddShare(new Share
    {
        Name = "DfsRoot",
        Type = ShareType.Disk,
        Remark = "DFS namespace root",
        IsDfs = true,
        FileStore = new LocalFileStore(dfsRootDir, readOnly: false),
    })

    // ── Locking / caching / coordination seams ─────────────────────────────
    // Custom byte-range lock manager with a persistent audit trail (decorates the default).
    .UseLockManager(new DemoAuditingLockManager(lockAuditFile, log: msg => Console.WriteLine($"[locks] {msg}")))
    // The remaining seams are shown with their DEFAULT implementation; swap in your own to
    // delegate to a cluster/OS. Pass the Null* variants to disable a feature entirely.
    .UseOplockManager(new InMemoryOplockManager())                       // or NullOplockManager to disable
    .UseLeaseManager(new InMemoryLeaseManager())                         // or NullLeaseManager to disable
    .UseShareModeManager(new InMemoryShareModeManager())                 // sharing-violation coordination
    .UseDurableHandleStore(new InMemoryDurableHandleStore(), timeout: TimeSpan.FromSeconds(60))
    .UseDirectoryWatcher(new FileSystemDirectoryWatcher())               // or NullDirectoryWatcher for no CHANGE_NOTIFY

    // ── Scale-out (Phases 6 & 7) ───────────────────────────────────────────
    .EnableMultichannel(true)                                            // advertise SMB2_GLOBAL_CAP_MULTICHANNEL
    .UseNetworkInterfaceProvider(new SystemNetworkInterfaceProvider())   // NICs reported to clients
    .UseDfsNamespace(dfs)                                                // publish the DFS links above

    // ── Transport add-ons (Phase 10) ───────────────────────────────────────
    .UseCompression(minSize: 4096)                                      // SMB2 compression for large responses
    // TLS and QUIC change the transport and need a certificate + a TLS-capable client, so they are
    // left commented here (the loopback self-test below speaks plain TCP). To enable, load a PFX with a
    // private key and uncomment — TLS on a dedicated port, QUIC on UDP/443:
    //   var cert = X509CertificateLoader.LoadPkcs12FromFile("server.pfx", "password");
    //   .UseTls(cert, tls => { tls.RequireClientCertificate = false; })   // wrap TCP in TLS (e.g. port 8445)
    //   .UseQuic(cert, port: 443, quic => { quic.MaxInboundStreams = 256; })

    // ── Quota (Phase 11) ───────────────────────────────────────────────────
    .UseQuotaProvider(quota)                                            // per-owner disk quotas

    // ── Operational readiness (Phase 8) ────────────────────────────────────
    .UseAuditLogger(evt => Console.WriteLine($"[audit] {evt}"), SmbLogLevel.Information) // security events
    .UseMetrics(metrics)                                               // health/perf counters (read below)
    .WithConnectionLimits(max: 1024, perClient: 64)                    // DoS guardrails
    .WithIdleTimeouts(                                                 // tear down idle sessions/conns; drop slow auth
        session: TimeSpan.FromMinutes(15),
        connection: TimeSpan.FromMinutes(5),
        authentication: TimeSpan.FromSeconds(30))
    .WithTimeProvider(TimeProvider.System)                            // inject a fake clock in tests

    // ── WS-Discovery (Phase 11) — appear in Explorer's Network view ────────
    // Demo runs it conservatively on loopback (no multicast) so startup can't fail on a busy 3702.
    // PRODUCTION: keep the default Port (3702), JoinMulticast = true, and set XAddrs to your host/IP.
    .UseWsDiscovery(wsd =>
    {
        wsd.EndpointId = Guid.Parse("99999999-8888-7777-6666-555555555555"); // stable device UUID
        wsd.XAddrs = ["http://SAMPLE/"];        // advertised transport address(es)
        wsd.BindAddress = IPAddress.Loopback;   // PRODUCTION: IPAddress.Any
        wsd.JoinMulticast = false;              // PRODUCTION: true
        wsd.AnnouncePresence = false;           // PRODUCTION: true (Hello on start / Bye on stop)
    })

    // ── Fine-grained escape hatch for options without a dedicated method ────
    .Configure(o =>
    {
        o.ConcurrentMetadataOps = true;                       // metadata ops off the connection barrier — without
                                                              // this, one slow backend CREATE/QUERY freezes every
                                                              // other op on the connection (Explorer hangs)
        o.MaxCreditsPerResponse = 512;                        // credit grant cap per response
        o.MaxOutstandingRequests = 512;                       // async ops (blocking LOCK / CHANGE_NOTIFY) cap
        o.MaxConcurrentFileOpsPerConnection = 8;              // pipelined READ/WRITE parallelism (1 = sequential)
        o.MaxDurableHandleTimeout = TimeSpan.FromMinutes(16); // clamp for durable-v2 client requests
        o.ShutdownDrainTimeout = TimeSpan.FromSeconds(30);    // grace period on StopAsync
        o.TimeoutSweepInterval = TimeSpan.FromSeconds(30);    // how often the idle/auth sweeper runs
    })

    .WithLogger(ServerLog)
    .Build();

await server.StartAsync();
Console.WriteLine($"Share 'Files':          {shareDir}");
Console.WriteLine($"Share 'ReadOnly':       {readOnlyDir} (read-only)");
Console.WriteLine($"Share 'Versions':       {versionDir} (lib default, in-memory)");
Console.WriteLine($"Share 'CustomVersions': {customDir} (custom impl, persistent → {customVersionStore})");
Console.WriteLine($"Share 'DfsRoot':        {dfsRootDir} (DFS namespace: \\SAMPLE\\DfsRoot\\Public → \\SAMPLE\\Files)");
Console.WriteLine($"Lock audit:             {lockAuditFile} (custom ILockManager)");
Console.WriteLine($"Diagnostic log:         {logPath} (grep for [FAIL] to see declined requests)");
Console.WriteLine($"Login:                  {Domain}\\{User} / {Password}");
Console.WriteLine();

// --- Self-test: log in via TCP, list directory, read/write file ---------------
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

// --- Read a metrics snapshot (M8.5) -------------------------------------------
MetricsSnapshot snap = metrics.Snapshot();
Console.WriteLine(
    $"Metrics: connections={snap.ConnectionsAccepted}, auth ok/fail={snap.AuthenticationSuccesses}/{snap.AuthenticationFailures}, " +
    $"requests={snap.RequestCount}, bytes r/w={snap.BytesRead}/{snap.BytesWritten}");
Console.WriteLine("=== Self-test end ===");
Console.WriteLine();

// --- Keep running -------------------------------------------------------------
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
Console.WriteLine($"Server running on {server.Endpoint}. Ctrl+C to stop.");
try { await Task.Delay(Timeout.Infinite, cts.Token); }
catch (OperationCanceledException) { }
await server.StopAsync();
logQueue.CompleteAdding();
logDrained.Wait(TimeSpan.FromSeconds(5)); // let the background writer flush the tail before exit

async Task<bool> TryWrongLogin()
{
    using var c = new DemoClient();
    await c.ConnectAsync("127.0.0.1", Port);
    return !await c.LoginAsync(Domain, User, "wrong");
}
