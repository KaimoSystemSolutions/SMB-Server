using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Host;
using Smb.Protocol.Enums;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// The loopback Windows-interop lab: one server, started once for the whole test class, serving several shares
/// on <c>127.0.0.1:445</c> to the real Windows SMB client.
/// <para>
/// <b>Why one shared server instead of one per test.</b> The redirector only routes to loopback addresses
/// actually <i>assigned</i> to the interface, i.e. 127.0.0.1 alone (the rest of 127.0.0.0/8 is bindable and
/// reachable from user-mode TCP, but a kernel connect to it fails with ERROR_NETWORK_UNREACHABLE), so every
/// test necessarily reuses one address and one port. Windows caches its connection to a server across that
/// reuse, and a server that restarts underneath the cache produces a transient ERROR_BAD_NET_NAME (67) on the
/// next attach. Starting once means one attach for the whole class instead of one per test.
/// </para>
/// <para>
/// <b>Prerequisite (one-time, host-level):</b> Windows' own SMB server occupies port 445 exclusively, so it
/// must be stopped — see <c>docs/interop/WINDOWS_LAB.md</c>:
/// <code>Stop-Service LanmanServer -Force   # admin shell</code>
/// When the lab cannot come up — not Windows, LanmanServer running, another SMB server present — it records
/// <see cref="SkipReason"/> instead of throwing, and every test reports as <b>Skipped</b>. A test that
/// silently does nothing while reporting green is worse than no test.
/// </para>
/// </summary>
/// <remarks>
/// The lab is a <b>collection</b> fixture, not a class fixture: xUnit runs test classes in parallel, and the
/// lab owns the single address:port the redirector will talk to. Two classes each holding their own lab would
/// race for 127.0.0.1:445 and one would fail to bind. Every class that drives the client joins
/// <see cref="WindowsSmbLabCollection"/>, which both shares the one server and serialises those classes.
/// </remarks>
[CollectionDefinition(Name)]
public sealed class WindowsSmbLabCollection : ICollectionFixture<WindowsSmbLab>
{
    public const string Name = "windows-smb-lab";
}

public sealed class WindowsSmbLab : IAsyncLifetime
{
    public const int SmbPort = 445;
    public const string Host = "127.0.0.1";
    public const string Domain = "DOM";
    public const string User = "alice";
    public const string Password = "pw";   // throwaway credential for the local loopback lab only

    public const string FilesShare = "Files";
    public const string ReadOnlyShare = "ReadOnlyFiles";
    public const string SlowShare = "SlowFiles";

    /// <summary>Non-null when the lab could not start; every test skips with this reason.</summary>
    public string? SkipReason { get; private set; }

    /// <summary>Backing directory of the writable <see cref="FilesShare"/>.</summary>
    public string FilesRoot { get; private set; } = string.Empty;

    /// <summary>Backing directory of the read-only <see cref="ReadOnlyShare"/>.</summary>
    public string ReadOnlyRoot { get; private set; } = string.Empty;

    /// <summary>Backing directory of <see cref="SlowShare"/>, whose CREATEs can be held by <see cref="Gate"/>.</summary>
    public string SlowRoot { get; private set; } = string.Empty;

    /// <summary>Holds any CREATE whose path contains "slow" until released — the freeze case's stuck backend.</summary>
    public GatedCreateFileStore Gate { get; private set; } = null!;

    private SmbServer? _server;
    private readonly ConcurrentQueue<string> _log = new();

    public static string Unc(string share) => $@"\\{Host}\{share}";

    /// <summary>Skips the calling test unless the lab is up. Only the environment may skip.</summary>
    public void Require() => Skip.If(SkipReason is not null, SkipReason);

    /// <summary>Server-side command trace, for attaching to a failure message.</summary>
    public string RecentLog() => string.Join(Environment.NewLine, _log.TakeLast(80));

    /// <summary>
    /// A fresh, empty directory under the writable share; returns its UNC and backing paths.
    /// <para>
    /// The name carries a per-run suffix, so no test ever reuses a UNC path a previous run used. The Windows
    /// client caches directory contents and failed lookups per path for several seconds; a test that seeds a
    /// file on the backend and then opens it through a path the client already has a (now stale, and from the
    /// previous run's deleted directory: negative) cache entry for reads back STATUS_OBJECT_NAME_NOT_FOUND.
    /// That is the client behaving as designed, not a server fault — an unseen path avoids the whole question.
    /// </para>
    /// </summary>
    public (string Unc, string Local) NewDir(string name)
    {
        string unique = $"{name}-{_runTag}";
        string local = Path.Combine(FilesRoot, unique);
        Directory.CreateDirectory(local);
        return ($@"{Unc(FilesShare)}\{unique}", local);
    }

    private readonly string _runTag = Guid.NewGuid().ToString("N")[..8];

    public async Task InitializeAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            SkipReason = "not Windows — the SMB client under test is a Windows kernel driver (mrxsmb.sys).";
            return;
        }

        if (BindError() is { } err)
        {
            SkipReason = $"port {SmbPort} not bindable ({err}) — Windows' own SMB server holds it exclusively. " +
                         "Run `Stop-Service LanmanServer -Force` in an admin shell, verify with " +
                         "`Get-NetTCPConnection -LocalPort 445 -State Listen`, then re-run. " +
                         "See docs/interop/WINDOWS_LAB.md.";
            return;
        }

        FilesRoot = NewTempDir();
        ReadOnlyRoot = NewTempDir();
        SlowRoot = NewTempDir();
        await File.WriteAllTextAsync(Path.Combine(ReadOnlyRoot, "readable.txt"), "read only content");
        await File.WriteAllTextAsync(Path.Combine(SlowRoot, "fast.txt"), "fast content");
        Gate = new GatedCreateFileStore(new LocalFileStore(SlowRoot, readOnly: false), gatedName: "slow");

        var backend = new InMemoryIdentityBackend().AddUser(Domain, User, Password);
        _server = SmbServerBuilder.Create()
            .WithLogger(m => { _log.Enqueue(m); while (_log.Count > 400) _log.TryDequeue(out _); })
            .WithEndpoint(IPAddress.Parse(Host), SmbPort)
            .UseAuthentication(new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = Domain }))
            .Configure(o => o.ConcurrentMetadataOps = true) // the freeze fix (roadmap W2.1/W6.3)
            // readOnly defaults to TRUE on LocalFileStore — a writable share must say so explicitly, or every
            // write case fails with STATUS_ACCESS_DENIED from the backend and tests nothing.
            .AddShare(new Share { Name = FilesShare, Type = ShareType.Disk, FileStore = new LocalFileStore(FilesRoot, readOnly: false) })
            .AddShare(new Share { Name = ReadOnlyShare, Type = ShareType.Disk, FileStore = new LocalFileStore(ReadOnlyRoot, readOnly: true) })
            .AddShare(new Share { Name = SlowShare, Type = ShareType.Disk, FileStore = Gate })
            .Build();
        await _server.StartAsync();

        Connect();
    }

    public async Task DisposeAsync()
    {
        Gate?.Release();
        if (_server is not null)
        {
            foreach (string share in new[] { FilesShare, ReadOnlyShare, SlowShare })
                RunNet(out _, "use", Unc(share), "/delete", "/y");
            await _server.DisposeAsync();
        }
        foreach (string dir in new[] { FilesRoot, ReadOnlyRoot, SlowRoot })
            if (!string.IsNullOrEmpty(dir))
                try { Directory.Delete(dir, recursive: true); } catch { /* best-effort */ }
    }

    /// <summary>
    /// Authenticates against the server with explicit NTLM credentials (deviceless <c>net use</c>). A failed
    /// login is a real interop bug, so it fails the lab rather than skipping — with one exception:
    /// ERROR_BAD_NET_NAME (67) is retried.
    /// <para>
    /// That 67 is the cached-connection transient described on the type: a lab in a <i>previous</i>
    /// <c>dotnet test</c> process served this same address, and the client can still be holding its connection
    /// to that now-dead server. It is uncommon (most runs attach on the first attempt, in ~200 ms) and it does
    /// clear, but not on a timescale worth asserting — one observed episode outlasted five one-second retries,
    /// and the next run attached immediately. So the window is generous rather than tuned; a run that pays it
    /// is rare enough not to matter, and the alternative is a spurious red. Only 67 is retried — every other
    /// failure is reported at once.
    /// </para>
    /// </summary>
    private void Connect()
    {
        string unc = Unc(FilesShare);
        var sw = Stopwatch.StartNew();
        for (int attempt = 1; ; attempt++)
        {
            RunNet(out _, "use", unc, "/delete", "/y");            // drop a stale mapping from an earlier run
            int exit = RunNet(out string log, "use", unc, Password, $"/user:{Domain}\\{User}");
            _log.Enqueue($"[lab] net use attempt {attempt} @ {sw.ElapsedMilliseconds}ms → exit {exit}: {log.Trim().ReplaceLineEndings(" ")}");
            if (exit == 0) return;

            // "System error 67 has occurred." / "Systemfehler 67 aufgetreten." — matched with the surrounding
            // spaces so this stays locale-independent without matching a stray 67 inside a path or byte count.
            bool staleCachedConnection = log.Contains(" 67 ");
            if (staleCachedConnection && attempt < 15)
            {
                Thread.Sleep(TimeSpan.FromSeconds(1));
                continue;
            }
            // The lab itself is broken. Throwing from InitializeAsync fails every test in the collection,
            // which is what we want: a login failure is a real interop result and must never be a silent skip.
            throw new InvalidOperationException(
                $"NTLM login of {Domain}\\{User} against {unc} failed (net use exit {exit}, attempt {attempt}): " +
                $"{log.Trim()}{Environment.NewLine}Server log:{Environment.NewLine}{RecentLog()}");
        }
    }

    private static SocketError? BindError()
    {
        try
        {
            var probe = new TcpListener(IPAddress.Parse(Host), SmbPort);
            probe.Start();
            probe.Stop();
            return null;
        }
        catch (SocketException ex)
        {
            return ex.SocketErrorCode;
        }
    }

    private static string NewTempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "smb-interop-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    internal static int RunNet(out string output, params string[] args)
    {
        var psi = new ProcessStartInfo("net")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string a in args) psi.ArgumentList.Add(a);
        using Process p = Process.Start(psi)!;
        output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(30_000);
        return p.ExitCode;
    }
}

/// <summary>
/// Decorator that holds a CREATE for one path name until released — models a slow backend/rights lookup
/// (ZFS latency, DB ACL check) without needing real latency. Everything else passes straight through.
/// </summary>
public sealed class GatedCreateFileStore(IFileStore inner, string gatedName) : IFileStore
{
    private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public void Release() => _gate.TrySetResult();

    public async ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(
        string path, FileAccessIntent access, CreateDispositionIntent disposition,
        bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
    {
        if (path.Contains(gatedName, StringComparison.OrdinalIgnoreCase))
            await _gate.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        return await inner.CreateAsync(path, access, disposition, directoryRequired, nonDirectoryRequired, cancellationToken)
            .ConfigureAwait(false);
    }

    public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        => inner.ReadAsync(handle, offset, buffer, cancellationToken);
    public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        => inner.WriteAsync(handle, offset, data, cancellationToken);
    public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
        => inner.QueryDirectoryAsync(handle, searchPattern, cancellationToken);
    public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default)
        => inner.SetEndOfFileAsync(handle, length, cancellationToken);
    public ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default)
        => inner.RenameAsync(handle, newPath, replaceIfExists, cancellationToken);
    public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default)
        => inner.SetDeleteOnCloseAsync(handle, delete, cancellationToken);
    public ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default)
        => inner.FlushAsync(handle, cancellationToken);
}
