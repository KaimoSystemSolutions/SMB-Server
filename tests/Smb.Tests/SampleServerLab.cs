using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// The second Windows-interop lab: the shipped example server (<c>examples/Smb.Sample.Server</c>) launched as
/// an <b>external process</b> — the very binary a user points Explorer at — serving <c>127.0.0.1:445</c> to the
/// real Windows SMB client.
/// <para>
/// <b>Why a second lab.</b> <see cref="WindowsSmbLab"/> runs a minimal configuration; the example server turns
/// (almost) every knob on: compression, quota, multichannel, DFS, versioned shares, a custom lock manager,
/// connection limits, 8-MiB I/O sizes, <i>without</i> <c>ConcurrentMetadataOps</c> unless the example sets it.
/// Explorer bugs that only bite under that configuration are invisible to the minimal lab — this lab runs the
/// same <see cref="WindowsInteropBattery"/> against the full-featured configuration, and it tests the example
/// itself: if the example is misconfigured, that is a finding, not noise.
/// </para>
/// <para>
/// <b>Process, not in-process replica.</b> Replicating the example's builder calls in test code would drift the
/// moment someone edits <c>Program.cs</c>. Launching the built example exercises exactly what the user runs —
/// configuration, startup self-test and all. Server-side diagnostics still work: the example logs through
/// <c>WithLogger</c> to stdout, which this fixture captures as <see cref="RecentLog"/>.
/// </para>
/// <para>
/// Shares 127.0.0.1:445 with the other lab via <see cref="Port445Gate"/>; the collections run one after the
/// other. Skips (never silently passes) when not on Windows or when port 445 is held by LanmanServer — see
/// <c>docs/interop/WINDOWS_LAB.md</c>.
/// </para>
/// </summary>
[CollectionDefinition(Name)]
public sealed class SampleServerLabCollection : ICollectionFixture<SampleServerLab>
{
    public const string Name = "sample-server-lab";
}

public sealed class SampleServerLab : IAsyncLifetime, IWindowsInteropLab
{
    // Must match examples/Smb.Sample.Server/Program.cs.
    public const string Domain = "WORKGROUP";
    public const string User = "demo";
    public const string Password = "demo123";
    public const string FilesShare = "Files";
    public const string ReadOnlyShare = "ReadOnly";
    public const string VersionsShare = "Versions";
    public const string CustomVersionsShare = "CustomVersions";
    public const string DfsRootShare = "DfsRoot";

    /// <summary>Non-null when the lab could not start; every test skips with this reason.</summary>
    public string? SkipReason { get; private set; }

    /// <summary>Backing directory of the writable <see cref="FilesShare"/> (<c>shared</c> next to the exe).</summary>
    public string FilesRoot { get; private set; } = string.Empty;

    /// <summary>Backing directory of <see cref="ReadOnlyShare"/>.</summary>
    public string ReadOnlyRoot { get; private set; } = string.Empty;

    /// <summary>Backing directory of <see cref="VersionsShare"/>.</summary>
    public string VersionsRoot { get; private set; } = string.Empty;

    /// <summary>Backing directory of <see cref="CustomVersionsShare"/>.</summary>
    public string CustomVersionsRoot { get; private set; } = string.Empty;

    /// <summary>Backing directory of <see cref="DfsRootShare"/>.</summary>
    public string DfsRootRoot { get; private set; } = string.Empty;

    private Process? _proc;
    private bool _gateHeld;
    private readonly ConcurrentQueue<string> _log = new();
    private readonly string _runTag = Guid.NewGuid().ToString("N")[..8];
    private readonly List<string> _createdDirs = [];

    public static string Unc(string share) => $@"\\{WindowsInteropBattery.Host}\{share}";

    // ── IWindowsInteropLab ────────────────────────────────────────────────
    public string WritableShareUnc => Unc(FilesShare);
    public string ReadOnlyShareUnc => Unc(ReadOnlyShare);
    public string ReadOnlyProbeFile => "readable.txt";
    public string ReadOnlyProbeContent => "read only content";
    public IReadOnlyCollection<string> VisibleShares =>
        [FilesShare, ReadOnlyShare, VersionsShare, CustomVersionsShare, DfsRootShare];
    string IWindowsInteropLab.WritableShareRoot => FilesRoot;
    string IWindowsInteropLab.Domain => Domain;
    string IWindowsInteropLab.User => User;
    string IWindowsInteropLab.Password => Password;

    public void Require() => Skip.If(SkipReason is not null, SkipReason);

    public string RecentLog() => string.Join(Environment.NewLine, _log.TakeLast(80));

    /// <summary>The whole retained log window (for the manual-repro capture harness).</summary>
    public string FullLog() => string.Join(Environment.NewLine, _log);

    /// <summary>
    /// A fresh, empty directory under the writable share; same per-run-suffix contract as
    /// <see cref="WindowsSmbLab.NewDir"/> (defeats the client's per-path directory/negative caches).
    /// </summary>
    public (string Unc, string Local) NewDir(string name)
    {
        string unique = $"{name}-{_runTag}";
        string local = Path.Combine(FilesRoot, unique);
        Directory.CreateDirectory(local);
        lock (_createdDirs) _createdDirs.Add(local);
        return ($@"{Unc(FilesShare)}\{unique}", local);
    }

    public async Task InitializeAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            SkipReason = "not Windows — the SMB client under test is a Windows kernel driver (mrxsmb.sys).";
            return;
        }

        await Port445Gate.AcquireAsync();
        _gateHeld = true;
        try
        {
            await StartSampleAndConnectAsync();
        }
        catch
        {
            KillSample();
            Port445Gate.Release();
            _gateHeld = false;
            throw;
        }
    }

    private async Task StartSampleAndConnectAsync()
    {
        // A sample server orphaned by an aborted earlier run would hold 445 forever; it is ours, so it may go.
        foreach (Process stale in Process.GetProcessesByName("Smb.Sample.Server"))
        {
            try { stale.Kill(entireProcessTree: true); stale.WaitForExit(5_000); } catch { /* best-effort */ }
        }

        if (BindError() is { } err)
        {
            SkipReason = $"port 445 not bindable ({err}) — Windows' own SMB server holds it exclusively. " +
                         "Run `Stop-Service LanmanServer -Force` in an admin shell, verify with " +
                         "`Get-NetTCPConnection -LocalPort 445 -State Listen`, then re-run. " +
                         "See docs/interop/WINDOWS_LAB.md.";
            return;
        }

        string exe = LocateSampleExe();
        string exeDir = Path.GetDirectoryName(exe)!;
        FilesRoot = Path.Combine(exeDir, "shared");
        ReadOnlyRoot = Path.Combine(exeDir, "readonly");
        VersionsRoot = Path.Combine(exeDir, "versioned");
        CustomVersionsRoot = Path.Combine(exeDir, "custom_versioned");
        DfsRootRoot = Path.Combine(exeDir, "dfsroot");

        var psi = new ProcessStartInfo(exe)
        {
            WorkingDirectory = exeDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            // A .NET child writes redirected output as UTF-8; reading it with the console's OEM code
            // page (the Process default) mangles every non-ASCII character — including the "→" the
            // battery greps for in AwaitPendingChangeNotify.
            StandardOutputEncoding = System.Text.Encoding.UTF8,
            StandardErrorEncoding = System.Text.Encoding.UTF8,
        };
        _proc = Process.Start(psi)!;
        _proc.OutputDataReceived += (_, e) => { if (e.Data is not null) Log(e.Data); };
        _proc.ErrorDataReceived += (_, e) => { if (e.Data is not null) Log("[stderr] " + e.Data); };
        _proc.BeginOutputReadLine();
        _proc.BeginErrorReadLine();

        await AwaitReadyAsync();

        // The example creates the read-only directory but seeds no file into it; the battery needs one.
        // Seeding on the backend (plain local write) is exactly how an admin would provision the share.
        await File.WriteAllTextAsync(Path.Combine(ReadOnlyRoot, ReadOnlyProbeFile), ReadOnlyProbeContent);

        NetUse.ConnectWithRetry(Unc(FilesShare), Domain, User, Password, Log, RecentLog);
    }

    /// <summary>
    /// Waits for the example's "Server running on …" banner — printed only after StartAsync succeeded and the
    /// built-in self-test finished. A process that exits first failed to start (its output says why).
    /// </summary>
    private async Task AwaitReadyAsync()
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(90))
        {
            if (_proc!.HasExited)
                throw new InvalidOperationException(
                    $"the example server exited with code {_proc.ExitCode} before becoming ready. Output:" +
                    $"{Environment.NewLine}{RecentLog()}");
            if (_log.Any(l => l.Contains("Server running on"))) return;
            await Task.Delay(100);
        }
        throw new InvalidOperationException(
            $"the example server did not become ready within 90s. Output:{Environment.NewLine}{RecentLog()}");
    }

    public async Task DisposeAsync()
    {
        try
        {
            foreach (string share in VisibleShares)
                NetUse.Run(out _, "use", Unc(share), "/delete", "/y");
            KillSample();
            // Leave the example's own share content alone; only remove the directories this run created.
            lock (_createdDirs)
            {
                foreach (string dir in _createdDirs)
                    try { Directory.Delete(dir, recursive: true); } catch { /* best-effort */ }
            }
        }
        finally
        {
            if (_gateHeld) Port445Gate.Release();
        }
        await Task.CompletedTask;
    }

    private void KillSample()
    {
        if (_proc is null) return;
        try
        {
            if (!_proc.HasExited) { _proc.Kill(entireProcessTree: true); _proc.WaitForExit(10_000); }
        }
        catch { /* best-effort */ }
        finally { _proc.Dispose(); _proc = null; }
    }

    private void Log(string line)
    {
        _log.Enqueue(line);
        // Generous window: manual-repro captures need the WHOLE session — at 800 lines the traffic
        // of interest (one double-click among Explorer noise) had already rotated out twice.
        while (_log.Count > 5000) _log.TryDequeue(out _);
    }

    /// <summary>
    /// Finds the built example exe relative to the repository root (located by walking up to the .slnx). The
    /// test project declares a build-order-only ProjectReference on the example, so a normal build of the
    /// tests has always built it; a missing exe therefore means the configurations diverge, and the error
    /// message says which path was expected.
    /// </summary>
    private static string LocateSampleExe()
    {
        string? dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "Smb.Server.slnx")))
            dir = Path.GetDirectoryName(dir);
        if (dir is null)
            throw new InvalidOperationException(
                $"repository root (Smb.Server.slnx) not found above {AppContext.BaseDirectory}");

        // Same configuration as the running test bin ("Debug"/"Release" segment after "bin").
        string[] segments = AppContext.BaseDirectory.Split(Path.DirectorySeparatorChar);
        int binIdx = Array.FindLastIndex(segments, s => s.Equals("bin", StringComparison.OrdinalIgnoreCase));
        string config = binIdx >= 0 && binIdx + 1 < segments.Length ? segments[binIdx + 1] : "Debug";

        string exe = Path.Combine(dir, "examples", "Smb.Sample.Server", "bin", config, "net9.0", "Smb.Sample.Server.exe");
        if (!File.Exists(exe))
            throw new InvalidOperationException(
                $"example server binary not found at {exe} — build examples/Smb.Sample.Server first " +
                "(building tests/Smb.Tests does this automatically via its build-order ProjectReference).");
        return exe;
    }

    private static SocketError? BindError()
    {
        try
        {
            var probe = new TcpListener(IPAddress.Parse(WindowsInteropBattery.Host), 445);
            probe.Start();
            probe.Stop();
            return null;
        }
        catch (SocketException ex)
        {
            return ex.SocketErrorCode;
        }
    }
}
