using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace Smb.Tests;

/// <summary>
/// The full <see cref="WindowsInteropBattery"/> against the <b>shipped example server</b>
/// (<c>examples/Smb.Sample.Server</c>, launched as an external process by <see cref="SampleServerLab"/>),
/// plus the cases only this configuration has: negotiated compression, versioned shares and the DFS
/// namespace.
/// <para>
/// Every case here is an operation Explorer issues, running against the configuration a user actually gets
/// when they start the example and browse to <c>\\127.0.0.1\Files</c>. A case that passes in
/// <see cref="WindowsClientInteropTests"/> (minimal config) but fails here isolates a bug to the example's
/// configuration surface — the LZ77 wire-format regression was found exactly this way.
/// </para>
/// </summary>
[Collection(SampleServerLabCollection.Name)]
public class SampleServerInteropTests(SampleServerLab lab, ITestOutputHelper output)
    : WindowsInteropBattery(lab, output)
{
    /// <summary>
    /// Inbound compression: <c>robocopy /compress</c> makes the Windows client send compressed WRITEs
    /// (the sample negotiates LZ77), so this drives our <b>decoder</b> with streams the real Windows
    /// encoder produced — the mirror image of the listing case that drove our encoder. Highly
    /// compressible payload on purpose; random data would make the client skip compression.
    /// </summary>
    [SkippableFact]
    public void Robocopy_WithCompression_InboundWritesLandIntact()
    {
        var (unc, local) = Dir();
        string src = Path.Combine(Path.GetTempPath(), "smb-robocomp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(src);
        try
        {
            byte[] payload = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("compressible content line\r\n", 40_000)));
            File.WriteAllBytes(Path.Combine(src, "big.txt"), payload);

            int exit = Timed("robocopy /compress", () =>
                RunProcess("robocopy", src, $@"{unc}\dst", "/COMPRESS", "/NFL", "/NDL", "/NJH", "/NJS"));
            Assert.True(exit < 8, $"robocopy /compress failed with exit code {exit}.{Environment.NewLine}{Lab.RecentLog()}");

            Assert.Equal(payload, ReadBackend(Path.Combine(local, "dst", "big.txt")));
        }
        finally
        {
            try { Directory.Delete(src, recursive: true); } catch { /* best-effort */ }
        }
    }

    /// <summary>
    /// Reading a large, highly compressible file back through the client — the server compresses the
    /// READ responses (unlike the battery's random 4-MiB payload, which never shrinks and therefore
    /// travels uncompressed). Byte-exact content proves the compressed READ path end to end.
    /// </summary>
    [SkippableFact]
    public void CompressibleLargeFile_ReadBack_ByteExact()
    {
        var (unc, local) = Dir();
        byte[] payload = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("0123456789 abcdefghij ", 100_000)));
        File.WriteAllBytes(Path.Combine(local, "comp.txt"), payload);

        byte[] readBack = Timed("read compressible 2 MiB", () => File.ReadAllBytes($@"{unc}\comp.txt"));

        Assert.Equal(payload.Length, readBack.Length);
        Assert.Equal(payload, readBack);
    }

    /// <summary>Basic I/O on the versioned share (library-default snapshot store decorating the disk).</summary>
    [SkippableFact]
    public void VersionsShare_WriteReadDelete_Works()
    {
        Require();
        string unc = $@"{SampleServerLab.Unc(SampleServerLab.VersionsShare)}\vprobe-{Guid.NewGuid():N}.txt";

        Timed("write versioned", () => File.WriteAllText(unc, "v1"));
        Timed("overwrite versioned", () => File.WriteAllText(unc, "v2"));
        Assert.Equal("v2", Timed("read versioned", () => File.ReadAllText(unc)));
        Timed("delete versioned", () => File.Delete(unc));
    }

    /// <summary>Basic I/O through the example's <b>custom</b> IFileStore/ISnapshotStore decorator.</summary>
    [SkippableFact]
    public void CustomVersionsShare_WriteReadDelete_Works()
    {
        Require();
        string unc = $@"{SampleServerLab.Unc(SampleServerLab.CustomVersionsShare)}\cprobe-{Guid.NewGuid():N}.txt";

        Timed("write custom-versioned", () => File.WriteAllText(unc, "c1"));
        Assert.Equal("c1", Timed("read custom-versioned", () => File.ReadAllText(unc)));
        Timed("delete custom-versioned", () => File.Delete(unc));
    }

    /// <summary>
    /// Manual-repro capture harness, NOT a regular test: it only runs when
    /// <c>manual-repro-start.txt</c> exists in the repository root (otherwise it skips). While it
    /// runs, the example server is up on 127.0.0.1:445 and a human reproduces the failing Explorer
    /// flows; the harness waits for <c>manual-repro-stop.txt</c> (or 10 minutes), then writes the
    /// full server log to <c>manual-repro-server.log</c> for offline analysis. Exists because the
    /// reported Explorer failures (double-click "not found", shortcut freeze) have resisted every
    /// automated repro up to real Explorer windows — the next data can only come from the real
    /// manual session, measured.
    /// </summary>
    [SkippableFact]
    public void ManualReproCapture_WaitsForHumanRepro_ThenDumpsServerLog()
    {
        string repoRoot = LocateRepoRoot();
        string startMarker = Path.Combine(repoRoot, "manual-repro-start.txt");
        Skip.IfNot(File.Exists(startMarker), "manual capture not requested (no manual-repro-start.txt)");
        Require();

        string stopMarker = Path.Combine(repoRoot, "manual-repro-stop.txt");
        string logDump = Path.Combine(repoRoot, "manual-repro-server.log");
        File.Delete(stopMarker);

        // Dump continuously, not only at the end: the first capture attempt died mid-session (external
        // process kill) and took its never-written log with it. A crash now costs at most two seconds
        // of tail, and the heartbeat timestamps let the offline analysis see both that the server was
        // alive and when the capture stopped.
        var deadline = System.Diagnostics.Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromMinutes(10) && !File.Exists(stopMarker))
        {
            File.WriteAllText(logDump,
                $"capture heartbeat {DateTimeOffset.Now:O} (running {deadline.Elapsed.TotalSeconds:0}s)" +
                $"{Environment.NewLine}{lab.FullLog()}{Environment.NewLine}");
            Thread.Sleep(2000);
        }

        File.WriteAllText(logDump, $"capture finished {DateTimeOffset.Now:O}{Environment.NewLine}{lab.FullLog()}{Environment.NewLine}");
        Output.WriteLine($"captured {deadline.Elapsed.TotalSeconds:0}s of manual repro; log at {logDump}");
    }

    private static string LocateRepoRoot()
    {
        string? dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "Smb.Server.slnx")))
            dir = Path.GetDirectoryName(dir);
        return dir ?? throw new InvalidOperationException("repo root not found");
    }

    /// <summary>
    /// The DFS namespace: the example publishes <c>DfsRoot\Public → \SAMPLE\Files</c>. Browsing the
    /// root share itself must work like any disk share (Explorer opens it before any link is
    /// followed), and file I/O directly in the root must behave.
    /// </summary>
    [SkippableFact]
    public void DfsRootShare_BrowsesAsDiskShare()
    {
        Require();
        string unc = SampleServerLab.Unc(SampleServerLab.DfsRootShare);
        string probe = $"dfsprobe-{Guid.NewGuid():N}.txt";

        Timed("write in dfs root", () => File.WriteAllText($@"{unc}\{probe}", "dfs"));
        Assert.Contains(probe, Timed("enumerate dfs root", () => Directory.GetFiles(unc).Select(Path.GetFileName)));
        Assert.Equal("dfs", Timed("read in dfs root", () => File.ReadAllText($@"{unc}\{probe}")));
        Timed("delete in dfs root", () => File.Delete($@"{unc}\{probe}"));
    }
}
