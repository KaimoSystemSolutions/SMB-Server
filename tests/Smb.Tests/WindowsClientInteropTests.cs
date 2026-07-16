using System.Diagnostics;
using Xunit;
using Xunit.Abstractions;

namespace Smb.Tests;

/// <summary>
/// docs/WINDOWS_COMPATIBILITY_ROADMAP.md W0.1/W2.1 — the full <see cref="WindowsInteropBattery"/> against the
/// <b>minimal-configuration</b> in-process server (<see cref="WindowsSmbLab"/>), plus the lab-specific freeze
/// case that needs the gated backend only this lab has. The same battery also runs against the fully-featured
/// example server (<see cref="SampleServerInteropTests"/>) — a bug that only bites with the extra features on
/// fails there, not here.
/// </summary>
[Collection(WindowsSmbLabCollection.Name)]
public class WindowsClientInteropTests(WindowsSmbLab lab, ITestOutputHelper output)
    : WindowsInteropBattery(lab, output)
{
    /// <summary>
    /// The freeze case against the real client: a metadata op stuck in the backend must not stall an unrelated
    /// read on another file. Mirrors <see cref="WindowsFreezeReproTests"/> but drives Windows itself. Uses its
    /// own share so the gate cannot hold up any other test. Lives here rather than in the battery because it
    /// needs the lab's <see cref="GatedCreateFileStore"/> — the example server has no gated backend.
    /// </summary>
    [SkippableFact]
    public async Task SlowMetadataOp_DoesNotStallUnrelatedRead()
    {
        Require();
        string unc = WindowsSmbLab.Unc(WindowsSmbLab.SlowShare);

        try
        {
            // Warm the connection so the measurement below is not dominated by negotiate/auth.
            Assert.Equal("fast content", Timed("warm read", () => File.ReadAllText($@"{unc}\fast.txt")));

            // Kick off an op the backend holds open (a stuck CREATE), then time an unrelated read.
            Task stuck = Task.Run(() => { try { File.ReadAllText($@"{unc}\slow.txt"); } catch { /* expected */ } });
            await Task.Delay(200); // let the stuck CREATE reach the backend gate

            var sw = Stopwatch.StartNew();
            string content = Timed("read while a CREATE is stuck", () => File.ReadAllText($@"{unc}\fast.txt"));
            sw.Stop();

            Assert.Equal("fast content", content);
            Output.WriteLine($"unrelated read took {sw.ElapsedMilliseconds} ms while a CREATE was stuck");
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5),
                $"unrelated read stalled behind the stuck metadata op ({sw.ElapsedMilliseconds} ms) — the connection froze.");

            lab.Gate.Release();
            await stuck.WaitAsync(TimeSpan.FromSeconds(30));
        }
        finally
        {
            lab.Gate.Release();
        }
    }
}
