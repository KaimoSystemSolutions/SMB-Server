using System.Diagnostics;
using Xunit;
using Xunit.Abstractions;
using Skip = Xunit.Skip;

namespace Smb.Tests;

/// <summary>
/// Catches the environmental failure behind "the Win11 Notepad opens the file but the window body reports it
/// failed, while Notepad++ / copy work" on a <b>loopback</b> share (<c>\\127.0.0.1</c> / <c>\\localhost</c>).
/// <para>
/// The Win11 Notepad is a packaged app and runs in an <b>AppContainer</b>. Windows blocks AppContainer
/// processes from reaching the loopback address (127.0.0.0/8, ::1) unless the app is explicitly exempted —
/// a network-isolation security boundary, enforced on the client <i>before</i> any SMB packet is sent. So a
/// double-click resolves through Explorer (full trust, succeeds — the server logs only Success), but
/// Notepad's own re-open inside the container never reaches the server and the editor reports failure. This
/// is NOT a server defect: the server serves the full-trust probes correctly. Classic Win32 apps
/// (Notepad++, <c>copy</c>, the VS Code core) are not AppContainers and are unaffected.
/// </para>
/// <para>
/// This is why every in-process repro stays green: the test host is full trust and uses <c>Windows.Storage</c>
/// without the AppContainer restriction (<c>WindowsStorageApi_OpenTextFileInShareRoot_ReadsContent</c> passes),
/// and the one GUI test that would hit it (<c>RealNotepad_DoubleClickOnLocalhostFile_OpensIt</c>) skips
/// whenever a Notepad is already running — which, on a dev box, is always.
/// </para>
/// <para>
/// The fix is client-side and per package family (developer/loopback-testing setting; not needed on a real
/// network address, only on loopback):
/// <code>CheckNetIsolation LoopbackExempt -a -n=Microsoft.WindowsNotepad_8wekyb3d8bbwe</code>
/// The alternative that needs no exemption is to serve on a non-loopback address (bind 0.0.0.0 / the LAN IP)
/// and connect via the host name or LAN IP instead of localhost — the loopback block only covers loopback.
/// </para>
/// </summary>
public class PackagedAppLoopbackTests(ITestOutputHelper output)
{
    private const string NotepadFamily = "Microsoft.WindowsNotepad_8wekyb3d8bbwe";

    /// <summary>
    /// Fails with the exact remedy when the Win11 Notepad's AppContainer is not loopback-exempt AND that
    /// Notepad is actually present — i.e. exactly the configuration in which loopback double-click "opens but
    /// fails". A machine without the packaged Notepad, or one where the exemption is already granted, is not
    /// in the failing state, so the test skips rather than nagging.
    /// </summary>
    [SkippableFact]
    public void Win11Notepad_IsLoopbackExempt_ElseLoopbackOpensWillFail()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "Windows-only (AppContainer loopback isolation).");
        Skip.IfNot(IsPackagePresent(NotepadFamily),
            "the packaged Win11 Notepad is not installed — the AppContainer loopback block does not apply.");

        string exemptions = RunCheckNetIsolation();
        output.WriteLine("CheckNetIsolation LoopbackExempt -s:\n" + exemptions);

        bool exempt = exemptions.Contains("WindowsNotepad", StringComparison.OrdinalIgnoreCase);
        Assert.True(exempt,
            "The Win11 Notepad (AppContainer) has NO loopback exemption, so it cannot open files on " +
            @"\\127.0.0.1 / \\localhost — Windows blocks AppContainer loopback access before any SMB packet " +
            "is sent. The file 'opens' (Explorer resolves it) but the editor body reports failure, while " +
            "Notepad++/copy work. This is a client-side Windows restriction, not an SMB-server fault.\n" +
            "Fix (developer/loopback-testing): run in an admin shell:\n" +
            $"    CheckNetIsolation LoopbackExempt -a -n={NotepadFamily}\n" +
            "Or serve on a non-loopback address (bind 0.0.0.0 / LAN IP) and connect via host name / LAN IP.");
    }

    private static bool IsPackagePresent(string familyName)
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -Command \"[bool](Get-AppxPackage | Where-Object PackageFamilyName -eq '{familyName}')\"")
            { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using Process p = Process.Start(psi)!;
            string outp = p.StandardOutput.ReadToEnd();
            p.WaitForExit(15_000);
            return outp.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static string RunCheckNetIsolation()
    {
        try
        {
            var psi = new ProcessStartInfo("CheckNetIsolation.exe", "LoopbackExempt -s")
            { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            using Process p = Process.Start(psi)!;
            string outp = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(15_000);
            return outp;
        }
        catch (Exception ex) { return $"(could not run CheckNetIsolation: {ex.Message})"; }
    }
}
