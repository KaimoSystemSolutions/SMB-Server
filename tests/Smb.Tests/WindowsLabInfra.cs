using System.Diagnostics;

namespace Smb.Tests;

/// <summary>
/// Serialises the two Windows-interop labs (<see cref="WindowsSmbLab"/>, <see cref="SampleServerLab"/>) onto
/// the one address the redirector can reach: <c>127.0.0.1:445</c>. xUnit runs test collections in parallel,
/// and each lab is a collection fixture that owns that port for its collection's lifetime — without a gate the
/// second lab's bind would fail and all its tests would spuriously skip. A lab acquires the gate before its
/// bind probe and releases it after its server is gone.
/// </summary>
internal static class Port445Gate
{
    /// <summary>
    /// Generous but bounded: the other lab's whole collection has to finish first, and every one of its cases
    /// is itself time-boxed. A wait past this means that lab hung, and an unbounded wait here would turn that
    /// hang into a second one.
    /// </summary>
    private static readonly TimeSpan MaxWait = TimeSpan.FromMinutes(10);

    private static readonly SemaphoreSlim Semaphore = new(1, 1);

    public static async Task AcquireAsync()
    {
        if (!await Semaphore.WaitAsync(MaxWait).ConfigureAwait(false))
            throw new InvalidOperationException(
                $"port-445 gate not acquired within {MaxWait.TotalMinutes:0} minutes — the other Windows lab " +
                "never released it, i.e. its collection hung.");
    }

    public static void Release() => Semaphore.Release();
}

/// <summary>Shared <c>net</c> helpers for the Windows-interop labs.</summary>
internal static class NetUse
{
    internal static int Run(out string output, params string[] args)
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

    /// <summary>
    /// Authenticates against a lab server with explicit NTLM credentials (deviceless <c>net use</c>). A failed
    /// login is a real interop bug, so it throws (failing every test of the calling lab's collection) rather
    /// than skipping — with one exception: ERROR_BAD_NET_NAME (67) is retried.
    /// <para>
    /// That 67 is a cached-connection transient: a lab (possibly in a <i>previous</i> <c>dotnet test</c>
    /// process, possibly the other lab of this run) served this same address, and the client can still be
    /// holding its connection to that now-dead server. It is uncommon (most runs attach on the first attempt,
    /// in ~200 ms) and it does clear, but not on a timescale worth asserting — one observed episode outlasted
    /// five one-second retries, and the next run attached immediately. So the window is generous rather than
    /// tuned; a run that pays it is rare enough not to matter, and the alternative is a spurious red.
    /// </para>
    /// <para>
    /// 1326 (logon failure) gets a <i>short</i> retry for the same reason: with two labs alternating on one
    /// address, the client can answer the first SessionSetup after a server swap from its stale session state
    /// for the previous server (observed 2026-07-16: a 1326 immediately after the sample lab, with the new
    /// server's log showing no SessionSetup at all — the error never came from this server). It clears as
    /// soon as the client notices the old connection is dead. The window is deliberately small: a real
    /// credential regression must still fail the lab, just not on the first flaky attempt.
    /// </para>
    /// </summary>
    internal static void ConnectWithRetry(string unc, string domain, string user, string password,
        Action<string> log, Func<string> serverLog)
    {
        string host = unc.Split('\\', StringSplitOptions.RemoveEmptyEntries)[0];
        var sw = Stopwatch.StartNew();
        for (int attempt = 1; ; attempt++)
        {
            Run(out _, "use", unc, "/delete", "/y");            // drop a stale mapping from an earlier run
            Run(out _, "use", $@"\\{host}", "/delete", "/y");   // and any deviceless host-level connection
            int exit = Run(out string output, "use", unc, password, $"/user:{domain}\\{user}");
            log($"[lab] net use attempt {attempt} @ {sw.ElapsedMilliseconds}ms → exit {exit}: {output.Trim().ReplaceLineEndings(" ")}");
            if (exit == 0) return;

            // "System error 67 has occurred." / "Systemfehler 67 aufgetreten." — matched with the surrounding
            // spaces so this stays locale-independent without matching a stray 67 inside a path or byte count.
            bool staleCachedConnection = output.Contains(" 67 ");
            bool staleSessionAfterSwap = output.Contains(" 1326 ");
            if ((staleCachedConnection && attempt < 15) || (staleSessionAfterSwap && attempt < 4))
            {
                Thread.Sleep(TimeSpan.FromSeconds(1));
                continue;
            }
            throw new InvalidOperationException(
                $"NTLM login of {domain}\\{user} against {unc} failed (net use exit {exit}, attempt {attempt}): " +
                $"{output.Trim()}{Environment.NewLine}Server log:{Environment.NewLine}{serverLog()}");
        }
    }
}
