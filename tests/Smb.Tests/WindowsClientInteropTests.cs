using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Xunit;
using Xunit.Abstractions;
using Skip = Xunit.Skip;

namespace Smb.Tests;

/// <summary>
/// docs/WINDOWS_COMPATIBILITY_ROADMAP.md W0.1/W2.1 — interop against the <b>real Windows SMB client</b>, without
/// a VM.
/// <para>
/// The Windows SMB client is a kernel driver (<c>mrxsmb.sys</c>) already present on this machine — it does not
/// need to be simulated, only pointed at our server. Once the server listens on <c>127.0.0.1:445</c>
/// (<see cref="WindowsSmbLab"/>), any UNC path from ordinary .NET file I/O travels the real MUP/RDBSS/mrxsmb
/// stack — the same one Explorer, robocopy and Office use. So this is genuine Windows interop running inside
/// <c>dotnet test</c>, and the operations below are the ones Explorer issues when you browse, open, copy,
/// rename and delete.
/// </para>
/// <para>
/// <b>Every case is time-boxed</b> (see <see cref="Timed{T}"/>). A freeze is the symptom under investigation, so
/// it must fail as a freeze — an un-boxed operation would hang <c>dotnet test</c> for the client's own timeout
/// (tens of seconds) or forever, and report as a hang rather than a diagnosis.
/// </para>
/// <para>
/// <b>Scope:</b> loopback covers client semantics, auth, and the file/metadata cases. It deliberately does not
/// cover real-network effects (latency/MTU/packet loss), other Windows versions, or reconnect-after-drop —
/// those are the only reasons to reach for a VM later (roadmap W4.3/W5).
/// </para>
/// </summary>
[Collection(WindowsSmbLabCollection.Name)]
public class WindowsClientInteropTests(WindowsSmbLab lab, ITestOutputHelper output)
{
    /// <summary>
    /// Generous on purpose: this asserts "did not freeze", not "was fast". The Windows client's own retry/
    /// timeout behaviour on a stuck operation runs to tens of seconds, so anything under that would be timing
    /// noise on a loaded machine rather than a freeze. Latency assertions belong in the freeze case, which
    /// compares against a deliberately stuck op.
    /// </summary>
    private static readonly TimeSpan OpTimeout = TimeSpan.FromSeconds(25);

    // ─── Read / write ─────────────────────────────────────────────────────

    [SkippableFact]
    public void Read_File_ReturnsServerContent()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "read.txt"), "hello from server");

        Assert.Equal("hello from server", Timed("read", () => File.ReadAllText($@"{unc}\read.txt")));
    }

    [SkippableFact]
    public void Write_NewFile_LandsOnBackend()
    {
        var (unc, local) = Dir();

        Timed("write", () => File.WriteAllText($@"{unc}\written.txt", "from windows client"));

        Assert.Equal("from windows client", ReadBackendText(Path.Combine(local, "written.txt")));
    }

    [SkippableFact]
    public void Write_OverExistingFile_Truncates()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "f.txt"), "the original, much longer content");

        Timed("overwrite", () => File.WriteAllText($@"{unc}\f.txt", "short"));

        // FILE_OVERWRITE_IF must truncate, not leave a tail of the old content behind.
        Assert.Equal("short", ReadBackendText(Path.Combine(local, "f.txt")));
    }

    [SkippableFact]
    public void Append_ToExistingFile_Concatenates()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "log.txt"), "first\n");

        Timed("append", () => File.AppendAllText($@"{unc}\log.txt", "second\n"));

        Assert.Equal("first\nsecond\n", ReadBackendText(Path.Combine(local, "log.txt")));
    }

    [SkippableFact]
    public void SetLength_TruncatesAndExtends()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "s.txt"), "0123456789");

        Timed("truncate", () =>
        {
            using FileStream fs = File.Open($@"{unc}\s.txt", FileMode.Open, FileAccess.ReadWrite);
            fs.SetLength(4);
        });
        Assert.Equal("0123", ReadBackendText(Path.Combine(local, "s.txt")));

        Timed("extend", () =>
        {
            using FileStream fs = File.Open($@"{unc}\s.txt", FileMode.Open, FileAccess.ReadWrite);
            fs.SetLength(8);
        });
        // Extending must zero-fill, not expose whatever was there before.
        Assert.Equal(new byte[] { 0, 0, 0, 0 }, ReadBackend(Path.Combine(local, "s.txt"))[4..]);
    }

    [SkippableFact]
    public void ReadWrite_AtOffset_SeeksCorrectly()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "o.txt"), "AAAAAAAAAA");

        Timed("write at offset", () =>
        {
            using FileStream fs = File.Open($@"{unc}\o.txt", FileMode.Open, FileAccess.ReadWrite);
            fs.Seek(4, SeekOrigin.Begin);
            fs.Write("BB"u8);
        });

        Assert.Equal("AAAABBAAAA", ReadBackendText(Path.Combine(local, "o.txt")));
    }

    /// <summary>
    /// A payload past a single SMB2 message: the client splits it into multiple credited READ/WRITEs
    /// (LARGE_MTU). A byte-exact round trip pins offsets/lengths across that split.
    /// </summary>
    [SkippableFact]
    public void LargeFile_RoundTrips_ByteExact()
    {
        var (unc, local) = Dir();
        byte[] payload = new byte[4 * 1024 * 1024];
        Random.Shared.NextBytes(payload);

        Timed("write 4 MiB", () => File.WriteAllBytes($@"{unc}\big.bin", payload));
        Assert.Equal(payload, ReadBackend(Path.Combine(local, "big.bin")));

        byte[] readBack = Timed("read 4 MiB", () => File.ReadAllBytes($@"{unc}\big.bin"));
        Assert.Equal(payload, readBack);
    }

    // ─── Namespace: rename, delete, directories ───────────────────────────

    [SkippableFact]
    public void Rename_File_MovesOnBackend()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "before.txt"), "x");

        Timed("rename", () => File.Move($@"{unc}\before.txt", $@"{unc}\after.txt"));

        AssertEventually(() => File.Exists(Path.Combine(local, "after.txt")),
            "rename never became visible on the backend");
        Assert.False(File.Exists(Path.Combine(local, "before.txt")));
    }

    [SkippableFact]
    public void Rename_IntoSubdirectory_Works()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "m.txt"), "x");
        Directory.CreateDirectory(Path.Combine(local, "sub"));

        Timed("move into subdir", () => File.Move($@"{unc}\m.txt", $@"{unc}\sub\m.txt"));

        Assert.True(File.Exists(Path.Combine(local, "sub", "m.txt")));
    }

    [SkippableFact]
    public void Delete_File_RemovesFromBackend()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "gone.txt"), "x");

        Timed("delete", () => File.Delete($@"{unc}\gone.txt"));

        AssertEventually(() => !File.Exists(Path.Combine(local, "gone.txt")),
            "delete never became visible on the backend");
    }

    [SkippableFact]
    public void CreateAndDelete_Directory_Works()
    {
        var (unc, local) = Dir();

        Timed("mkdir", () => Directory.CreateDirectory($@"{unc}\d"));
        Assert.True(Directory.Exists(Path.Combine(local, "d")));

        Timed("rmdir", () => Directory.Delete($@"{unc}\d"));
        AssertEventually(() => !Directory.Exists(Path.Combine(local, "d")),
            "rmdir never became visible on the backend");
    }

    [SkippableFact]
    public void NestedDirectories_CreateAndEnumerate()
    {
        var (unc, local) = Dir();

        Timed("mkdir -p", () => Directory.CreateDirectory($@"{unc}\a\b\c"));
        Timed("write nested", () => File.WriteAllText($@"{unc}\a\b\c\deep.txt", "deep"));

        Assert.Equal("deep", ReadBackendText(Path.Combine(local, "a", "b", "c", "deep.txt")));
        Assert.Contains("deep.txt", Timed("enumerate nested", () => Directory.GetFiles($@"{unc}\a\b\c").Select(Path.GetFileName)));
    }

    // ─── Enumeration (QUERY_DIRECTORY) ────────────────────────────────────

    [SkippableFact]
    public void Enumerate_Directory_ListsAllEntries()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "one.txt"), "1");
        File.WriteAllText(Path.Combine(local, "two.txt"), "2");
        Directory.CreateDirectory(Path.Combine(local, "adir"));

        var files = Timed("enumerate files", () => Directory.GetFiles(unc).Select(Path.GetFileName).ToList());
        var dirs = Timed("enumerate dirs", () => Directory.GetDirectories(unc).Select(Path.GetFileName).ToList());

        Assert.Contains("one.txt", files);
        Assert.Contains("two.txt", files);
        Assert.Contains("adir", dirs);
        Assert.DoesNotContain("adir", files); // a directory must not surface as a file
    }

    [SkippableFact]
    public void Enumerate_EmptyDirectory_ReturnsNothing()
    {
        var (unc, _) = Dir();

        // STATUS_NO_MORE_FILES on the first page, not an error and not a hang.
        Assert.Empty(Timed("enumerate empty", () => Directory.GetFileSystemEntries(unc)));
    }

    /// <summary>
    /// Enough entries that the listing cannot fit one QUERY_DIRECTORY response — exercises the paging cursor
    /// across continuation requests, which is where an off-by-one silently drops or repeats names.
    /// </summary>
    [SkippableFact]
    public void Enumerate_ManyEntries_PagesWithoutLoss()
    {
        var (unc, local) = Dir();
        var expected = new HashSet<string>();
        for (int i = 0; i < 500; i++)
        {
            string name = $"file-{i:D4}.txt";
            File.WriteAllText(Path.Combine(local, name), "x");
            expected.Add(name);
        }

        var actual = Timed("enumerate 500", () => Directory.GetFiles(unc).Select(Path.GetFileName).ToList());

        Assert.Equal(expected.Count, actual.Count);                 // no duplicates across page boundaries
        Assert.Equal(expected, actual.ToHashSet()!);                // and nothing dropped
    }

    [SkippableFact]
    public void Enumerate_WithWildcard_FiltersServerSide()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "keep.log"), "x");
        File.WriteAllText(Path.Combine(local, "skip.txt"), "x");

        var logs = Timed("enumerate *.log", () => Directory.GetFiles(unc, "*.log").Select(Path.GetFileName).ToList());

        Assert.Equal(["keep.log"], logs);
    }

    [SkippableFact]
    public void Enumerate_UnicodeAndSpaceNames_RoundTrip()
    {
        var (unc, local) = Dir();
        const string name = "Grüße 日本語 file.txt";
        File.WriteAllText(Path.Combine(local, name), "u");

        Assert.Contains(name, Timed("enumerate unicode", () => Directory.GetFiles(unc).Select(Path.GetFileName)));
        Assert.Equal("u", Timed("read unicode", () => File.ReadAllText($@"{unc}\{name}")));
    }

    // ─── Metadata (QUERY_INFO / SET_INFO) ─────────────────────────────────

    [SkippableFact]
    public void QueryFileInfo_ReportsSizeAndExistence()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "i.txt"), "12345");

        var info = Timed("stat", () => new FileInfo($@"{unc}\i.txt"));

        Assert.True(info.Exists);
        Assert.Equal(5, info.Length);
    }

    [SkippableFact]
    public void SetAndQuery_Timestamps_RoundTrip()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "t.txt"), "x");
        var stamp = new DateTime(2020, 3, 4, 5, 6, 7, DateTimeKind.Utc);

        Timed("set mtime", () => File.SetLastWriteTimeUtc($@"{unc}\t.txt", stamp));
        var readBack = Timed("get mtime", () => File.GetLastWriteTimeUtc($@"{unc}\t.txt"));

        Assert.Equal(stamp, readBack);
        Assert.Equal(stamp, File.GetLastWriteTimeUtc(Path.Combine(local, "t.txt")));
    }

    [SkippableFact]
    public void SetAndQuery_Attributes_RoundTrip()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "a.txt"), "x");

        Timed("set attrs", () => File.SetAttributes($@"{unc}\a.txt", FileAttributes.Hidden | FileAttributes.ReadOnly));
        var attrs = Timed("get attrs", () => File.GetAttributes($@"{unc}\a.txt"));

        Assert.True(attrs.HasFlag(FileAttributes.Hidden), $"Hidden missing from {attrs}");
        Assert.True(attrs.HasFlag(FileAttributes.ReadOnly), $"ReadOnly missing from {attrs}");

        // Clear again so the backing file can be cleaned up.
        Timed("clear attrs", () => File.SetAttributes($@"{unc}\a.txt", FileAttributes.Normal));
    }

    /// <summary>
    /// Explorer asks for free space to draw the drive/status bar on essentially every folder it opens, so a
    /// broken volume query stalls browsing even when file I/O is fine. This is <c>GetDiskFreeSpaceEx</c>, the
    /// same call Explorer makes.
    /// </summary>
    [SkippableFact]
    public void QueryVolume_FreeSpace_IsReported()
    {
        Require();
        string unc = WindowsSmbLab.Unc(WindowsSmbLab.FilesShare);

        bool ok = Timed("free space", () => GetDiskFreeSpaceEx(unc + @"\", out ulong avail, out ulong total, out _)
            ? Report(avail, total)
            : throw new Win32Exception_(Marshal.GetLastWin32Error(), "GetDiskFreeSpaceEx"));

        Assert.True(ok);

        bool Report(ulong avail, ulong total)
        {
            output.WriteLine($"volume: {avail / (1024 * 1024)} MiB free of {total / (1024 * 1024)} MiB");
            Assert.True(total > 0, "total volume size reported as 0 — Explorer draws an empty drive bar");
            return true;
        }
    }

    // ─── Error statuses ───────────────────────────────────────────────────

    /// <summary>
    /// The regression that made this whole suite worth building. Every declined status travels a
    /// <c>BuildError</c> path, and those responses used to go out <b>unsigned</b> on a signed session. A
    /// Windows client discards a response whose signature does not verify (§3.2.5.1.3) rather than failing the
    /// call, so the operation hung. Opening a missing file is the cheapest way to make the server decline, so
    /// it is the canary: it must come back promptly as FileNotFound, not as a signature error and not as a
    /// freeze. See <see cref="SignedErrorResponseTests"/> for the wire-level assertion.
    /// </summary>
    [SkippableFact]
    public void OpenMissingFile_FailsFastWithFileNotFound()
    {
        var (unc, _) = Dir();

        var ex = Assert.ThrowsAny<IOException>(() =>
            Timed("open missing", () => File.ReadAllText($@"{unc}\does-not-exist.txt")));

        Assert.IsType<FileNotFoundException>(ex);
    }

    [SkippableFact]
    public void OpenMissingDirectory_FailsFastWithDirectoryNotFound()
    {
        var (unc, _) = Dir();

        Assert.ThrowsAny<IOException>(() =>
            Timed("enumerate missing dir", () => Directory.GetFiles($@"{unc}\no-such-dir")));
    }

    [SkippableFact]
    public void WriteToReadOnlyShare_FailsFastWithAccessDenied()
    {
        Require();
        string unc = WindowsSmbLab.Unc(WindowsSmbLab.ReadOnlyShare);

        // The share is readable...
        Assert.Equal("read only content", Timed("read ro share", () => File.ReadAllText($@"{unc}\readable.txt")));

        // ...but a write must be declined, promptly and as an access error.
        Assert.ThrowsAny<UnauthorizedAccessException>(() =>
            Timed("write ro share", () => File.WriteAllText($@"{unc}\nope.txt", "x")));
    }

    [SkippableFact]
    public void DeleteMissingFile_FailsFast()
    {
        var (unc, _) = Dir();

        // File.Delete swallows "not found" by design; the point is that it returns rather than hanging.
        Timed("delete missing", () => File.Delete($@"{unc}\never-existed.txt"));
    }

    // ─── Sharing / concurrency ────────────────────────────────────────────

    [SkippableFact]
    public void ExclusiveOpen_SecondOpen_GetsSharingViolation()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "excl.txt"), "x");

        using FileStream first = Timed("open exclusive",
            () => File.Open($@"{unc}\excl.txt", FileMode.Open, FileAccess.ReadWrite, FileShare.None));

        Assert.ThrowsAny<IOException>(() =>
            Timed("second open", () => File.Open($@"{unc}\excl.txt", FileMode.Open, FileAccess.ReadWrite, FileShare.None)));
    }

    [SkippableFact]
    public void SharedOpen_ParallelReaders_AllSucceed()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "shared.txt"), "content");

        Timed("8 parallel readers", () =>
            Parallel.For(0, 8, _ => Assert.Equal("content", File.ReadAllText($@"{unc}\shared.txt"))));
    }

    [SkippableFact]
    public void ByteRangeLock_BlocksConflictingWrite()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "lock.txt"), "0123456789");

        using FileStream holder = File.Open($@"{unc}\lock.txt", FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
        Timed("lock range", () => holder.Lock(0, 4));
        try
        {
            using FileStream other = File.Open($@"{unc}\lock.txt", FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            Assert.ThrowsAny<IOException>(() => Timed("conflicting lock", () => other.Lock(0, 4)));
        }
        finally
        {
            Timed("unlock range", () => holder.Unlock(0, 4));
        }
    }

    [SkippableFact]
    public void Flush_OnOpenHandle_Completes()
    {
        var (unc, local) = Dir();

        Timed("write+flush", () =>
        {
            using FileStream fs = File.Create($@"{unc}\flush.txt");
            fs.Write("data"u8);
            fs.Flush(flushToDisk: true);
        });

        Assert.Equal("data", ReadBackendText(Path.Combine(local, "flush.txt")));
    }

    // ─── Explorer-shaped composite flows ──────────────────────────────────

    /// <summary>
    /// What a copy in Explorer actually is: open source, open destination, stream the bytes, then stamp the
    /// timestamps. Runs share-to-share within the server.
    /// </summary>
    [SkippableFact]
    public void CopyFile_WithinShare_PreservesContent()
    {
        var (unc, local) = Dir();
        byte[] payload = new byte[512 * 1024];
        Random.Shared.NextBytes(payload);
        File.WriteAllBytes(Path.Combine(local, "src.bin"), payload);

        Timed("copy", () => File.Copy($@"{unc}\src.bin", $@"{unc}\dst.bin"));

        Assert.Equal(payload, ReadBackend(Path.Combine(local, "dst.bin")));
    }

    /// <summary>
    /// Explorer registers a directory change notification for every folder window it has open. CHANGE_NOTIFY is
    /// long-lived and asynchronous (STATUS_PENDING now, an answer whenever something changes), so a server that
    /// mishandles it either never reports changes — a stale window — or wedges the connection it is pending on.
    /// <para>
    /// The teardown half is the half that bit: dropping the watch cost <b>65 seconds</b>, because the client
    /// cancels its parked CHANGE_NOTIFY with an <i>async</i> CANCEL and the server matched CANCELs by
    /// MessageId only (§3.3.5.16 requires AsyncId when SMB2_FLAGS_ASYNC_COMMAND is set). The notification was
    /// never completed, so the client waited out its own timeout — closing an Explorer window on the share
    /// froze for exactly that long. Both halves are asserted here; the timing assertion is the regression.
    /// </para>
    /// </summary>
    [SkippableFact]
    public void ChangeNotify_ReportsCreate_AndDropsWatchPromptly()
    {
        var (unc, local) = Dir();
        using var seen = new ManualResetEventSlim(false);
        string? observed = null;

        var watcher = new FileSystemWatcher(unc)
        {
            NotifyFilter = NotifyFilters.FileName,
            EnableRaisingEvents = true,
        };
        watcher.Created += (_, e) => { observed = e.Name; seen.Set(); };

        // Wait for the subscription to actually reach the server before changing anything. Enabling the
        // watcher only queues the CHANGE_NOTIFY; a change made before it arrives is not a missed notification,
        // it is a change that nobody was watching for yet — and the test would fail for the wrong reason.
        AwaitPendingChangeNotify();

        // Make the change on the backend, so the notification can only have come from the server.
        File.WriteAllText(Path.Combine(local, "appeared.txt"), "x");

        Assert.True(seen.Wait(OpTimeout),
            $"no CHANGE_NOTIFY for a file created in a watched directory within {OpTimeout.TotalSeconds:0}s — " +
            $"an Explorer window on this folder would never refresh.{Environment.NewLine}{lab.RecentLog()}");
        Assert.Equal("appeared.txt", observed);

        // Dropping the watch cancels the CHANGE_NOTIFY the client has re-armed and left parked on the server.
        // If that CANCEL goes unanswered the client blocks here for its own timeout (~65 s was the observed
        // cost), which is the Explorer freeze this suite exists to catch.
        var teardown = Stopwatch.StartNew();
        watcher.Dispose();
        teardown.Stop();
        output.WriteLine($"watcher teardown: {teardown.ElapsedMilliseconds} ms");
        Assert.True(teardown.Elapsed < TimeSpan.FromSeconds(5),
            $"dropping the directory watch took {teardown.ElapsedMilliseconds} ms — the client's parked " +
            $"CHANGE_NOTIFY was not cancelled, so it waited out its own timeout. Closing an Explorer window " +
            $"on this share freezes for that long.{Environment.NewLine}{lab.RecentLog()}");
    }

    /// <summary>Blocks until the server reports a CHANGE_NOTIFY parked as STATUS_PENDING.</summary>
    private void AwaitPendingChangeNotify()
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < OpTimeout)
        {
            if (lab.RecentLog().Contains("ChangeNotify mid=") && lab.RecentLog().Contains("→ Pending")) return;
            Thread.Sleep(50);
        }
        Assert.Fail($"the client's directory watch never reached the server as a pending CHANGE_NOTIFY " +
                    $"within {OpTimeout.TotalSeconds:0}s.{Environment.NewLine}{lab.RecentLog()}");
    }

    /// <summary>
    /// The freeze case against the real client: a metadata op stuck in the backend must not stall an unrelated
    /// read on another file. Mirrors <see cref="WindowsFreezeReproTests"/> but drives Windows itself. Uses its
    /// own share so the gate cannot hold up any other test.
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
            output.WriteLine($"unrelated read took {sw.ElapsedMilliseconds} ms while a CREATE was stuck");
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

    // ─── Harness ──────────────────────────────────────────────────────────

    private void Require() => lab.Require();

    /// <summary>
    /// Reads a backing file the way a bystander has to. The server keeps its own handle on an open file, and
    /// the client may hold the SMB open past the app's close while it has a lease — so at the moment a test
    /// checks the backend, the file is often still open read/write by the server. <c>File.ReadAllText</c> asks
    /// for deny-write sharing, which collides with exactly that and fails with a sharing violation on the
    /// <i>local</i> path. Being sharing-tolerant keeps these assertions about content rather than about when
    /// the client got round to sending CLOSE.
    /// </summary>
    private static byte[] ReadBackend(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var ms = new MemoryStream();
        fs.CopyTo(ms);
        return ms.ToArray();
    }

    private static string ReadBackendText(string path) => Encoding.UTF8.GetString(ReadBackend(path));

    /// <summary>
    /// Asserts a backend effect the client is entitled to delay. A delete over SMB is delete-on-close: the
    /// server removes the file when the handle closes, and the Windows client may hold that handle past the
    /// app's close while it has a lease. So the effect lands when the client sends CLOSE, not when
    /// <c>File.Delete</c> returns. Polling asserts the outcome without asserting a timing the protocol does
    /// not promise — and still fails, in bounded time, if the effect never lands at all.
    /// </summary>
    private static void AssertEventually(Func<bool> condition, string because)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(10))
        {
            if (condition()) return;
            Thread.Sleep(25);
        }
        Assert.Fail(because);
    }

    /// <summary>A private directory for the calling test, as a (UNC, backing) pair. Skips if the lab is down.</summary>
    private (string Unc, string Local) Dir([System.Runtime.CompilerServices.CallerMemberName] string caller = "")
    {
        Require();
        return lab.NewDir(caller);
    }

    /// <summary>
    /// Runs one client operation with a deadline. A freeze is the symptom under investigation, so exceeding the
    /// deadline is reported as exactly that rather than hanging the run. The operation's own exception is
    /// preserved (unwrapped), because "which status did the client surface" is what most cases assert.
    /// </summary>
    private T Timed<T>(string what, Func<T> op)
    {
        var sw = Stopwatch.StartNew();
        Task<T> task = Task.Run(op);

        // Task.WhenAny rather than task.Wait(timeout): Wait reports a faulted operation by throwing
        // AggregateException, which would hide the client's actual status behind a wrapper and defeat every
        // ThrowsAny<IOException> below. WhenAny never throws, so the unwrapping stays with GetResult.
        if (Task.WhenAny(task, Task.Delay(OpTimeout)).GetAwaiter().GetResult() != task)
        {
            Assert.Fail($"'{what}' did not complete within {OpTimeout.TotalSeconds:0}s — the Windows client " +
                        $"froze on this operation.{Environment.NewLine}Server log:{Environment.NewLine}{lab.RecentLog()}");
        }
        output.WriteLine($"{what}: {sw.ElapsedMilliseconds} ms");
        return task.GetAwaiter().GetResult();   // rethrows the client's real exception, unwrapped
    }

    private void Timed(string what, Action op) => Timed<object?>(what, () => { op(); return null; });

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpaceEx(
        string directoryName, out ulong freeBytesAvailable, out ulong totalBytes, out ulong totalFreeBytes);

    private sealed class Win32Exception_(int code, string what)
        : IOException($"{what} failed with Win32 error {code}");
}
