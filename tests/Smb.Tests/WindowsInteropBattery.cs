using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using Xunit;
using Xunit.Abstractions;
using Skip = Xunit.Skip;

namespace Smb.Tests;

/// <summary>
/// The lab a <see cref="WindowsInteropBattery"/> runs against: some SMB server reachable by the real Windows
/// client on <c>127.0.0.1:445</c>. Two implementations exist — <see cref="WindowsSmbLab"/> (in-process server,
/// minimal configuration) and <see cref="SampleServerLab"/> (the shipped example server as an external process,
/// every feature turned on). The battery itself is configuration-agnostic; whatever breaks only under one
/// configuration shows up as that lab's run failing.
/// </summary>
public interface IWindowsInteropLab
{
    /// <summary>Skips the calling test unless the lab is up. Only the environment may skip.</summary>
    void Require();

    /// <summary>A fresh, empty directory under the writable share, as (UNC, backing local path).</summary>
    (string Unc, string Local) NewDir(string name);

    /// <summary>Server-side log tail, for attaching to a failure message.</summary>
    string RecentLog();

    /// <summary>UNC of the writable share (for share-level operations like volume queries).</summary>
    string WritableShareUnc { get; }

    /// <summary>UNC of a read-only share.</summary>
    string ReadOnlyShareUnc { get; }

    /// <summary>Name of a file pre-seeded on the read-only share.</summary>
    string ReadOnlyProbeFile { get; }

    /// <summary>Content of <see cref="ReadOnlyProbeFile"/>.</summary>
    string ReadOnlyProbeContent { get; }

    /// <summary>Share names <c>net view \\host</c> must list.</summary>
    IReadOnlyCollection<string> VisibleShares { get; }

    /// <summary>Local backing directory of the writable share's ROOT (for root-level flows).</summary>
    string WritableShareRoot { get; }

    /// <summary>NTLM domain of the lab account (for connecting under a host alias).</summary>
    string Domain { get; }

    /// <summary>NTLM user of the lab account.</summary>
    string User { get; }

    /// <summary>NTLM password of the lab account.</summary>
    string Password { get; }
}

/// <summary>
/// docs/WINDOWS_COMPATIBILITY_ROADMAP.md W0.1/W2.1 — the battery of operations the <b>real Windows SMB
/// client</b> issues when Explorer browses, opens, copies, renames and deletes, runnable against any
/// <see cref="IWindowsInteropLab"/>.
/// <para>
/// The Windows SMB client is a kernel driver (<c>mrxsmb.sys</c>) already present on this machine — it does not
/// need to be simulated, only pointed at our server. Once a server listens on <c>127.0.0.1:445</c>, any UNC
/// path from ordinary .NET file I/O travels the real MUP/RDBSS/mrxsmb stack — the same one Explorer, robocopy
/// and Office use. So this is genuine Windows interop running inside <c>dotnet test</c>.
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
public abstract class WindowsInteropBattery(IWindowsInteropLab lab, ITestOutputHelper output)
{
    public const string Host = "127.0.0.1";

    protected IWindowsInteropLab Lab => lab;
    protected ITestOutputHelper Output => output;

    /// <summary>
    /// Generous on purpose: this asserts "did not freeze", not "was fast". The Windows client's own retry/
    /// timeout behaviour on a stuck operation runs to tens of seconds, so anything under that would be timing
    /// noise on a loaded machine rather than a freeze. Latency assertions belong in the freeze case, which
    /// compares against a deliberately stuck op.
    /// </summary>
    protected static readonly TimeSpan OpTimeout = TimeSpan.FromSeconds(25);

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

    /// <summary>
    /// Overwriting a file with shorter content via a truncating open must leave no tail of the old content.
    /// This is what an application does when it saves a file that got smaller, and what
    /// <c>FileMode.Truncate</c> maps to.
    /// <para>
    /// The redirector implements a truncating open not with FILE_OVERWRITE but with FILE_OPEN + SET_INFO
    /// FileAllocationInformation(newSize) + WRITE. The server treated that allocation set as a no-op, so the
    /// file kept its old length and the shorter write only replaced a prefix — "BB" over "the original,
    /// much longer content" left the tail "…longer content" behind on disk. The distinct backend check (not
    /// a read back through the client, which would serve its own cache) is what makes that tail visible.
    /// </para>
    /// </summary>
    [SkippableFact]
    public void TruncatingOpen_WithShorterContent_LeavesNoOldTail()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "t.txt"), "the original, much longer content");

        Timed("truncating open + shorter write", () =>
        {
            using FileStream fs = File.Open($@"{unc}\t.txt", FileMode.Truncate, FileAccess.Write);
            fs.Write("BB"u8);
        });

        Assert.Equal("BB", ReadBackendText(Path.Combine(local, "t.txt")));
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

    /// <summary>
    /// Explorer's new-folder flow: after CREATE it looks the folder up by its <b>exact name</b>
    /// (QUERY_DIRECTORY with a specific pattern, no wildcard) to select it and open the inline-rename
    /// box. The server used to synthesize "." into every listing regardless of the pattern, so that
    /// lookup returned "." as the first (and with SL_RETURN_SINGLE_ENTRY: only) entry — Explorer then
    /// displayed the new folder as "." and the rename box never opened. <c>Directory.GetDirectories</c>
    /// with a literal name issues exactly that FindFirstFile shape through the real redirector.
    /// </summary>
    [SkippableFact]
    public void Enumerate_ExactName_ReturnsTheRealEntry_NotDot()
    {
        var (unc, local) = Dir();
        Directory.CreateDirectory(Path.Combine(local, "Neuer Ordner"));

        var hits = Timed("find exact name", () => Directory.GetDirectories(unc, "Neuer Ordner").Select(Path.GetFileName).ToList());
        Assert.Equal(["Neuer Ordner"], hits);

        // The dual: an exact-name lookup for a name that does not exist must come back empty
        // (STATUS_NO_SUCH_FILE), which the unconditional "." synthesis used to mask.
        Assert.Empty(Timed("find missing name", () => Directory.GetFileSystemEntries(unc, "does-not-exist")));
    }

    /// <summary>The rest of the Explorer new-folder flow: create under the provisional name, then rename.</summary>
    [SkippableFact]
    public void NewFolder_CreateThenRename_Works()
    {
        var (unc, local) = Dir();

        Timed("mkdir provisional", () => Directory.CreateDirectory($@"{unc}\Neuer Ordner"));
        Timed("rename to final", () => Directory.Move($@"{unc}\Neuer Ordner", $@"{unc}\Projekte"));

        Assert.True(Directory.Exists(Path.Combine(local, "Projekte")));
        Assert.False(Directory.Exists(Path.Combine(local, "Neuer Ordner")));
    }

    // ─── Enumeration (QUERY_DIRECTORY) ────────────────────────────────────

    /// <summary>
    /// Browsing the <i>server</i> rather than a share: <c>net view \\host</c> is what Explorer does when you
    /// type <c>\\host</c>, and it is share enumeration over DCERPC — TREE_CONNECT IPC$, CREATE \PIPE\srvsvc,
    /// bind, NetrShareEnum. It is the one client flow that never touches a file store, so nothing else in this
    /// class covers it, and a server that serves files perfectly can still be unbrowsable.
    /// <para>
    /// The failure this pins had the client giving up mid-handshake, so it surfaced as RPC_S_CALL_FAILED
    /// ("the remote procedure call failed") <i>after</i> a successful login — which reads like an
    /// authorization problem and is not one. Asserting on the listed shares rather than the exit code alone
    /// keeps a client that connects but enumerates nothing from passing.
    /// </para>
    /// </summary>
    [SkippableFact]
    public void Enumerate_Server_ListsShares()
    {
        Require();

        var (exit, listing) = Timed("net view", () =>
        {
            int code = WindowsSmbLab.RunNet(out string o, "view", $@"\\{Host}");
            return (code, o);
        });
        output.WriteLine(listing);

        Assert.Equal(0, exit);
        foreach (string share in lab.VisibleShares)
            Assert.Contains(share, listing);
    }

    /// <summary>
    /// Two overlapping opens of the same directory — what Explorer does the moment you open a share, and
    /// what froze it.
    /// <para>
    /// The client asks for a BATCH oplock on every directory open. Granting it made the second open break
    /// the first, and a break away from BATCH parks the CREATE until the holder acknowledges (W1.1) — which
    /// the client never does for a directory, because it never believed it held that oplock. So the second
    /// open hung for the full <c>OplockBreakTimeout</c>. <see cref="Timed{T}"/> reports that as the freeze it
    /// is rather than waiting it out; the case is only meaningful against the real client, since the freeze
    /// was entirely about what the client does <i>not</i> send.
    /// </para>
    /// </summary>
    [SkippableFact]
    public void OpenDirectory_TwiceOverlapping_DoesNotFreeze()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "a.txt"), "x");

        var entries = Timed("open directory twice, then enumerate", () =>
        {
            using SafeFileHandle first = OpenDirectoryHandle(unc);
            Assert.False(first.IsInvalid, $"first directory open failed: Win32 {Marshal.GetLastWin32Error()}");

            using SafeFileHandle second = OpenDirectoryHandle(unc);
            Assert.False(second.IsInvalid, $"second directory open failed: Win32 {Marshal.GetLastWin32Error()}");

            return Directory.GetFileSystemEntries(unc);
        });

        Assert.Single(entries);
    }

    /// <summary>
    /// The shortcut (.lnk) creation pattern that froze Explorer: write a small file, then reopen it
    /// immediately (Explorer re-opens a fresh .lnk several times — icon extraction, preview, Defender).
    /// The redirector holds a <b>batch</b> oplock from the write and keeps the handle alive after the
    /// app-level close (that is what "batch" means), so the reopen breaks Batch — and the redirector's
    /// answer to that break on a deferred-close handle is a CLOSE, <b>not</b> an OPLOCK_BREAK ack.
    /// §3.3.5.9.8 requires the server to treat that close as the end of the wait; before it did, every
    /// such reopen parked for the full <c>OplockBreakTimeout</c> (35 s), felt as a per-file Explorer freeze.
    /// </summary>
    [SkippableFact]
    public void CreateShortcut_WriteThenImmediateReopen_DoesNotFreeze()
    {
        var (unc, local) = Dir();
        byte[] payload = Encoding.ASCII.GetBytes("L\0\0\0fake-lnk-payload");

        byte[] readBack = Timed("write .lnk then reopen", () =>
        {
            File.WriteAllBytes($@"{unc}\new.lnk", payload);   // redirector takes a batch oplock + deferred close
            return File.ReadAllBytes($@"{unc}\new.lnk");      // reopen breaks Batch → client CLOSEs, never acks
        });

        Assert.Equal(payload, readBack);
        Assert.Equal(payload, File.ReadAllBytes(Path.Combine(local, "new.lnk")));
    }

    // ─── Host alias (\\localhost) + Explorer file flows ───────────────────
    //
    // Reported 2026-07-16 from a manual Explorer session: double-clicking a text file produced the
    // default editor's "Die Datei \\localhost\Files\notes.txt kann nicht gefunden werden", and creating
    // a shortcut froze Explorer before falling back. Two things the battery had never modelled: the
    // host ALIAS (`\\localhost` is a different server to the redirector than `\\127.0.0.1` — separate
    // connection, session, and caches, with an IPv6 ::1 connect attempt first), and the REAL shell
    // COM path for .lnk creation (IShellLink::Save, not File.WriteAllBytes).

    /// <summary>
    /// The exact failing user flow: browse and open a file via <c>\\localhost\…</c>. The redirector
    /// treats every host string as its own server, so all coverage against <c>\\127.0.0.1</c> says
    /// nothing about this path: `localhost` resolves to ::1 first (the server listens on IPv4 only),
    /// and the fallback behaviour plus a second server entry against the same running server is what
    /// this pins.
    /// </summary>
    [SkippableFact]
    public void LocalhostAlias_EnumerateAndOpenFile_Works()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "notes.txt"), "localhost content");
        string aliasDir = ToAlias(unc, "localhost");

        try
        {
            ConnectVia("localhost");

            Assert.Contains("notes.txt",
                Timed("enumerate via localhost", () => Directory.GetFiles(aliasDir).Select(Path.GetFileName)));
            Assert.Equal("localhost content",
                Timed("read via localhost", () => File.ReadAllText($@"{aliasDir}\notes.txt")));
        }
        finally
        {
            DisconnectAlias("localhost");
        }
    }

    /// <summary>
    /// The flow that produced the reported "kann nicht gefunden werden", end to end under the alias:
    /// Explorer creates <c>Neues Textdokument.txt</c>, looks it up by exact name, the user renames it,
    /// then double-clicks — the editor opens it by the new name over the SAME alias connection whose
    /// caches watched the whole flow. Splitting create/rename from the final open across the alias vs.
    /// the canonical host would miss any cache/lookup interaction, so everything runs on the alias.
    /// </summary>
    [SkippableFact]
    public void LocalhostAlias_NewTextDocument_CreateRenameOpen_ExplorerFlow()
    {
        var (unc, local) = Dir();
        string aliasDir = ToAlias(unc, "localhost");

        try
        {
            ConnectVia("localhost");

            Timed("create provisional", () =>
            {
                using var fs = new FileStream($@"{aliasDir}\Neues Textdokument.txt", FileMode.CreateNew, FileAccess.Write);
            });

            // Explorer's post-create exact-name lookup (the F8 shape), now under the alias.
            Assert.Equal(["Neues Textdokument.txt"], Timed("exact-name lookup", () =>
                Directory.GetFiles(aliasDir, "Neues Textdokument.txt").Select(Path.GetFileName).ToList()));

            Timed("inline rename", () => File.Move($@"{aliasDir}\Neues Textdokument.txt", $@"{aliasDir}\notes.txt"));

            // The double-click: open by the new name. This is where the user saw NOT_FOUND.
            Assert.Equal(string.Empty, Timed("open renamed file", () => File.ReadAllText($@"{aliasDir}\notes.txt")));

            Timed("edit and save", () => File.WriteAllText($@"{aliasDir}\notes.txt", "edited"));
            Assert.Equal("edited", ReadBackendText(Path.Combine(local, "notes.txt")));
        }
        finally
        {
            DisconnectAlias("localhost");
        }
    }

    /// <summary>
    /// Shortcut creation through the REAL shell code path: <c>WScript.Shell</c>'s CreateShortcut is
    /// IShellLink + IPersistFile::Save — the same COM machinery Explorer's "Neu → Verknüpfung" and
    /// "Verknüpfung erstellen" run, as opposed to the plain write+reopen model of
    /// <see cref="CreateShortcut_WriteThenImmediateReopen_DoesNotFreeze"/>. IPersistFile::Save opens
    /// with shapes plain File I/O never sends; the reported symptom was a freeze followed by a
    /// fallback, so the whole flow is time-boxed and then re-read like Explorer's icon extraction does.
    /// </summary>
    [SkippableFact]
    public void CreateShortcut_ViaShellCom_SavesAndReopensPromptly()
    {
        var (unc, local) = Dir();
        string lnkUnc = $@"{unc}\Editor - Verknüpfung.lnk";

        Timed("IShellLink::Save", () =>
        {
            Type shellType = Type.GetTypeFromProgID("WScript.Shell")
                ?? throw new InvalidOperationException("WScript.Shell not available");
            dynamic shell = Activator.CreateInstance(shellType)!;
            try
            {
                dynamic lnk = shell.CreateShortcut(lnkUnc);
                lnk.TargetPath = @"C:\Windows\notepad.exe";
                lnk.Description = "battery probe";
                lnk.Save();
            }
            finally
            {
                Marshal.FinalReleaseComObject(shell);
            }
        });

        Assert.True(File.Exists(Path.Combine(local, "Editor - Verknüpfung.lnk")),
            $"IPersistFile::Save reported success but nothing landed on the backend.{Environment.NewLine}{Lab.RecentLog()}");

        // Explorer re-opens a fresh .lnk immediately (icon extraction, preview) — the reported freeze.
        byte[] readBack = Timed("reopen .lnk", () => File.ReadAllBytes(lnkUnc));
        Assert.True(readBack.Length > 0, ".lnk re-read came back empty");
        Assert.Equal((byte)'L', readBack[0]); // shell link magic 0x4C
    }

    /// <summary>
    /// <c>GetFinalPathNameByHandle</c> on a share file — the call <c>Windows.Storage</c> (and with it the
    /// Windows 11 Notepad, every WinRT file picker, and packaged apps generally) makes while opening a
    /// file. Over SMB it needs QUERY_INFO <c>FileNormalizedNameInformation</c>; a server that declines the
    /// class fails this API, and the packaged editor then reports the file as <i>not found</i> even though
    /// it just enumerated it — the reported double-click symptom.
    /// </summary>
    [SkippableFact]
    public void GetFinalPathNameByHandle_OnShareFile_Works()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "notes.txt"), "x");

        using FileStream fs = File.Open($@"{unc}\notes.txt", FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var buffer = new StringBuilder(1024);
        uint len = GetFinalPathNameByHandleW(fs.SafeFileHandle, buffer, (uint)buffer.Capacity, 0);
        int err = Marshal.GetLastWin32Error();
        Output.WriteLine($"GetFinalPathNameByHandle → len={len} err={err} path='{buffer}'");

        Assert.True(len > 0,
            $"GetFinalPathNameByHandle failed with Win32 error {err} — Windows.Storage-based apps " +
            $"(Windows 11 Notepad among them) fail their open on this call and report the file as not " +
            $"found.{Environment.NewLine}Server log:{Environment.NewLine}{Lab.RecentLog()}");

        // Exact, not Contains: the client REBUILDS this path from the server's name answers
        // (FileNormalizedName/FileName), and the manual capture showed a leaf-only server answer
        // making it reconstruct wrong paths (share component doubled, or the leaf dropped) which it
        // then re-opened — the "file not found on a file that exists" family.
        Assert.Equal($@"\\?\UNC{unc[1..]}\notes.txt", buffer.ToString(), ignoreCase: true);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file, StringBuilder path, uint pathLength, uint flags);

    /// <summary>
    /// The reported double-click, driven end to end with the REAL editor: launch Notepad on a file under
    /// <c>\\localhost\…</c> exactly as Explorer's double-click would (ShellExecute), and assert it got the
    /// file open — its window title carries the document name on success, while a failed open falls back
    /// to "Unbenannt"/"Untitled" plus an error dialog. The server log is attached either way, so a failure
    /// names the request that declined. GUI-spawning, so the process is killed in <c>finally</c>.
    /// </summary>
    [SkippableFact]
    public void RealNotepad_DoubleClickOnLocalhostFile_OpensIt()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "probe-notes.txt"), "hello from the battery");

        var before = Process.GetProcessesByName("Notepad").Select(p => p.Id).ToHashSet();
        // Win11 Notepad is single-instance: with an instance already running (a GUI test seconds ago
        // whose window is still winding down, or the user's own), the launch hands the file off as a
        // TAB to that instance — whose state may point at a server that no longer exists mid-suite.
        // That is not the scenario under test; skip rather than false-fail (or kill a human's notepad).
        Skip.If(before.Count > 0, "a Notepad instance is already running — the single-instance handoff " +
                                  "would not exercise a fresh open");
        try
        {
            ConnectVia("localhost");
            string alias = ToAlias(unc, "localhost");

            using var launcher = Process.Start(new ProcessStartInfo("notepad.exe", $"\"{alias}\\probe-notes.txt\"")
            {
                UseShellExecute = true,
            });

            // Win11 Notepad is packaged: the launcher may exit after handing off, so find the window by
            // title rather than by the launched process.
            var deadline = Stopwatch.StartNew();
            string titles = "";
            while (deadline.Elapsed < OpTimeout)
            {
                titles = string.Join(" | ", Process.GetProcessesByName("Notepad")
                    .Concat(Process.GetProcessesByName("notepad"))
                    .Select(p => { try { return p.MainWindowTitle; } catch { return ""; } })
                    .Where(t => t.Length > 0));
                if (titles.Contains("probe-notes", StringComparison.OrdinalIgnoreCase)) break;
                Thread.Sleep(250);
            }
            Output.WriteLine($"notepad titles after {deadline.ElapsedMilliseconds} ms: {titles}");

            Assert.True(titles.Contains("probe-notes", StringComparison.OrdinalIgnoreCase),
                $"Notepad never showed 'probe-notes' in a window title (saw: '{titles}') — the editor could " +
                $"not open the file it was handed, which is the reported double-click failure.");

            AssertDataOpenOnWire("probe-notes.txt");
        }
        finally
        {
            foreach (Process p in Process.GetProcessesByName("Notepad").Concat(Process.GetProcessesByName("notepad")))
            {
                if (!before.Contains(p.Id))
                    try { p.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            }
            DisconnectAlias("localhost");
        }
    }

    /// <summary>
    /// The reported flows one level closer to reality: a REAL Explorer window is open on the folder
    /// (directory handle, CHANGE_NOTIFY watch, icon extraction — each with its own opens and batch
    /// oplocks) while the flow runs inside it. The prior repro tests drove the operations without a
    /// window and stayed green; whatever broke manually involves Explorer's own concurrent opens.
    /// </summary>
    [SkippableFact]
    public void RealExplorer_DoubleClickInOpenFolder_OpensEditor()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "notes.txt"), "Example notes\r\nLine 2.\r\n");
        var notepadsBefore = Process.GetProcessesByName("Notepad").Select(p => p.Id).ToHashSet();

        try
        {
            ConnectVia("localhost");
            string alias = ToAlias(unc, "localhost");

            using var _ = Process.Start(new ProcessStartInfo("explorer.exe", $"\"{alias}\"") { UseShellExecute = true });
            dynamic folder = AwaitExplorerWindow(alias);

            // Give Explorer a moment to run its usual post-enumeration work (icons, preview, details).
            Thread.Sleep(1500);

            // The double-click: invoke the item's default verb inside the open window.
            dynamic item = folder.Document.Folder.ParseName("notes.txt")
                ?? throw new InvalidOperationException($"Explorer window does not see notes.txt.{Environment.NewLine}{Lab.RecentLog()}");
            Timed("invoke default verb", () => item.InvokeVerb());

            var deadline = Stopwatch.StartNew();
            string titles = "";
            while (deadline.Elapsed < OpTimeout)
            {
                titles = NotepadTitles();
                if (titles.Contains("notes", StringComparison.OrdinalIgnoreCase)) break;
                Thread.Sleep(250);
            }
            Output.WriteLine($"editor titles after {deadline.ElapsedMilliseconds} ms: '{titles}'");
            Assert.True(titles.Contains("notes", StringComparison.OrdinalIgnoreCase),
                $"the editor never opened notes.txt from the Explorer window (titles: '{titles}') — " +
                "the reported double-click failure.");
            AssertDataOpenOnWire("notes.txt");
        }
        finally
        {
            CloseExplorerWindows("localhost");
            KillNewNotepads(notepadsBefore);
            DisconnectAlias("localhost");
        }
    }

    /// <summary>
    /// Shortcut creation inside a watched folder: IShellLink::Save writes <c>Neue Verknüpfung.lnk</c>
    /// while the Explorer window watches the directory — Explorer reacts to the CHANGE_NOTIFY by opening
    /// the fresh .lnk for icon extraction, and the wizard's subsequent rename then runs against a file
    /// Explorer holds open under a batch oplock. That interleaving is what a bare COM save (no window)
    /// never produced, and the manual session left exactly the un-renamed <c>Neue Verknüpfung.lnk</c>
    /// behind after its freeze.
    /// </summary>
    [SkippableFact]
    public void RealExplorer_CreateShortcutInWatchedFolder_SaveAndRename_DoesNotFreeze()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "seed.txt"), "x"); // window has something to draw

        try
        {
            ConnectVia("localhost");
            string alias = ToAlias(unc, "localhost");

            using var _ = Process.Start(new ProcessStartInfo("explorer.exe", $"\"{alias}\"") { UseShellExecute = true });
            AwaitExplorerWindow(alias);
            Thread.Sleep(1000);

            Timed("IShellLink::Save into watched folder", () =>
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell")!;
                dynamic shell = Activator.CreateInstance(shellType)!;
                try
                {
                    dynamic lnk = shell.CreateShortcut($@"{alias}\Neue Verknüpfung.lnk");
                    lnk.TargetPath = @"C:\Windows\notepad.exe";
                    lnk.Save();
                }
                finally
                {
                    Marshal.FinalReleaseComObject(shell);
                }
            });

            // Explorer notices the new .lnk via CHANGE_NOTIFY and opens it (icon extraction) — give it
            // time to be mid-flight, then rename like the wizard's final step does.
            Thread.Sleep(1500);
            Timed("rename provisional shortcut", () =>
                File.Move($@"{alias}\Neue Verknüpfung.lnk", $@"{alias}\Editor - Verknüpfung.lnk"));

            Assert.True(File.Exists(Path.Combine(local, "Editor - Verknüpfung.lnk")),
                $"rename never landed on the backend.{Environment.NewLine}{Lab.RecentLog()}");

            // The folder must still be fully usable afterwards (the freeze outlives the operation).
            byte[] readBack = Timed("reopen renamed .lnk", () => File.ReadAllBytes($@"{alias}\Editor - Verknüpfung.lnk"));
            Assert.Equal((byte)'L', readBack[0]);
            Output.WriteLine($"server log:{Environment.NewLine}{Lab.RecentLog()}");
        }
        finally
        {
            CloseExplorerWindows("localhost");
            DisconnectAlias("localhost");
        }
    }

    /// <summary>
    /// The same double-click, but in the share ROOT — where the user actually was
    /// (<c>\\localhost\Files\notes.txt</c>). Root paths take different branches than subdirectory
    /// paths ("" vs "."; F8 lived exactly there), and every other battery case runs in a per-test
    /// subdirectory, so the root flow had zero coverage.
    /// </summary>
    [SkippableFact]
    public void RealExplorer_DoubleClickInShareRoot_OpensEditor()
    {
        Require();
        string probe = $"root-notes-{_rootTag}.txt";
        File.WriteAllText(Path.Combine(Lab.WritableShareRoot, probe), "root notes");
        var notepadsBefore = Process.GetProcessesByName("Notepad").Select(p => p.Id).ToHashSet();

        try
        {
            ConnectVia("localhost");
            string aliasRoot = ToAlias(Lab.WritableShareUnc, "localhost");

            using var _ = Process.Start(new ProcessStartInfo("explorer.exe", $"\"{aliasRoot}\"") { UseShellExecute = true });
            dynamic folder = AwaitExplorerWindow(aliasRoot);
            Thread.Sleep(1500);

            dynamic item = folder.Document.Folder.ParseName(probe)
                ?? throw new InvalidOperationException($"Explorer window does not see {probe}.{Environment.NewLine}{Lab.RecentLog()}");
            Timed("invoke default verb in root", () => item.InvokeVerb());

            var deadline = Stopwatch.StartNew();
            string titles = "";
            while (deadline.Elapsed < OpTimeout)
            {
                titles = NotepadTitles();
                if (titles.Contains("root-notes", StringComparison.OrdinalIgnoreCase)) break;
                Thread.Sleep(250);
            }
            Output.WriteLine($"editor titles after {deadline.ElapsedMilliseconds} ms: '{titles}'");
            Assert.True(titles.Contains("root-notes", StringComparison.OrdinalIgnoreCase),
                $"the editor never opened {probe} from the share-root Explorer window (titles: '{titles}').");
            AssertDataOpenOnWire(probe);
        }
        finally
        {
            CloseExplorerWindows("localhost");
            KillNewNotepads(notepadsBefore);
            DisconnectAlias("localhost");
            try { File.Delete(Path.Combine(Lab.WritableShareRoot, probe)); } catch { /* best-effort */ }
        }
    }

    /// <summary>Shortcut save + wizard rename in the share ROOT, window open — the manual session's exact shape.</summary>
    [SkippableFact]
    public void RealExplorer_CreateShortcutInShareRoot_SaveAndRename_DoesNotFreeze()
    {
        Require();
        string provisional = $"Neue Verknüpfung {_rootTag}.lnk";
        string final = $"Editor {_rootTag} - Verknüpfung.lnk";

        try
        {
            ConnectVia("localhost");
            string aliasRoot = ToAlias(Lab.WritableShareUnc, "localhost");

            using var _ = Process.Start(new ProcessStartInfo("explorer.exe", $"\"{aliasRoot}\"") { UseShellExecute = true });
            AwaitExplorerWindow(aliasRoot);
            Thread.Sleep(1000);

            Timed("IShellLink::Save into share root", () =>
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell")!;
                dynamic shell = Activator.CreateInstance(shellType)!;
                try
                {
                    dynamic lnk = shell.CreateShortcut($@"{aliasRoot}\{provisional}");
                    lnk.TargetPath = @"C:\Windows\notepad.exe";
                    lnk.Save();
                }
                finally
                {
                    Marshal.FinalReleaseComObject(shell);
                }
            });

            Thread.Sleep(1500); // Explorer's icon extraction on the fresh .lnk is mid-flight now
            Timed("rename provisional shortcut in root", () =>
                File.Move($@"{aliasRoot}\{provisional}", $@"{aliasRoot}\{final}"));

            Assert.True(File.Exists(Path.Combine(Lab.WritableShareRoot, final)),
                $"root rename never landed on the backend.{Environment.NewLine}{Lab.RecentLog()}");
            byte[] readBack = Timed("reopen renamed root .lnk", () => File.ReadAllBytes($@"{aliasRoot}\{final}"));
            Assert.Equal((byte)'L', readBack[0]);
        }
        finally
        {
            CloseExplorerWindows("localhost");
            DisconnectAlias("localhost");
            foreach (string name in new[] { provisional, final })
                try { File.Delete(Path.Combine(Lab.WritableShareRoot, name)); } catch { /* best-effort */ }
        }
    }

    private readonly string _rootTag = Guid.NewGuid().ToString("N")[..6];

    /// <summary>
    /// The wire-level truth check for "the editor really loaded the file": the server log must show
    /// an open of the file with DATA-read intent. A window title is not evidence — the Windows 11
    /// Notepad shows the file name in its tab even while the body reports "Die Datei … kann nicht
    /// gefunden werden" (measured: the title-based assertions here were green through exactly that
    /// failure). The broken flow only ever opened with FILE_READ_ATTRIBUTES (0x80/0x100080), probed,
    /// and gave up — it never asked for the bytes.
    /// </summary>
    protected void AssertDataOpenOnWire(string fileName)
    {
        var deadline = Stopwatch.StartNew();
        bool sawDataOpen = false;
        string pattern = @"\[create\] '[^']*" + Regex.Escape(fileName) + @"' disp=\w+ access=0x([0-9A-Fa-f]{8})";
        // Generous: on a loaded machine (mid-suite) the packaged app's activation pipeline alone can
        // take several seconds before the data open reaches the wire.
        while (deadline.Elapsed < TimeSpan.FromSeconds(20) && !sawDataOpen)
        {
            foreach (Match m in Regex.Matches(Lab.RecentLog(), pattern))
            {
                uint access = Convert.ToUInt32(m.Groups[1].Value, 16);
                const uint dataReadIntent = 0x80000001 | 0x02000000; // GENERIC_READ | FILE_READ_DATA | MAXIMUM_ALLOWED
                if ((access & dataReadIntent) != 0) { sawDataOpen = true; break; }
            }
            if (!sawDataOpen) Thread.Sleep(250);
        }
        Output.WriteLine($"server log:{Environment.NewLine}{Lab.RecentLog()}");
        Assert.True(sawDataOpen,
            $"the client never opened '{fileName}' with data-read access — it only probed attributes and " +
            "gave up, i.e. the app is reporting the file as not found despite the window title carrying it.");
    }

    /// <summary>Waits until a real Explorer window shows <paramref name="folderUnc"/> and returns it.</summary>
    private dynamic AwaitExplorerWindow(string folderUnc)
    {
        Type shellType = Type.GetTypeFromProgID("Shell.Application")!;
        dynamic shell = Activator.CreateInstance(shellType)!;
        var deadline = Stopwatch.StartNew();
        string expected = folderUnc.TrimEnd('\\');
        while (deadline.Elapsed < OpTimeout)
        {
            foreach (dynamic w in shell.Windows())
            {
                string? path = null;
                try { path = (string?)w.Document?.Folder?.Self?.Path; } catch { /* window mid-navigation */ }
                if (string.Equals(path, expected, StringComparison.OrdinalIgnoreCase))
                {
                    Output.WriteLine($"explorer window on '{path}' after {deadline.ElapsedMilliseconds} ms");
                    return w;
                }
            }
            Thread.Sleep(250);
        }
        throw new InvalidOperationException(
            $"no Explorer window appeared on {expected} within {OpTimeout.TotalSeconds:0}s — opening the " +
            $"share folder itself froze.{Environment.NewLine}Server log:{Environment.NewLine}{Lab.RecentLog()}");
    }

    /// <summary>
    /// Closes every Explorer window whose location lies under the given host — and WAITS until they
    /// are gone. Quit() is asynchronous; a window still winding down keeps its directory handles (and
    /// with them the redirector connection) alive, so a fire-and-forget close let the alias connection
    /// linger into the next lab, where the different lab account turned it into a 15-second 1219 storm.
    /// </summary>
    private static void CloseExplorerWindows(string host)
    {
        try
        {
            Type shellType = Type.GetTypeFromProgID("Shell.Application")!;
            dynamic shell = Activator.CreateInstance(shellType)!;
            var deadline = Stopwatch.StartNew();
            while (deadline.Elapsed < TimeSpan.FromSeconds(10))
            {
                bool any = false;
                foreach (dynamic w in shell.Windows())
                {
                    string? path = null;
                    try { path = (string?)w.Document?.Folder?.Self?.Path; } catch { /* ignore */ }
                    if (path is not null && path.StartsWith($@"\\{host}\", StringComparison.OrdinalIgnoreCase))
                    {
                        any = true;
                        try { w.Quit(); } catch { /* best-effort */ }
                    }
                }
                if (!any) return;
                Thread.Sleep(250);
            }
        }
        catch { /* shell gone — nothing to close */ }
    }

    private static string NotepadTitles() => string.Join(" | ",
        Process.GetProcessesByName("Notepad").Concat(Process.GetProcessesByName("notepad"))
            .Select(p => { try { return p.MainWindowTitle; } catch { return ""; } })
            .Where(t => t.Length > 0));

    private static void KillNewNotepads(HashSet<int> before)
    {
        // Close gracefully first: a hard kill leaves the Win11 Notepad's session-restore state
        // behind, and the NEXT launch then restores tabs / shows a crash prompt instead of loading
        // the file it was handed — which made the following GUI test's wire oracle time out.
        var mine = Process.GetProcessesByName("Notepad").Concat(Process.GetProcessesByName("notepad"))
            .Where(p => !before.Contains(p.Id)).ToList();
        foreach (Process p in mine)
            try { p.CloseMainWindow(); } catch { /* best-effort */ }
        foreach (Process p in mine)
        {
            try
            {
                if (!p.WaitForExit(3000)) p.Kill(entireProcessTree: true);
            }
            catch { /* best-effort */ }
        }
    }

    /// <summary>
    /// The Windows 11 Notepad's open, driven through the REAL API it uses: <c>Windows.Storage</c>.
    /// The title-based Notepad probes were false-green — the editor window shows the file name in
    /// its tab even while the body reports the file as not found. StorageFile is the layer that
    /// fails, so calling it directly is both the honest repro and the regression pin; the manual
    /// symptom was "Die Datei … kann nicht gefunden werden" on double-click for files that exist.
    /// </summary>
    [SkippableFact]
    public void WindowsStorageApi_OpenTextFileViaLocalhost_ReadsContent()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "notes.txt"), "storage api content");

        try
        {
            ConnectVia("localhost");
            string alias = ToAlias(unc, "localhost");

            string text = Timed("StorageFile open+read", () =>
            {
                try
                {
                    Windows.Storage.StorageFile file = Windows.Storage.StorageFile
                        .GetFileFromPathAsync($@"{alias}\notes.txt").AsTask().GetAwaiter().GetResult();
                    return Windows.Storage.FileIO.ReadTextAsync(file).AsTask().GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    throw new IOException(
                        $"Windows.Storage failed to open the file ({ex.GetType().Name}: {ex.Message}) — " +
                        $"this is the packaged-Notepad double-click failure.{Environment.NewLine}" +
                        $"Server log:{Environment.NewLine}{Lab.RecentLog()}", ex);
                }
            });

            Assert.Equal("storage api content", text);
        }
        finally
        {
            DisconnectAlias("localhost");
        }
    }

    /// <summary>Rewrites a lab UNC (<c>\\127.0.0.1\Share\dir</c>) onto an alternative host alias.</summary>
    protected static string ToAlias(string unc, string host)
        => $@"\\{host}\{unc[$@"\\{Host}\".Length..]}";

    /// <summary>
    /// Authenticates the redirector against this lab under an alternative host name. Every distinct
    /// host string is its own server entry to the redirector, so the lab's <c>\\127.0.0.1</c> login
    /// does not cover it.
    /// </summary>
    protected void ConnectVia(string host)
    {
        Require();
        string share = Lab.WritableShareUnc.Split('\\', StringSplitOptions.RemoveEmptyEntries)[1];
        NetUse.ConnectWithRetry($@"\\{host}\{share}", Lab.Domain, Lab.User, Lab.Password,
            Output.WriteLine, Lab.RecentLog);
    }

    /// <summary>
    /// Drops the alias connection and waits until the redirector no longer lists it — a connection
    /// still held open (e.g. by an Explorer window mid-teardown) survives <c>net use /delete</c> and
    /// greets the next lab's different account with error 1219.
    /// </summary>
    protected void DisconnectAlias(string host)
    {
        string share = Lab.WritableShareUnc.Split('\\', StringSplitOptions.RemoveEmptyEntries)[1];
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(10))
        {
            WindowsSmbLab.RunNet(out _, "use", $@"\\{host}\{share}", "/delete", "/y");
            WindowsSmbLab.RunNet(out _, "use", $@"\\{host}", "/delete", "/y");
            WindowsSmbLab.RunNet(out string listing, "use");
            if (!listing.Contains($@"\\{host}\", StringComparison.OrdinalIgnoreCase))
                return;
            Thread.Sleep(500);
        }
        Output.WriteLine($@"[lab] warning: a \\{host} connection outlived DisconnectAlias — the next lab may see 1219");
    }

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
        string unc = lab.WritableShareUnc;

        bool ok = Timed("free space", () => GetDiskFreeSpaceEx(unc + @"\", out ulong avail, out ulong total, out _)
            ? Report(avail, total)
            : throw new Win32Exception_(Marshal.GetLastWin32Error(),
                $"GetDiskFreeSpaceEx{Environment.NewLine}Server log:{Environment.NewLine}{lab.RecentLog()}"));

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
        string unc = lab.ReadOnlyShareUnc;

        // The share is readable...
        Assert.Equal(lab.ReadOnlyProbeContent, Timed("read ro share", () => File.ReadAllText($@"{unc}\{lab.ReadOnlyProbeFile}")));

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
            // Line-based so both labs match regardless of log decoration ("[server] " prefix etc.).
            if (lab.RecentLog().Split('\n').Any(l => l.Contains("ChangeNotify mid=") && l.Contains("Pending")))
                return;
            Thread.Sleep(50);
        }
        Assert.Fail($"the client's directory watch never reached the server as a pending CHANGE_NOTIFY " +
                    $"within {OpTimeout.TotalSeconds:0}s.{Environment.NewLine}{lab.RecentLog()}");
    }

    // ─── Explorer-shaped composite flows II ───────────────────────────────

    /// <summary>
    /// Operations directly in the share root — everything else in the battery works in a
    /// subdirectory, but the first thing a user does in Explorer is create/rename/delete at the root
    /// of the share, where path parsing ("" vs ".", empty relative paths) takes different branches.
    /// </summary>
    [SkippableFact]
    public void ShareRoot_CreateEnumerateDelete_Works()
    {
        Require();
        string name = $"root-probe-{Guid.NewGuid():N}";
        string unc = $@"{lab.WritableShareUnc}\{name}";

        Timed("mkdir at root", () => Directory.CreateDirectory(unc));
        Assert.Contains(name, Timed("enumerate root", () => Directory.GetDirectories(lab.WritableShareUnc).Select(Path.GetFileName)));

        Timed("write at root", () => File.WriteAllText($@"{unc}\f.txt", "x"));
        Timed("delete at root", () => Directory.Delete(unc, recursive: true));
        AssertEventually(() => !Directory.Exists(unc), "root-level delete never became visible");
    }

    /// <summary>
    /// Explorer's "New folder" flow: create a directory with the placeholder name, then immediately
    /// rename it while its parent is being watched and enumerated — a rename of a directory that was
    /// created milliseconds ago, which trips servers that cache directory handles or oplock state by
    /// path.
    /// </summary>
    [SkippableFact]
    public void NewFolderThenRename_ExplorerFlow_Works()
    {
        var (unc, local) = Dir();

        Timed("create placeholder", () => Directory.CreateDirectory($@"{unc}\New folder"));
        Timed("rename placeholder", () => Directory.Move($@"{unc}\New folder", $@"{unc}\Projekte"));

        Assert.True(Directory.Exists(Path.Combine(local, "Projekte")));
        Assert.False(Directory.Exists(Path.Combine(local, "New folder")));
    }

    /// <summary>Deleting a populated tree — Explorer's delete of a folder with content.</summary>
    [SkippableFact]
    public void RecursiveDelete_RemovesWholeTree()
    {
        var (unc, local) = Dir();
        Directory.CreateDirectory(Path.Combine(local, "t", "sub"));
        File.WriteAllText(Path.Combine(local, "t", "a.txt"), "x");
        File.WriteAllText(Path.Combine(local, "t", "sub", "b.txt"), "x");

        Timed("recursive delete", () => Directory.Delete($@"{unc}\t", recursive: true));

        AssertEventually(() => !Directory.Exists(Path.Combine(local, "t")),
            "recursive delete never became visible on the backend");
    }

    /// <summary>
    /// A real robocopy of a directory tree onto the share — the tool admins actually use, driving
    /// opens, writes, timestamps and attribute stamping in robocopy's own aggressive order.
    /// </summary>
    [SkippableFact]
    public void Robocopy_CopiesTree_ByteExact()
    {
        var (unc, local) = Dir();
        string src = Path.Combine(Path.GetTempPath(), "smb-robosrc-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(src, "nested"));
        try
        {
            byte[] payload = new byte[128 * 1024];
            Random.Shared.NextBytes(payload);
            File.WriteAllBytes(Path.Combine(src, "top.bin"), payload);
            File.WriteAllText(Path.Combine(src, "nested", "deep.txt"), "deep content");

            int exit = Timed("robocopy /E", () => RunProcess("robocopy", src, $@"{unc}\dst", "/E", "/NFL", "/NDL", "/NJH", "/NJS"));
            // Robocopy exit codes: 0–7 success (1 = files copied), ≥8 failure.
            Assert.True(exit < 8, $"robocopy failed with exit code {exit}.{Environment.NewLine}{lab.RecentLog()}");

            Assert.Equal(payload, ReadBackend(Path.Combine(local, "dst", "top.bin")));
            Assert.Equal("deep content", ReadBackendText(Path.Combine(local, "dst", "nested", "deep.txt")));
        }
        finally
        {
            try { Directory.Delete(src, recursive: true); } catch { /* best-effort */ }
        }
    }

    /// <summary>
    /// The save flow of Office and most editors: write the new content to a temp file, then
    /// <c>File.Replace</c> it over the original (FILE_RENAME_INFORMATION with ReplaceIfExists,
    /// after the original moved to the backup name). A server that mishandles replace-rename loses
    /// either the new content or the backup.
    /// </summary>
    [SkippableFact]
    public void FileReplace_SaveFlow_SwapsContentAndKeepsBackup()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "doc.txt"), "old content");

        Timed("save via replace", () =>
        {
            File.WriteAllText($@"{unc}\doc.tmp", "new content");
            File.Replace($@"{unc}\doc.tmp", $@"{unc}\doc.txt", $@"{unc}\doc.bak");
        });

        Assert.Equal("new content", ReadBackendText(Path.Combine(local, "doc.txt")));
        Assert.Equal("old content", ReadBackendText(Path.Combine(local, "doc.bak")));
        Assert.False(File.Exists(Path.Combine(local, "doc.tmp")), "temp file must be gone after the replace");
    }

    /// <summary>
    /// Alternate data streams, as Explorer writes them: every file copied from a browser download
    /// carries a <c>Zone.Identifier</c> stream, and Explorer writes it right after the main content.
    /// A server without stream support makes every such copy end in an error dialog.
    /// </summary>
    [SkippableFact]
    public void AlternateDataStream_ZoneIdentifier_RoundTrips()
    {
        var (unc, local) = Dir();
        const string zone = "[ZoneTransfer]\r\nZoneId=3\r\n";

        Timed("write main + ADS", () =>
        {
            File.WriteAllText($@"{unc}\download.txt", "payload");
            using var ads = new FileStream($@"{unc}\download.txt:Zone.Identifier", FileMode.Create, FileAccess.Write);
            ads.Write(Encoding.ASCII.GetBytes(zone));
        });

        string readBack = Timed("read ADS", () =>
        {
            using var ads = new FileStream($@"{unc}\download.txt:Zone.Identifier", FileMode.Open, FileAccess.Read);
            using var r = new StreamReader(ads, Encoding.ASCII);
            return r.ReadToEnd();
        });

        Assert.Equal(zone, readBack);
        Assert.Equal("payload", ReadBackendText(Path.Combine(local, "download.txt"))); // main stream untouched
    }

    /// <summary>
    /// Explorer's Properties → Security tab is a QUERY_INFO for the file's security descriptor. It
    /// must return a descriptor with an owner and a DACL — an error here makes the whole Properties
    /// dialog stall or come up empty.
    /// </summary>
    [SkippableFact]
    public void SecurityDescriptor_Query_ReturnsOwnerAndDacl()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "sec.txt"), "x");

        var security = Timed("query security", () => new FileInfo($@"{unc}\sec.txt").GetAccessControl());

        Assert.NotNull(security.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)));
        Assert.NotEmpty(security.GetAccessRules(includeExplicit: true, includeInherited: true,
            typeof(System.Security.Principal.SecurityIdentifier)));
    }

    /// <summary>
    /// Deleting a read-only file: Explorer first gets the decline, asks the user, clears the
    /// attribute and retries. Both halves must behave — the decline must be prompt and the retry must
    /// succeed.
    /// </summary>
    [SkippableFact]
    public void ReadOnlyFile_DeleteDeclined_ThenSucceedsAfterClearingAttribute()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "locked.txt"), "x");

        Timed("set read-only", () => File.SetAttributes($@"{unc}\locked.txt", FileAttributes.ReadOnly));
        Assert.ThrowsAny<UnauthorizedAccessException>(() =>
            Timed("delete read-only", () => File.Delete($@"{unc}\locked.txt")));

        Timed("clear read-only", () => File.SetAttributes($@"{unc}\locked.txt", FileAttributes.Normal));
        Timed("delete again", () => File.Delete($@"{unc}\locked.txt"));
        AssertEventually(() => !File.Exists(Path.Combine(local, "locked.txt")),
            "delete after clearing read-only never became visible");
    }

    /// <summary>Windows shares are case-insensitive; a lookup under a different case must hit.</summary>
    [SkippableFact]
    public void CaseInsensitiveLookup_OpensExistingFile()
    {
        var (unc, local) = Dir();
        File.WriteAllText(Path.Combine(local, "MixedCase.txt"), "case content");

        Assert.Equal("case content", Timed("read other case", () => File.ReadAllText($@"{unc}\mixedcase.TXT")));
    }

    /// <summary>
    /// Volume queries and root enumerations, interleaved — the combination Explorer produces the
    /// moment a share window opens (free space for the drive bar, listing for the view), and a
    /// regression pin for a bug the battery only caught by lucky test ordering: the redirector opens
    /// the share root attributes-only (ShareAccess=0) for GetDiskFreeSpaceEx and <b>caches that
    /// handle</b>. Per MS-FSA §2.1.5.1.2 an attributes-only open participates in no sharing checks;
    /// the server registered it anyway, so whichever of the two opens came second failed with a
    /// sharing violation — an Explorer window that could show either the listing or the drive bar,
    /// never both.
    /// </summary>
    [SkippableFact]
    public void VolumeQueryAndRootEnumeration_Interleaved_DoNotConflict()
    {
        Require();
        string root = lab.WritableShareUnc;

        Timed("free space #1", () => Assert.True(GetDiskFreeSpaceEx(root + @"\", out _, out _, out _),
            $"first GetDiskFreeSpaceEx failed: Win32 {Marshal.GetLastWin32Error()}"));
        Timed("enumerate root #1", () => Directory.GetFileSystemEntries(root));
        Timed("free space #2", () => Assert.True(GetDiskFreeSpaceEx(root + @"\", out _, out _, out _),
            $"GetDiskFreeSpaceEx after a root enumeration failed: Win32 {Marshal.GetLastWin32Error()} — " +
            "the enumeration's cached root handle blocked the volume open"));
        Timed("enumerate root #2", () => Directory.GetFileSystemEntries(root));
    }

    /// <summary>Runs a console tool with arguments; returns its exit code (stdout to test output).</summary>
    protected int RunProcess(string fileName, params string[] args)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string a in args) psi.ArgumentList.Add(a);
        using Process p = Process.Start(psi)!;
        string log = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        if (!p.WaitForExit(60_000))
        {
            p.Kill(entireProcessTree: true);
            Assert.Fail($"{fileName} did not exit within 60s.{Environment.NewLine}{log}");
        }
        if (log.Length > 0) output.WriteLine(log);
        return p.ExitCode;
    }

    // ─── Harness ──────────────────────────────────────────────────────────

    protected void Require() => lab.Require();

    /// <summary>
    /// Reads a backing file the way a bystander has to. The server keeps its own handle on an open file, and
    /// the client may hold the SMB open past the app's close while it has a lease — so at the moment a test
    /// checks the backend, the file is often still open read/write by the server. <c>File.ReadAllText</c> asks
    /// for deny-write sharing, which collides with exactly that and fails with a sharing violation on the
    /// <i>local</i> path. Being sharing-tolerant keeps these assertions about content rather than about when
    /// the client got round to sending CLOSE.
    /// </summary>
    protected static byte[] ReadBackend(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var ms = new MemoryStream();
        fs.CopyTo(ms);
        return ms.ToArray();
    }

    protected static string ReadBackendText(string path) => Encoding.UTF8.GetString(ReadBackend(path));

    /// <summary>
    /// Asserts a backend effect the client is entitled to delay. A delete over SMB is delete-on-close: the
    /// server removes the file when the handle closes, and the Windows client may hold that handle past the
    /// app's close while it has a lease. So the effect lands when the client sends CLOSE, not when
    /// <c>File.Delete</c> returns. Polling asserts the outcome without asserting a timing the protocol does
    /// not promise — and still fails, in bounded time, if the effect never lands at all.
    /// </summary>
    protected static void AssertEventually(Func<bool> condition, string because)
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
    protected (string Unc, string Local) Dir([System.Runtime.CompilerServices.CallerMemberName] string caller = "")
    {
        Require();
        return lab.NewDir(caller);
    }

    /// <summary>
    /// Runs one client operation with a deadline. A freeze is the symptom under investigation, so exceeding the
    /// deadline is reported as exactly that rather than hanging the run. The operation's own exception is
    /// preserved (unwrapped), because "which status did the client surface" is what most cases assert.
    /// </summary>
    protected T Timed<T>(string what, Func<T> op)
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

    protected void Timed(string what, Action op) => Timed<object?>(what, () => { op(); return null; });

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpaceEx(
        string directoryName, out ulong freeBytesAvailable, out ulong totalBytes, out ulong totalFreeBytes);

    /// <summary>
    /// Opens a directory handle the way Explorer does. .NET has no API for this — <c>FileStream</c> refuses a
    /// directory — so it has to go through CreateFile with FILE_FLAG_BACKUP_SEMANTICS, which is what makes
    /// the redirector send the directory CREATE (and, with it, the BATCH oplock request) under test.
    /// </summary>
    protected static SafeFileHandle OpenDirectoryHandle(string path) => CreateFileW(
        path, GenericRead, ShareAll, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics, IntPtr.Zero);

    private const uint GenericRead = 0x80000000;
    private const uint ShareAll = 0x00000007;              // FILE_SHARE_READ | WRITE | DELETE
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string path, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    private sealed class Win32Exception_(int code, string what)
        : IOException($"{what} failed with Win32 error {code}");
}
