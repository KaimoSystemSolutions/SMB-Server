using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using Xunit;
using Xunit.Abstractions;
using Skip = Xunit.Skip;

namespace Smb.Tests;

/// <summary>
/// Directory-handle and folder-watch cases the general battery does not cover, driven against the real
/// Windows client (minimal <see cref="WindowsSmbLab"/>). These are the operations an editor issues when it
/// <b>opens a folder</b> rather than a single file — the reported "VS Code: the folder path does not exist
/// on this computer" and file-watching symptoms:
/// <list type="bullet">
///   <item><b>realpath on a directory handle</b> — Node/libuv's <c>realpathSync.native</c> calls
///     <c>GetFinalPathNameByHandle</c> on a handle opened with <c>FILE_FLAG_BACKUP_SEMANTICS</c>; the
///     battery only ever tested it on a FILE handle (<c>GetFinalPathNameByHandle_OnShareFile_Works</c>).</item>
///   <item><b>open + read through a mapped drive letter</b> — <c>net use Z: \\host\share</c> then a UNC-free
///     <c>Z:\dir\file.txt</c>, the shape a user gets from a mapped network drive.</item>
///   <item><b>recursive CHANGE_NOTIFY</b> — the watch VS Code arms on the opened folder
///     (<c>ReadDirectoryChangesW</c> with the watch-subtree flag).</item>
/// </list>
/// </summary>
[Collection(WindowsSmbLabCollection.Name)]
public class DirectoryClientInteropTests(WindowsSmbLab lab, ITestOutputHelper output)
{
    private const uint GenericRead = 0x80000000;
    private const uint ShareAll = 0x00000007;      // FILE_SHARE_READ | WRITE | DELETE
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string path, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file, StringBuilder path, uint pathLength, uint flags);

    private void Require() => Skip.If(lab.SkipReason is not null, lab.SkipReason);

    /// <summary>
    /// Opens a directory handle (the <c>FILE_FLAG_BACKUP_SEMANTICS</c> open .NET's FileStream refuses) and
    /// resolves it with <c>GetFinalPathNameByHandle</c> — the call an editor makes on the folder it opens.
    /// The resolved path must be the folder's own UNC in <c>\\?\UNC\…</c> form, byte-exact: the client
    /// rebuilds paths from it, and a wrong answer reads back as "the folder does not exist on this computer".
    /// </summary>
    private void AssertRealpath(string dirUnc, string expectedUncTail)
    {
        using SafeFileHandle h = CreateFileW(dirUnc, GenericRead, ShareAll, IntPtr.Zero,
            OpenExisting, FileFlagBackupSemantics, IntPtr.Zero);
        Assert.False(h.IsInvalid,
            $"could not open a directory handle for '{dirUnc}' (Win32 {Marshal.GetLastWin32Error()}) — an " +
            $"editor's folder open fails here.{Environment.NewLine}{lab.RecentLog()}");

        var sb = new StringBuilder(1024);
        uint len = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
        int err = Marshal.GetLastWin32Error();
        output.WriteLine($"realpath('{dirUnc}') → len={len} err={err} '{sb}'");
        Assert.True(len > 0,
            $"GetFinalPathNameByHandle on the directory handle failed (Win32 {err}) — Node/libuv's realpath " +
            $"fails here, and VS Code reports the folder as not existing.{Environment.NewLine}{lab.RecentLog()}");
        Assert.Equal($@"\\?\UNC\{expectedUncTail}", sb.ToString(), ignoreCase: true);
    }

    [SkippableFact]
    public void Realpath_OnShareRootDirectory_ResolvesToShareUnc()
    {
        Require();
        // WritableShareUnc is \\127.0.0.1\Files → tail 127.0.0.1\Files.
        AssertRealpath(lab.WritableShareUnc, lab.WritableShareUnc[2..]);
    }

    [SkippableFact]
    public void Realpath_OnSubdirectory_ResolvesToItsOwnUnc()
    {
        Require();
        var (unc, _) = lab.NewDir("realpath-sub");
        AssertRealpath(unc, unc[2..]);
    }

    [SkippableFact]
    public void Realpath_OnNestedSubdirectory_ResolvesToItsOwnUnc()
    {
        Require();
        var (unc, local) = lab.NewDir("realpath-nested");
        Directory.CreateDirectory(Path.Combine(local, "inner"));
        AssertRealpath($@"{unc}\inner", $@"{unc[2..]}\inner");
    }

    /// <summary>
    /// A mapped drive letter (<c>net use Z: \\host\share</c>): open the folder handle and read a text file
    /// through the drive-letter path, the way an editor opened from a mapped network drive does.
    /// </summary>
    [SkippableFact]
    public void MappedDrive_OpenFolderHandleAndReadTextFile()
    {
        Require();
        var (unc, local) = lab.NewDir("mapped");
        File.WriteAllText(Path.Combine(local, "notes.txt"), "hello from a mapped drive");

        string? drive = FreeDriveLetter();
        Skip.If(drive is null, "no free drive letter available");

        string share = lab.WritableShareUnc;
        int rc = WindowsSmbLab.RunNet(out string mapOut, "use", drive!, share,
            WindowsSmbLab.Password, $"/user:{WindowsSmbLab.Domain}\\{WindowsSmbLab.User}");
        output.WriteLine($"net use {drive} {share} → {rc}: {mapOut.Trim()}");
        Skip.If(rc != 0, $"could not map {drive} (net use rc {rc}) — mapped-drive case not exercised");

        try
        {
            string sub = unc[(share.Length + 1)..];        // "mapped-<runtag>"
            string driveFolder = $@"{drive}\{sub}";

            using (SafeFileHandle dh = CreateFileW(driveFolder, GenericRead, ShareAll, IntPtr.Zero,
                       OpenExisting, FileFlagBackupSemantics, IntPtr.Zero))
            {
                Assert.False(dh.IsInvalid,
                    $"could not open mapped folder '{driveFolder}' (Win32 {Marshal.GetLastWin32Error()})" +
                    $"{Environment.NewLine}{lab.RecentLog()}");
            }

            Assert.Equal("hello from a mapped drive", File.ReadAllText($@"{driveFolder}\notes.txt"));
        }
        finally
        {
            WindowsSmbLab.RunNet(out _, "use", drive!, "/delete", "/y");
        }
    }

    /// <summary>
    /// The recursive watch VS Code arms on the opened folder: a change anywhere in the subtree must produce
    /// a CHANGE_NOTIFY. Arms the watch and waits for it to reach the server before mutating, so this asserts
    /// the server's notify behaviour rather than a client-side arming race.
    /// </summary>
    [SkippableFact]
    public void RecursiveWatch_FiresOnChangeInSubdirectory()
    {
        Require();
        var (unc, local) = lab.NewDir("watch-rec");
        Directory.CreateDirectory(Path.Combine(local, "sub"));

        using var watcher = new FileSystemWatcher(unc)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.DirectoryName,
        };
        var fired = new ManualResetEventSlim(false);
        string? seen = null;
        watcher.Created += (_, e) => { seen = e.Name; fired.Set(); };
        watcher.Changed += (_, e) => { seen ??= e.Name; fired.Set(); };
        watcher.EnableRaisingEvents = true;
        Thread.Sleep(400); // let the CHANGE_NOTIFY reach the server before the mutation

        File.WriteAllText(Path.Combine(local, "sub", "new.txt"), "x");

        bool got = fired.Wait(TimeSpan.FromSeconds(10));
        output.WriteLine($"recursive watch fired={got} name='{seen}'{Environment.NewLine}{lab.RecentLog()}");
        Assert.True(got,
            $"recursive CHANGE_NOTIFY (watch-subtree) never fired on a change in a subdirectory — an editor's " +
            $"file watcher on the opened folder would miss edits.{Environment.NewLine}{lab.RecentLog()}");
    }

    private static string? FreeDriveLetter()
    {
        var used = DriveInfo.GetDrives().Select(d => char.ToUpperInvariant(d.Name[0])).ToHashSet();
        for (char c = 'Y'; c >= 'K'; c--)
            if (!used.Contains(c)) return $"{c}:";
        return null;
    }
}
