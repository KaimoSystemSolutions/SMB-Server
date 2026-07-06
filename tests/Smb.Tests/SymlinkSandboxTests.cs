using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Regression tests for the symlink-aware path sandbox in <see cref="LocalFileStore"/>.
/// <c>Path.GetFullPath</c> only canonicalizes the path string ("..", slashes) but does not follow
/// symbolic links; a symlink placed inside the share that points outside would otherwise escape the
/// sandbox when the OS follows it on open. This is especially relevant on Unix/ZFS (TrueNAS).
///
/// The escape test needs to create a symbolic link, which requires privilege on some hosts (e.g.
/// Windows without Developer Mode). Where that is not permitted the test resolves to a no-op; on CI
/// (Linux) symlinks are unprivileged, so the protection is genuinely exercised there.
/// </summary>
public sealed class SymlinkSandboxTests : IDisposable
{
    private readonly string _base;
    private readonly string _root;
    private readonly string _outside;

    public SymlinkSandboxTests()
    {
        _base = Path.Combine(Path.GetTempPath(), "smb-symlink-test-" + Guid.NewGuid().ToString("N"));
        _root = Path.Combine(_base, "share");
        _outside = Path.Combine(_base, "outside");
        Directory.CreateDirectory(_root);
        Directory.CreateDirectory(_outside);
        File.WriteAllText(Path.Combine(_outside, "secret.txt"), "TOP SECRET");
    }

    [Fact]
    public async Task Create_ThroughDirectorySymlinkEscapingRoot_IsDenied()
    {
        string link = Path.Combine(_root, "escape");
        if (!TryCreateSymlink(link, _outside, directory: true))
            return;

        IFileStore store = new LocalFileStore(_root, readOnly: true);

        FileStoreResult<FileCreateResult> result = await store.CreateAsync(
            "escape\\secret.txt", FileAccessIntent.Read, CreateDispositionIntent.Open,
            directoryRequired: false, nonDirectoryRequired: true);

        Assert.False(result.IsSuccess);
        Assert.Equal(NtStatus.ObjectNameNotFound, result.Status);
    }

    [Fact]
    public async Task Create_ThroughFileSymlinkEscapingRoot_IsDenied()
    {
        string link = Path.Combine(_root, "leak.txt");
        if (!TryCreateSymlink(link, Path.Combine(_outside, "secret.txt"), directory: false))
            return;

        IFileStore store = new LocalFileStore(_root, readOnly: true);

        FileStoreResult<FileCreateResult> result = await store.CreateAsync(
            "leak.txt", FileAccessIntent.Read, CreateDispositionIntent.Open,
            directoryRequired: false, nonDirectoryRequired: true);

        Assert.False(result.IsSuccess);
        Assert.Equal(NtStatus.ObjectNameNotFound, result.Status);
    }

    [Fact]
    public async Task Create_NormalFileWithinRoot_StillWorks()
    {
        File.WriteAllText(Path.Combine(_root, "ok.txt"), "hello");
        IFileStore store = new LocalFileStore(_root, readOnly: true);

        FileStoreResult<FileCreateResult> result = await store.CreateAsync(
            "ok.txt", FileAccessIntent.Read, CreateDispositionIntent.Open,
            directoryRequired: false, nonDirectoryRequired: true);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task Create_FileWithinSymlinkedRoot_IsAllowed()
    {
        string linkedRoot = Path.Combine(_base, "linked-share");
        if (!TryCreateSymlink(linkedRoot, _root, directory: true))
            return;

        File.WriteAllText(Path.Combine(_root, "inside.txt"), "hi");
        IFileStore store = new LocalFileStore(linkedRoot, readOnly: true);

        FileStoreResult<FileCreateResult> result = await store.CreateAsync(
            "inside.txt", FileAccessIntent.Read, CreateDispositionIntent.Open,
            directoryRequired: false, nonDirectoryRequired: true);

        Assert.True(result.IsSuccess);
    }

    private static bool TryCreateSymlink(string link, string target, bool directory)
    {
        try
        {
            if (directory) Directory.CreateSymbolicLink(link, target);
            else File.CreateSymbolicLink(link, target);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            return directory && OperatingSystem.IsWindows() && TryCreateDirectoryJunction(link, target);
        }
    }

    private static bool TryCreateDirectoryJunction(string link, string target)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = System.Diagnostics.Process.Start(psi);
            if (p is null) return false;
            p.WaitForExit(5000);
            return p.HasExited && p.ExitCode == 0 && Directory.Exists(link);
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        try { Directory.Delete(_base, recursive: true); } catch { /* best effort */ }
    }
}
