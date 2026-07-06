using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Server.Sharing;
using Xunit;

namespace Smb.Tests;

/// <summary>Unit tests for the share-mode (sharing-violation) compatibility rule (O5).</summary>
public sealed class ShareModeManagerTests
{
    private const string Key = "Files\0report.docx";

    [Fact]
    public void SecondOpen_AgainstExclusiveHolder_IsRejected()
    {
        var m = new InMemoryShareModeManager();
        object first = new();
        Assert.True(m.TryOpen(Key, first, FileAccessIntent.ReadWrite, FileShareMode.None));
        // A second open that wants to read is denied because the holder shares nothing.
        Assert.False(m.TryOpen(Key, new object(), FileAccessIntent.Read,
            FileShareMode.Read | FileShareMode.Write | FileShareMode.Delete));
    }

    [Fact]
    public void SharedReaders_Coexist()
    {
        var m = new InMemoryShareModeManager();
        Assert.True(m.TryOpen(Key, new object(), FileAccessIntent.Read, FileShareMode.Read));
        Assert.True(m.TryOpen(Key, new object(), FileAccessIntent.Read, FileShareMode.Read));
    }

    [Fact]
    public void Writer_BlocksSecondWriter_WhenWriteNotShared()
    {
        var m = new InMemoryShareModeManager();
        Assert.True(m.TryOpen(Key, new object(), FileAccessIntent.Write, FileShareMode.Read)); // shares read only
        Assert.False(m.TryOpen(Key, new object(), FileAccessIntent.Write, FileShareMode.Read | FileShareMode.Write));
    }

    [Fact]
    public void Close_ReleasesReservation_AllowingExclusiveReopen()
    {
        var m = new InMemoryShareModeManager();
        object first = new();
        Assert.True(m.TryOpen(Key, first, FileAccessIntent.ReadWrite, FileShareMode.None));
        Assert.False(m.TryOpen(Key, new object(), FileAccessIntent.Read, FileShareMode.Read));
        m.Close(Key, first);
        Assert.True(m.TryOpen(Key, new object(), FileAccessIntent.ReadWrite, FileShareMode.None));
    }

    [Fact]
    public void DifferentFiles_DoNotConflict()
    {
        var m = new InMemoryShareModeManager();
        Assert.True(m.TryOpen("Files\0a", new object(), FileAccessIntent.ReadWrite, FileShareMode.None));
        Assert.True(m.TryOpen("Files\0b", new object(), FileAccessIntent.ReadWrite, FileShareMode.None));
    }
}

/// <summary>Unit tests for the persistent OS handle and the stable backend FileId (O2/O5).</summary>
public sealed class LocalFileStoreHandleTests : IDisposable
{
    private readonly string _dir;

    public LocalFileStoreHandleTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "smb-handle-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { /* best effort */ } }

    private static async Task<IFileHandle> OpenFileAsync(IFileStore s, string name, FileAccessIntent access, CreateDispositionIntent disp)
    {
        FileStoreResult<FileCreateResult> r = await s.CreateAsync(name, access, disp, directoryRequired: false, nonDirectoryRequired: true);
        Assert.True(r.IsSuccess, $"Create failed: {r.Status}");
        return r.Value.Handle;
    }

    [Fact]
    public async Task Write_Then_Read_ThroughPersistentHandle_RoundTrips()
    {
        IFileStore s = new LocalFileStore(_dir, readOnly: false);
        IFileHandle h = await OpenFileAsync(s, "data.bin", FileAccessIntent.ReadWrite, CreateDispositionIntent.OverwriteIf);
        byte[] payload = Enumerable.Range(0, 5000).Select(i => (byte)i).ToArray();

        Assert.True((await s.WriteAsync(h, 0, payload)).IsSuccess);
        Assert.Equal(payload.Length, h.GetInfo().EndOfFile); // size reflects the write via the open stream

        var buf = new byte[payload.Length];
        FileStoreResult<int> read = await s.ReadAsync(h, 0, buf);
        Assert.True(read.IsSuccess);
        Assert.Equal(payload.Length, read.Value);
        Assert.Equal(payload, buf);
        h.Dispose();
    }

    [Fact]
    public async Task DeleteOnClose_RemovesFile_OnDispose()
    {
        IFileStore s = new LocalFileStore(_dir, readOnly: false);
        IFileHandle h = await OpenFileAsync(s, "temp.txt", FileAccessIntent.ReadWrite, CreateDispositionIntent.Create);
        Assert.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(h, true));
        string full = Path.Combine(_dir, "temp.txt");
        Assert.True(File.Exists(full));
        h.Dispose();
        Assert.False(File.Exists(full));
    }

    [Fact]
    public async Task Rename_WhileHandleOpen_MovesFile_AndHandleStaysUsable()
    {
        IFileStore s = new LocalFileStore(_dir, readOnly: false);
        IFileHandle h = await OpenFileAsync(s, "old.txt", FileAccessIntent.ReadWrite, CreateDispositionIntent.Create);
        Assert.True((await s.WriteAsync(h, 0, new byte[] { 1, 2, 3 })).IsSuccess);

        Assert.Equal(NtStatus.Success, await s.RenameAsync(h, "new.txt", replaceIfExists: false));
        Assert.False(File.Exists(Path.Combine(_dir, "old.txt")));
        Assert.True(File.Exists(Path.Combine(_dir, "new.txt")));

        var buf = new byte[3];
        Assert.True((await s.ReadAsync(h, 0, buf)).IsSuccess); // open stream still valid after rename
        Assert.Equal(new byte[] { 1, 2, 3 }, buf);
        Assert.Equal("new.txt", h.GetInfo().Name);
        h.Dispose();
    }

    [Fact]
    public async Task FileId_IsStableAcrossCalls_AndDistinctPerFile()
    {
        File.WriteAllText(Path.Combine(_dir, "x.txt"), "x");
        File.WriteAllText(Path.Combine(_dir, "y.txt"), "y");
        IFileStore s = new LocalFileStore(_dir, readOnly: true);

        long x1 = await IndexOfAsync(s, "x.txt");
        long x2 = await IndexOfAsync(s, "x.txt");
        long y = await IndexOfAsync(s, "y.txt");

        Assert.NotEqual(0, x1);
        Assert.Equal(x1, x2);   // stable across calls (not process-randomized like string.GetHashCode)
        Assert.NotEqual(x1, y); // distinct per file
    }

    private static async Task<long> IndexOfAsync(IFileStore s, string name)
    {
        FileStoreResult<FileCreateResult> dir = await s.CreateAsync("", FileAccessIntent.Read, CreateDispositionIntent.Open,
            directoryRequired: true, nonDirectoryRequired: false);
        Assert.True(dir.IsSuccess);
        FileStoreResult<IReadOnlyList<FileEntryInfo>> listing = await s.QueryDirectoryAsync(dir.Value.Handle, name);
        Assert.True(listing.IsSuccess);
        return listing.Value!.Single(e => e.Name == name).IndexNumber;
    }
}
