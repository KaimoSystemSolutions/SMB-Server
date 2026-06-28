using System.Buffers.Binary;
using System.Text;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.FileSystem.Versioning;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Tests for "Previous Versions" / snapshots: <see cref="VersioningFileStore"/>,
/// <c>@GMT-…</c> path resolution, and the FSCTL_SRV_ENUMERATE_SNAPSHOTS response.
/// Mirrors the scenarios from the external <c>smb_version_tester.py</c>.
/// </summary>
public class VersioningTests : IDisposable
{
    private readonly string _dir;

    public VersioningTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "smbver_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { /* ignore */ }
    }

    // ─── GmtToken ──────────────────────────────────────────────

    [Fact]
    public void GmtToken_RoundTrips()
    {
        var t = new DateTime(2026, 6, 24, 10, 30, 45, DateTimeKind.Utc);
        string token = GmtToken.Format(t);
        Assert.Equal("@GMT-2026.06.24-10.30.45", token);

        Assert.True(GmtToken.TryParse(token, out DateTime parsed));
        Assert.Equal(t, parsed);
        Assert.Equal(DateTimeKind.Utc, parsed.Kind);
    }

    [Fact]
    public void GmtToken_SplitsSnapshotPath()
    {
        Assert.True(GmtToken.TrySplitSnapshotPath(@"\@GMT-2026.06.24-10.30.45\sub\f.txt",
            out DateTime at, out string remainder));
        Assert.Equal(new DateTime(2026, 6, 24, 10, 30, 45, DateTimeKind.Utc), at);
        Assert.Equal(@"sub\f.txt", remainder);

        Assert.False(GmtToken.TrySplitSnapshotPath(@"normal\f.txt", out _, out _));
    }

    // ─── VersioningFileStore ──────────────────────────────────

    [Fact]
    public void Overwrite_OldContent_ReadableViaGmtPath()
    {
        var store = new VersioningFileStore(new LocalFileStore(_dir, readOnly: false));

        Assert.Equal(NtStatus.Success, Write(store, "f.txt", "Version 1"));
        DateTime t = DateTime.UtcNow;                 // point in time when V1 is current
        Thread.Sleep(50);
        Assert.Equal(NtStatus.Success, Write(store, "f.txt", "Version 2")); // saves V1, writes V2

        // Current file = V2.
        (NtStatus cur, byte[] curData) = ReadAll(store, "f.txt");
        Assert.Equal(NtStatus.Success, cur);
        Assert.Equal("Version 2", Encoding.UTF8.GetString(curData));

        // @GMT path at the time of V1 returns V1.
        string snapPath = GmtToken.Format(t) + "\\f.txt";
        (NtStatus snap, byte[] snapData) = ReadAll(store, snapPath);
        Assert.Equal(NtStatus.Success, snap);
        Assert.Equal("Version 1", Encoding.UTF8.GetString(snapData));
    }

    [Fact]
    public void Snapshot_IsReadOnly()
    {
        var store = new VersioningFileStore(new LocalFileStore(_dir, readOnly: false));
        Assert.Equal(NtStatus.Success, Write(store, "f.txt", "Original"));
        DateTime t = DateTime.UtcNow;
        Thread.Sleep(50);
        Assert.Equal(NtStatus.Success, Write(store, "f.txt", "Updated"));

        // Writing to the snapshot path (OverwriteIf, write access) must be rejected.
        string snapPath = GmtToken.Format(t) + "\\f.txt";
        NtStatus status = Write(store, snapPath, "SHOULD FAIL");
        Assert.Equal(NtStatus.AccessDenied, status);
    }

    [Fact]
    public void FreshFile_HasNoSnapshots()
    {
        var store = new VersioningFileStore(new LocalFileStore(_dir, readOnly: false));
        Assert.Equal(NtStatus.Success, Write(store, "once.txt", "only once"));

        Assert.Empty(((ISnapshotStore)store).GetSnapshots("once.txt"));

        // A @GMT access with no existing version → ObjectNameNotFound.
        string snapPath = GmtToken.Format(DateTime.UtcNow) + "\\once.txt";
        (NtStatus status, _) = ReadAll(store, snapPath);
        Assert.Equal(NtStatus.ObjectNameNotFound, status);
    }

    [Fact]
    public void SnapshotStore_ListsTimes_AfterOverwrite()
    {
        var store = new VersioningFileStore(new LocalFileStore(_dir, readOnly: false));
        Write(store, "f.txt", "A");
        Thread.Sleep(50);
        Write(store, "f.txt", "B");

        IReadOnlyList<DateTime> times = ((ISnapshotStore)store).GetSnapshots("f.txt");
        Assert.Single(times);
        Assert.All(times, t => Assert.Equal(DateTimeKind.Utc, t.Kind));

        // Root/empty path aggregates all snapshots.
        Assert.Single(((ISnapshotStore)store).GetSnapshots(""));
    }

    // ─── FSCTL_SRV_ENUMERATE_SNAPSHOTS Response ────────────────

    [Fact]
    public void EnumerateSnapshots_Response_ParsesBack()
    {
        string[] tokens =
        [
            GmtToken.Format(new DateTime(2026, 6, 24, 10, 0, 0, DateTimeKind.Utc)),
            GmtToken.Format(new DateTime(2026, 6, 24, 11, 0, 0, DateTimeKind.Utc)),
        ];

        byte[] body = IoctlMessage.BuildEnumerateSnapshotsResponse(tokens, maxOutputResponse: 4096);

        uint number = BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(0, 4));
        uint returned = BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(4, 4));
        uint arraySize = BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(8, 4));
        Assert.Equal(2u, number);
        Assert.Equal(2u, returned);
        Assert.True(arraySize > 0);

        string array = Encoding.Unicode.GetString(body.AsSpan(12, (int)arraySize));
        List<string> parsed = array.Split('\0').Where(s => s.StartsWith("@GMT-")).ToList();
        Assert.Equal(tokens, parsed);
    }

    [Fact]
    public void EnumerateSnapshots_BufferTooSmall_ReportsCountsOnly()
    {
        string[] tokens = [GmtToken.Format(DateTime.UtcNow)];

        // maxOutput = 12 → counters only, no array; but the required size is reported.
        byte[] body = IoctlMessage.BuildEnumerateSnapshotsResponse(tokens, maxOutputResponse: 12);

        Assert.Equal(12, body.Length);
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(0, 4)));  // NumberOfSnapshots
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(4, 4)));  // Returned
        Assert.True(BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(8, 4)) > 0);   // required size
    }

    // ─── Helpers ────────────────────────────────────────────────

    private static NtStatus Write(IFileStore store, string path, string content)
    {
        FileStoreResult<IFileHandle> r = store.Create(
            path, FileAccessIntent.ReadWrite, CreateDispositionIntent.OverwriteIf,
            directoryRequired: false, nonDirectoryRequired: true, out _);
        if (!r.IsSuccess) return r.Status;
        IFileHandle h = r.Value!;
        try
        {
            return store.Write(h, 0, Encoding.UTF8.GetBytes(content)).Status;
        }
        finally { h.Dispose(); }
    }

    private static (NtStatus status, byte[] data) ReadAll(IFileStore store, string path)
    {
        FileStoreResult<IFileHandle> r = store.Create(
            path, FileAccessIntent.Read, CreateDispositionIntent.Open,
            directoryRequired: false, nonDirectoryRequired: true, out _);
        if (!r.IsSuccess) return (r.Status, []);
        IFileHandle h = r.Value!;
        try
        {
            using var ms = new MemoryStream();
            var buf = new byte[4096];
            long off = 0;
            while (true)
            {
                FileStoreResult<int> rr = store.Read(h, off, buf);
                if (!rr.IsSuccess) return (rr.Status, []);
                if (rr.Value == 0) break;
                ms.Write(buf, 0, rr.Value);
                off += rr.Value;
            }
            return (NtStatus.Success, ms.ToArray());
        }
        finally { h.Dispose(); }
    }
}
