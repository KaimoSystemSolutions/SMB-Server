using Smb.FileSystem;
using Smb.Protocol.Messages;
using Smb.Server.Locking;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Kernlogik der Byte-Range-Lock-Verwaltung (<see cref="InMemoryLockManager"/>): Konflikte,
/// shared/exclusive, asynchrones Warten blockierender Locks und deren Abbruch.
/// </summary>
public class LockManagerTests
{
    private static int _id;

    private static SmbOpen MakeOpen(string path)
    {
        var conn = new SmbConnection();
        var session = new SmbSession { SessionId = 1, SessionGlobalId = 1, Connection = conn };
        var tree = new SmbTreeConnect { TreeId = 1, Session = session, Share = Share.CreateIpc() };
        return new SmbOpen
        {
            PersistentFileId = 0,
            VolatileFileId = (ulong)Interlocked.Increment(ref _id),
            Session = session,
            TreeConnect = tree,
            PathName = path,
        };
    }

    private static LockElement Lock(ulong off, ulong len, bool exclusive) => new(off, len, exclusive, Unlock: false);
    private static LockElement Unlock(ulong off, ulong len) => new(off, len, Exclusive: false, Unlock: true);

    [Fact]
    public async Task ExclusiveLock_BlocksOtherOpensReadAndWrite_ButNotOwn()
    {
        var mgr = new InMemoryLockManager();
        SmbOpen a = MakeOpen("file"), b = MakeOpen("file");

        Assert.Equal(LockOutcome.Granted, await mgr.ApplyAsync(a, [Lock(0, 10, true)], failImmediately: true, default));

        Assert.False(mgr.IsRangeAccessible(b, 5, 2, forWrite: false)); // anderer Open: kein Read
        Assert.False(mgr.IsRangeAccessible(b, 5, 2, forWrite: true));  // anderer Open: kein Write
        Assert.True(mgr.IsRangeAccessible(b, 20, 5, forWrite: true));  // außerhalb: frei
        Assert.True(mgr.IsRangeAccessible(a, 5, 2, forWrite: true));   // eigener Open: nie blockiert
    }

    [Fact]
    public async Task SharedLock_AllowsOtherRead_ButBlocksOtherWrite()
    {
        var mgr = new InMemoryLockManager();
        SmbOpen a = MakeOpen("file"), b = MakeOpen("file");
        await mgr.ApplyAsync(a, [Lock(0, 10, false)], failImmediately: true, default);

        Assert.True(mgr.IsRangeAccessible(b, 0, 10, forWrite: false));  // Read erlaubt
        Assert.False(mgr.IsRangeAccessible(b, 0, 10, forWrite: true));  // Write blockiert
    }

    [Fact]
    public async Task ConflictingLock_WithFailImmediately_ReturnsConflict()
    {
        var mgr = new InMemoryLockManager();
        SmbOpen a = MakeOpen("file"), b = MakeOpen("file");
        await mgr.ApplyAsync(a, [Lock(0, 10, true)], failImmediately: true, default);

        Assert.Equal(LockOutcome.Conflict, await mgr.ApplyAsync(b, [Lock(0, 10, true)], failImmediately: true, default));
    }

    [Fact]
    public async Task BlockingLock_IsGrantedAfterConflictingLockReleased()
    {
        var mgr = new InMemoryLockManager();
        SmbOpen a = MakeOpen("file"), b = MakeOpen("file");
        await mgr.ApplyAsync(a, [Lock(0, 10, true)], failImmediately: true, default);

        Task<LockOutcome> blocking = mgr.ApplyAsync(b, [Lock(0, 10, true)], failImmediately: false, default);
        Assert.False(blocking.IsCompleted); // wartet, weil a den Bereich hält

        Assert.Equal(LockOutcome.Granted, await mgr.ApplyAsync(a, [Unlock(0, 10)], failImmediately: true, default));
        Assert.Equal(LockOutcome.Granted, await blocking.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task BlockingLock_IsCancelledByToken()
    {
        var mgr = new InMemoryLockManager();
        SmbOpen a = MakeOpen("file"), b = MakeOpen("file");
        await mgr.ApplyAsync(a, [Lock(0, 10, true)], failImmediately: true, default);

        using var cts = new CancellationTokenSource();
        Task<LockOutcome> blocking = mgr.ApplyAsync(b, [Lock(0, 10, true)], failImmediately: false, cts.Token);
        Assert.False(blocking.IsCompleted);

        cts.Cancel();
        Assert.Equal(LockOutcome.Cancelled, await blocking.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task ReleaseOwner_FreesLocks_AndWakesWaiter()
    {
        var mgr = new InMemoryLockManager();
        SmbOpen a = MakeOpen("file"), b = MakeOpen("file");
        await mgr.ApplyAsync(a, [Lock(0, 10, true)], failImmediately: true, default);
        Task<LockOutcome> blocking = mgr.ApplyAsync(b, [Lock(0, 10, true)], failImmediately: false, default);

        mgr.ReleaseOwner(a); // Close von a → b wird gewährt
        Assert.Equal(LockOutcome.Granted, await blocking.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task Unlock_OfNonexistentRange_ReturnsRangeNotLocked()
    {
        var mgr = new InMemoryLockManager();
        SmbOpen a = MakeOpen("file");
        Assert.Equal(LockOutcome.RangeNotLocked, await mgr.ApplyAsync(a, [Unlock(0, 10)], failImmediately: true, default));
    }

    [Fact]
    public void LockMessage_ParseRoundtrip()
    {
        byte[] msg = TestHelpers.BuildLockRequest(7, sessionId: 3, treeId: 2, persistentId: 0x11, volatileId: 0x22,
        [
            (0x1000, 0x200, (uint)(LockFlags.ExclusiveLock | LockFlags.FailImmediately)),
            (0x5000, 0x10, (uint)LockFlags.Unlock),
        ]);

        LockMessage.Request req = LockMessage.ParseRequest(msg, Smb2Header.Size);
        Assert.Equal(0x11ul, req.PersistentId);
        Assert.Equal(0x22ul, req.VolatileId);
        Assert.Equal(2, req.Locks.Count);
        Assert.True(req.Locks[0].IsExclusive);
        Assert.True(req.Locks[0].FailImmediately);
        Assert.Equal(0x1000ul, req.Locks[0].Offset);
        Assert.True(req.Locks[1].IsUnlock);
        Assert.Equal(0x5000ul, req.Locks[1].Offset);
    }
}
