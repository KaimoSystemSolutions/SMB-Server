using Smb.Server.Concurrency;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Unit tests for <see cref="KeyedReaderWriterQueue{TKey}"/> (docs/ENTERPRISE_HARDENING_ROADMAP.md,
/// A2a): the dispatch-ordering primitive. Covers leading-shared batching, exclusive-runs-alone, strict
/// FIFO (no reordering, no writer starvation), cancellation of queued nodes, and key eviction.
/// </summary>
public class KeyedReaderWriterQueueTests
{
    private static async Task<bool> IsStillPending(Task t)
    {
        Task completed = await Task.WhenAny(t, Task.Delay(100));
        return completed != t;
    }

    [Fact]
    public async Task LeadingShared_RunInParallel()
    {
        var q = new KeyedReaderWriterQueue<string>();
        var r1 = q.Reserve("k", LockMode.Shared);
        var r2 = q.Reserve("k", LockMode.Shared);
        var r3 = q.Reserve("k", LockMode.Shared);

        // All three are leading shared → all grant without any release.
        var a1 = await r1.AcquireAsync();
        var a2 = await r2.AcquireAsync();
        var a3 = await r3.AcquireAsync();

        a1.Dispose(); a2.Dispose(); a3.Dispose();
        Assert.Equal(0, q.TrackedKeyCount);
    }

    [Fact]
    public async Task Exclusive_WaitsForPriorShared_ThenRunsAlone()
    {
        var q = new KeyedReaderWriterQueue<string>();
        var rs1 = q.Reserve("k", LockMode.Shared);
        var rs2 = q.Reserve("k", LockMode.Shared);
        var rx = q.Reserve("k", LockMode.Exclusive);

        var s1 = await rs1.AcquireAsync();
        var s2 = await rs2.AcquireAsync();
        Task<KeyedReaderWriterQueue<string>.Releaser> x = rx.AcquireAsync().AsTask();

        Assert.True(await IsStillPending(x)); // exclusive blocked by the two active shared

        s1.Dispose();
        Assert.True(await IsStillPending(x)); // still one shared holder

        s2.Dispose();
        var xr = await x;                      // now free → exclusive granted, alone
        xr.Dispose();
        Assert.Equal(0, q.TrackedKeyCount);
    }

    [Fact]
    public async Task SharedAfterExclusive_WaitsForIt_FifoNoReorder()
    {
        var q = new KeyedReaderWriterQueue<string>();
        var rx = q.Reserve("k", LockMode.Exclusive);
        var rs = q.Reserve("k", LockMode.Shared);

        var x = await rx.AcquireAsync();       // exclusive granted first (arrived first)
        Task<KeyedReaderWriterQueue<string>.Releaser> s = rs.AcquireAsync().AsTask();

        Assert.True(await IsStillPending(s));   // shared must wait behind the exclusive (FIFO)

        x.Dispose();
        var sr = await s;
        sr.Dispose();
        Assert.Equal(0, q.TrackedKeyCount);
    }

    [Fact]
    public async Task QueuedExclusive_IsNotStarved_ByLaterShared()
    {
        var q = new KeyedReaderWriterQueue<string>();
        var rs1 = q.Reserve("k", LockMode.Shared);   // active
        var rx = q.Reserve("k", LockMode.Exclusive); // queued behind active shared
        var rs2 = q.Reserve("k", LockMode.Shared);   // queued BEHIND the exclusive (FIFO)

        var s1 = await rs1.AcquireAsync();
        Task<KeyedReaderWriterQueue<string>.Releaser> x = rx.AcquireAsync().AsTask();
        Task<KeyedReaderWriterQueue<string>.Releaser> s2 = rs2.AcquireAsync().AsTask();

        Assert.True(await IsStillPending(x));
        Assert.True(await IsStillPending(s2));

        s1.Dispose();                          // active shared drains → exclusive is next, NOT the later shared
        var xr = await x;
        Assert.True(await IsStillPending(s2));  // s2 still waits behind the now-active exclusive

        xr.Dispose();
        var s2r = await s2;                     // finally granted
        s2r.Dispose();
        Assert.Equal(0, q.TrackedKeyCount);
    }

    [Fact]
    public async Task Cancellation_OfQueuedNode_UnblocksTheRest()
    {
        var q = new KeyedReaderWriterQueue<string>();
        var rx = q.Reserve("k", LockMode.Exclusive);   // will hold
        var rc = q.Reserve("k", LockMode.Shared);      // cancelled while queued
        var rs = q.Reserve("k", LockMode.Shared);      // must still proceed after the exclusive

        var x = await rx.AcquireAsync();
        using var cts = new CancellationTokenSource();
        Task<KeyedReaderWriterQueue<string>.Releaser> c = rc.AcquireAsync(cts.Token).AsTask();
        Task<KeyedReaderWriterQueue<string>.Releaser> s = rs.AcquireAsync().AsTask();

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await c);

        x.Dispose();                            // exclusive drains → s (not the cancelled c) is granted
        var sr = await s;
        sr.Dispose();
        Assert.Equal(0, q.TrackedKeyCount);
    }

    [Fact]
    public async Task CancellingQueuedExclusive_UnblocksSharedBehindIt()
    {
        var q = new KeyedReaderWriterQueue<string>();
        var rs1 = q.Reserve("k", LockMode.Shared);      // active
        var rx = q.Reserve("k", LockMode.Exclusive);    // queued, blocks the shared behind it
        var rs2 = q.Reserve("k", LockMode.Shared);      // queued behind the exclusive

        var s1 = await rs1.AcquireAsync();
        using var cts = new CancellationTokenSource();
        Task<KeyedReaderWriterQueue<string>.Releaser> x = rx.AcquireAsync(cts.Token).AsTask();
        Task<KeyedReaderWriterQueue<string>.Releaser> s2 = rs2.AcquireAsync().AsTask();

        Assert.True(await IsStillPending(s2)); // blocked by the queued exclusive

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await x);

        // The exclusive is gone; s2 can now join the still-active shared batch.
        var s2r = await s2;
        s1.Dispose();
        s2r.Dispose();
        Assert.Equal(0, q.TrackedKeyCount);
    }

    [Fact]
    public async Task DifferentKeys_RunInParallel()
    {
        var q = new KeyedReaderWriterQueue<int>();
        var ra = q.Reserve(1, LockMode.Exclusive);
        var rb = q.Reserve(2, LockMode.Exclusive);

        var a = await ra.AcquireAsync();        // both exclusive but different keys → both grant
        var b = await rb.AcquireAsync();

        a.Dispose(); b.Dispose();
        Assert.Equal(0, q.TrackedKeyCount);
    }
}
