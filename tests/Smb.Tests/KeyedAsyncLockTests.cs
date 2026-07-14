using Smb.Server.Concurrency;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Unit tests for <see cref="KeyedAsyncLock{TKey}"/> (docs/ENTERPRISE_HARDENING_ROADMAP.md, A1): mutual
/// exclusion per key, parallelism across keys, key eviction, and cancellation.
/// </summary>
public class KeyedAsyncLockTests
{
    [Fact]
    public async Task SameKey_SerializesHolders()
    {
        var locks = new KeyedAsyncLock<string>();
        int concurrent = 0, maxConcurrent = 0;
        var start = new TaskCompletionSource();

        async Task Worker()
        {
            await start.Task;
            using (await locks.AcquireAsync("k"))
            {
                int now = Interlocked.Increment(ref concurrent);
                maxConcurrent = Math.Max(maxConcurrent, now);
                await Task.Delay(10);
                Interlocked.Decrement(ref concurrent);
            }
        }

        Task[] workers = Enumerable.Range(0, 8).Select(_ => Worker()).ToArray();
        start.SetResult();
        await Task.WhenAll(workers);

        Assert.Equal(1, maxConcurrent); // never two holders of the same key at once
    }

    [Fact]
    public async Task DifferentKeys_RunInParallel()
    {
        var locks = new KeyedAsyncLock<int>();
        const int n = 6;
        int inside = 0;
        var allInside = new TaskCompletionSource();
        var release = new TaskCompletionSource();

        async Task Worker(int key)
        {
            using (await locks.AcquireAsync(key))
            {
                if (Interlocked.Increment(ref inside) == n)
                    allInside.SetResult();
                await release.Task; // hold until everyone is inside
            }
        }

        Task[] workers = Enumerable.Range(0, n).Select(Worker).ToArray();

        // If distinct keys did NOT run in parallel, all n could never be inside simultaneously.
        Task completed = await Task.WhenAny(allInside.Task, Task.Delay(5000));
        Assert.True(completed == allInside.Task, "distinct keys did not run concurrently");

        release.SetResult();
        await Task.WhenAll(workers);
    }

    [Fact]
    public async Task Key_IsEvicted_AfterLastRelease()
    {
        var locks = new KeyedAsyncLock<string>();

        using (await locks.AcquireAsync("a"))
        {
            Assert.Equal(1, locks.TrackedKeyCount);
            using (await locks.AcquireAsync("b"))
                Assert.Equal(2, locks.TrackedKeyCount);
            Assert.Equal(1, locks.TrackedKeyCount); // "b" gone again
        }

        Assert.Equal(0, locks.TrackedKeyCount); // fully drained → no leak
    }

    [Fact]
    public async Task Contended_ThenDrained_LeavesNoState()
    {
        var locks = new KeyedAsyncLock<int>();

        async Task Worker() { using (await locks.AcquireAsync(42)) await Task.Delay(1); }

        await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => Worker()));

        Assert.Equal(0, locks.TrackedKeyCount);
    }

    [Fact]
    public async Task Cancellation_DropsReference_AndDoesNotBlockNextHolder()
    {
        var locks = new KeyedAsyncLock<string>();

        // Hold "k", then a second acquire that we cancel while it waits.
        var held = await locks.AcquireAsync("k");
        using var cts = new CancellationTokenSource();
        var pending = locks.AcquireAsync("k", cts.Token);

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pending);

        // Release the original holder; the cancelled waiter must have dropped its reference so the
        // key is now free and evicts cleanly after we release.
        held.Dispose();
        Assert.Equal(0, locks.TrackedKeyCount);

        // And the lock is reusable.
        using (await locks.AcquireAsync("k")) { }
        Assert.Equal(0, locks.TrackedKeyCount);
    }
}
