using Smb.FileSystem;
using Smb.Server.Sharing;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Concurrency safety of <see cref="InMemoryShareModeManager"/> (docs/ENTERPRISE_HARDENING_ROADMAP.md,
/// A3): the atomic check-then-insert that concurrent CREATEs will hammer once metadata ops leave the
/// per-connection barrier (A2b). Proves the sharing-compatibility rule holds under parallel access and
/// that balanced open/close churn leaves the store consistent (no leaked entries).
/// </summary>
public class ShareModeManagerConcurrencyTests
{
    [Fact]
    public async Task ExclusiveAccess_NeverAllowsTwoConcurrentHolders()
    {
        var mgr = new InMemoryShareModeManager();
        const string key = "share\\file.dat";

        int currentHolders = 0;
        int maxObserved = 0;
        int successfulOpens = 0;

        // Each worker repeatedly tries to open Write with share=None. Only one such open may exist at a
        // time; a losing attempt gets false (not blocked). While held, assert we are the sole holder.
        void Worker()
        {
            var owner = new object();
            for (int i = 0; i < 20_000; i++)
            {
                if (!mgr.TryOpen(key, owner, FileAccessIntent.Write, FileShareMode.None))
                    continue;

                int now = Interlocked.Increment(ref currentHolders);
                InterlockedMax(ref maxObserved, now);
                Interlocked.Increment(ref successfulOpens);
                // brief critical section
                Interlocked.Decrement(ref currentHolders);
                mgr.Close(key, owner);
            }
        }

        Task[] workers = Enumerable.Range(0, 8).Select(_ => Task.Run(Worker)).ToArray();
        await Task.WhenAll(workers);

        Assert.Equal(1, maxObserved);          // atomic check-then-insert: never two exclusive holders
        Assert.True(successfulOpens > 0);       // sanity: the workers actually made progress

        // Store is consistent and empty again → a fresh exclusive open succeeds.
        var probe = new object();
        Assert.True(mgr.TryOpen(key, probe, FileAccessIntent.Write, FileShareMode.None));
        mgr.Close(key, probe);
    }

    [Fact]
    public void CompatibleShares_AllCoexist_ThenDrainClean()
    {
        var mgr = new InMemoryShareModeManager();
        const string key = "share\\shared.dat";
        var owners = Enumerable.Range(0, 64).Select(_ => new object()).ToArray();

        // Readers that all share read: every open must succeed (fully compatible).
        Parallel.ForEach(owners, o =>
            Assert.True(mgr.TryOpen(key, o, FileAccessIntent.Read, FileShareMode.Read | FileShareMode.Write | FileShareMode.Delete)));

        // While all readers are open, an exclusive Write with share=None must be refused.
        var exclusive = new object();
        Assert.False(mgr.TryOpen(key, exclusive, FileAccessIntent.Write, FileShareMode.None));

        Parallel.ForEach(owners, o => mgr.Close(key, o));

        // Drained → the exclusive open now succeeds.
        Assert.True(mgr.TryOpen(key, exclusive, FileAccessIntent.Write, FileShareMode.None));
        mgr.Close(key, exclusive);
    }

    private static void InterlockedMax(ref int target, int value)
    {
        int seen = Volatile.Read(ref target);
        while (value > seen)
        {
            int prior = Interlocked.CompareExchange(ref target, value, seen);
            if (prior == seen) return;
            seen = prior;
        }
    }
}
