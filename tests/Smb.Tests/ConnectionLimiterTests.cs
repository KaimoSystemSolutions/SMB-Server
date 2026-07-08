using Smb.Server;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 8 / M8.3 — connection admission control. The <see cref="ConnectionLimiter"/> enforces a
/// global cap and a per-client cap, and frees slots on release.
/// </summary>
public class ConnectionLimiterTests
{
    [Fact]
    public void PerClientLimit_RejectsExcess()
    {
        var limiter = new ConnectionLimiter(globalMax: 0, perClientMax: 2);
        Assert.True(limiter.TryAdmit("10.0.0.1"));
        Assert.True(limiter.TryAdmit("10.0.0.1"));
        Assert.False(limiter.TryAdmit("10.0.0.1")); // third from same IP → rejected

        // A different client is unaffected.
        Assert.True(limiter.TryAdmit("10.0.0.2"));
    }

    [Fact]
    public void GlobalLimit_RejectsExcess()
    {
        var limiter = new ConnectionLimiter(globalMax: 2, perClientMax: 0);
        Assert.True(limiter.TryAdmit("10.0.0.1"));
        Assert.True(limiter.TryAdmit("10.0.0.2"));
        Assert.False(limiter.TryAdmit("10.0.0.3")); // global cap reached
        Assert.Equal(2, limiter.Total);
    }

    [Fact]
    public void Release_FreesASlot()
    {
        var limiter = new ConnectionLimiter(globalMax: 1, perClientMax: 1);
        Assert.True(limiter.TryAdmit("10.0.0.1"));
        Assert.False(limiter.TryAdmit("10.0.0.1"));

        limiter.Release("10.0.0.1");
        Assert.Equal(0, limiter.Total);
        Assert.Equal(0, limiter.CountFor("10.0.0.1"));
        Assert.True(limiter.TryAdmit("10.0.0.1")); // slot freed
    }

    [Fact]
    public void ZeroLimits_MeanUnlimited()
    {
        var limiter = new ConnectionLimiter(globalMax: 0, perClientMax: 0);
        for (int i = 0; i < 5000; i++)
            Assert.True(limiter.TryAdmit("10.0.0.1"));
        Assert.Equal(5000, limiter.Total);
    }

    [Fact]
    public void RejectedAdmission_DoesNotIncrementCounters()
    {
        var limiter = new ConnectionLimiter(globalMax: 1, perClientMax: 1);
        Assert.True(limiter.TryAdmit("10.0.0.1"));
        Assert.False(limiter.TryAdmit("10.0.0.2")); // rejected by global cap
        Assert.Equal(1, limiter.Total);
        Assert.Equal(0, limiter.CountFor("10.0.0.2"));
    }
}
