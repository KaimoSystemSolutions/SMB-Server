using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Diagnostics;
using Smb.Server.OpenTelemetry;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// [D1] OpenTelemetry bridge (docs/ENTERPRISE_HARDENING_ROADMAP.md): the <see cref="OpenTelemetrySmbServerMetrics"/>
/// fans the server's counters/gauges/latencies out through a <c>System.Diagnostics.Metrics.Meter</c> and per-command
/// spans through an <c>ActivitySource</c> — both named "Smb.Server", with no OpenTelemetry SDK dependency.
/// </summary>
public sealed class OpenTelemetryBridgeTests
{
    [Fact]
    public void MeterBridge_EmitsCountersAndHistogram()
    {
        using var metrics = new OpenTelemetrySmbServerMetrics();
        var longs = new List<(string Name, long Value)>();
        var doubles = new List<(string Name, double Value)>();
        using MeterListener listener = SubscribeMeter(longs, doubles);

        metrics.OnConnectionAccepted();
        metrics.OnAuthenticationSucceeded();
        metrics.OnAuthenticationFailed();
        metrics.OnBytesRead("Files", 4096);
        metrics.OnBytesWritten("Files", 128);
        metrics.OnRequestCompleted(7.5);

        Assert.Contains(("smb.connections.accepted", 1L), longs);
        Assert.Contains(("smb.auth.success", 1L), longs);
        Assert.Contains(("smb.auth.failure", 1L), longs);
        Assert.Contains(("smb.bytes.read", 4096L), longs);
        Assert.Contains(("smb.bytes.written", 128L), longs);
        Assert.Contains(("smb.requests", 1L), longs);
        Assert.Contains(("smb.request.duration", 7.5), doubles);

        // The base snapshot keeps working unchanged (health endpoint is not lost by the fan-out).
        Assert.Equal(1, metrics.Snapshot().ConnectionsAccepted);
    }

    [Fact]
    public void MeterBridge_ObservableGauges_ReflectLiveCounts()
    {
        using var metrics = new OpenTelemetrySmbServerMetrics();
        var longs = new List<(string Name, long Value)>();
        using MeterListener listener = SubscribeMeter(longs, new List<(string, double)>());

        metrics.OnConnectionAccepted();
        metrics.OnConnectionAccepted();
        metrics.OnHandleOpened();

        listener.RecordObservableInstruments();

        Assert.Contains(("smb.connections.active", 2L), longs);
        Assert.Contains(("smb.handles.open", 1L), longs);
    }

    [Fact]
    public void BeginCommand_EmitsActivityWithCommandAndStatusTags()
    {
        using var metrics = new OpenTelemetrySmbServerMetrics();
        var activities = new List<Activity>();
        using ActivityListener listener = SubscribeActivities(activities);

        using (ISmbCommandTrace? trace = metrics.BeginCommand(SmbCommand.Create))
        {
            Assert.NotNull(trace);
            trace!.SetStatus(NtStatus.Success);
        }

        Activity activity = Assert.Single(activities);
        Assert.Equal("smb.Create", activity.OperationName);
        Assert.Equal("Create", activity.GetTagItem("smb.command"));
        Assert.Equal("Success", activity.GetTagItem("smb.status"));
        Assert.NotEqual(ActivityStatusCode.Error, activity.Status);
    }

    [Fact]
    public void BeginCommand_ErrorStatus_MarksActivityError()
    {
        using var metrics = new OpenTelemetrySmbServerMetrics();
        var activities = new List<Activity>();
        using ActivityListener listener = SubscribeActivities(activities);

        using (ISmbCommandTrace? trace = metrics.BeginCommand(SmbCommand.Read))
            trace!.SetStatus(NtStatus.AccessDenied);

        Activity activity = Assert.Single(activities);
        Assert.Equal(ActivityStatusCode.Error, activity.Status);
    }

    [Fact]
    public void Dispatcher_WithBridge_ProducesPerCommandSpan()
    {
        var activities = new List<Activity>();
        using ActivityListener listener = SubscribeActivities(activities);

        // Drive a real NEGOTIATE through the dispatcher with the bridge installed → BeginCommand must fire.
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(
                new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw"),
                new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
            Metrics = new OpenTelemetrySmbServerMetrics(),
        };
        options.Shares.Add(Share.CreateIpc());
        var dispatcher = new Smb2Dispatcher(new SmbServerState(options));
        var conn = new SmbConnection();

        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));

        Assert.Contains(activities, a => a.OperationName == "smb.Negotiate");
    }

    // --- helpers ---

    private static MeterListener SubscribeMeter(List<(string, long)> longs, List<(string, double)> doubles)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (inst, l) =>
            {
                if (inst.Meter.Name == OpenTelemetrySmbServerMetrics.SourceName)
                    l.EnableMeasurementEvents(inst);
            },
        };
        listener.SetMeasurementEventCallback<long>((inst, val, _, _) => longs.Add((inst.Name, val)));
        listener.SetMeasurementEventCallback<double>((inst, val, _, _) => doubles.Add((inst.Name, val)));
        listener.Start();
        return listener;
    }

    private static ActivityListener SubscribeActivities(List<Activity> sink)
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == OpenTelemetrySmbServerMetrics.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = sink.Add,
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }
}
