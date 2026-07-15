using System.Diagnostics;
using System.Diagnostics.Metrics;
using Smb.Protocol.Enums;
using Smb.Server.Diagnostics;

namespace Smb.Server.OpenTelemetry;

/// <summary>
/// [D1] OpenTelemetry bridge (Phase D / D1): a drop-in <see cref="SmbServerMetrics"/> that also emits the
/// server's counters, gauges and latencies through the standard <see cref="System.Diagnostics.Metrics.Meter"/>
/// and per-command spans through an <see cref="System.Diagnostics.ActivitySource"/>. Both are named
/// <see cref="SourceName"/> (<c>"Smb.Server"</c>) — an OpenTelemetry SDK (or <c>dotnet-counters</c>) subscribes
/// to them by name; this library takes <b>no</b> dependency on the OpenTelemetry SDK itself.
/// <para>
/// Install by assigning it to <c>SmbServerOptions.Metrics</c> before building the server, e.g.
/// <code>options.Metrics = new OpenTelemetrySmbServerMetrics();</code>
/// then wire the consumer's OTel pipeline with <c>.AddMeter("Smb.Server")</c> and
/// <c>.AddSource("Smb.Server")</c>. The base counters/snapshot keep working unchanged (health endpoint), so
/// this only <i>adds</i> a fan-out — nothing is lost.
/// </para>
/// </summary>
public class OpenTelemetrySmbServerMetrics : SmbServerMetrics, IDisposable
{
    /// <summary>Name of both the <see cref="ActivitySource"/> and the <see cref="Meter"/> this bridge emits to.</summary>
    public const string SourceName = "Smb.Server";

    /// <summary>Version tag applied to the emitted <see cref="ActivitySource"/> / <see cref="Meter"/>.</summary>
    public const string Version = "1.0.0";

    private readonly Meter _meter;
    private readonly ActivitySource _activitySource;

    private readonly Counter<long> _connectionsAccepted;
    private readonly Counter<long> _authSuccess;
    private readonly Counter<long> _authFailure;
    private readonly Counter<long> _requests;
    private readonly Counter<long> _bytesRead;
    private readonly Counter<long> _bytesWritten;
    private readonly Counter<long> _lockContention;
    private readonly Counter<long> _oplockBreaksSent;
    private readonly Counter<long> _oplockBreakTimeouts;
    private readonly Histogram<double> _requestDuration;
    private readonly Histogram<double> _commandDuration;

    public OpenTelemetrySmbServerMetrics()
    {
        _meter = new Meter(SourceName, Version);
        _activitySource = new ActivitySource(SourceName, Version);

        _connectionsAccepted = _meter.CreateCounter<long>("smb.connections.accepted", unit: "{connection}", description: "TCP connections accepted.");
        _authSuccess = _meter.CreateCounter<long>("smb.auth.success", unit: "{attempt}", description: "Successful authentications.");
        _authFailure = _meter.CreateCounter<long>("smb.auth.failure", unit: "{attempt}", description: "Failed authentications.");
        _requests = _meter.CreateCounter<long>("smb.requests", unit: "{request}", description: "SMB2 requests processed (one per inbound message, compound counted once).");
        _bytesRead = _meter.CreateCounter<long>("smb.bytes.read", unit: "By", description: "Bytes read from shares.");
        _bytesWritten = _meter.CreateCounter<long>("smb.bytes.written", unit: "By", description: "Bytes written to shares.");
        _lockContention = _meter.CreateCounter<long>("smb.lock.contention", unit: "{event}", description: "Byte-range lock / sharing conflicts observed.");
        _oplockBreaksSent = _meter.CreateCounter<long>("smb.oplock.breaks_sent", unit: "{break}", description: "Oplock/lease breaks sent that require an acknowledgment.");
        _oplockBreakTimeouts = _meter.CreateCounter<long>("smb.oplock.break_timeouts", unit: "{break}", description: "Breaks whose acknowledgment did not arrive within the break timeout.");
        _requestDuration = _meter.CreateHistogram<double>("smb.request.duration", unit: "ms", description: "Wall-clock time to process an inbound SMB2 message.");
        _commandDuration = _meter.CreateHistogram<double>("smb.command.duration", unit: "ms", description: "Wall-clock time to dispatch a single SMB2 command.");

        // Gauges observe the base class's live Interlocked counters — no extra state to keep in sync.
        _meter.CreateObservableUpDownCounter("smb.connections.active", () => ActiveConnections, unit: "{connection}", description: "Currently open connections.");
        _meter.CreateObservableUpDownCounter("smb.sessions.active", () => ActiveSessions, unit: "{session}", description: "Currently authenticated sessions.");
        _meter.CreateObservableUpDownCounter("smb.tree_connects.active", () => ActiveTreeConnects, unit: "{tree}", description: "Currently connected trees.");
        _meter.CreateObservableUpDownCounter("smb.handles.open", () => OpenHandles, unit: "{handle}", description: "Currently open file handles.");
        // [W1.3] The gauge W0.3 asked for: a break outstanding here is a CREATE parked behind it. A value
        // that stays above zero is "the file sticks" made measurable.
        _meter.CreateObservableUpDownCounter("smb.oplock.pending_breaks", () => PendingBreaks, unit: "{break}", description: "Breaks sent and not yet acknowledged.");
    }

    public override void OnConnectionAccepted()
    {
        base.OnConnectionAccepted();
        _connectionsAccepted.Add(1);
    }

    public override void OnAuthenticationSucceeded()
    {
        base.OnAuthenticationSucceeded();
        _authSuccess.Add(1);
    }

    public override void OnAuthenticationFailed()
    {
        base.OnAuthenticationFailed();
        _authFailure.Add(1);
    }

    public override void OnLockContention()
    {
        base.OnLockContention();
        _lockContention.Add(1);
    }

    public override void OnOplockBreakSent()
    {
        base.OnOplockBreakSent();
        _oplockBreaksSent.Add(1);
    }

    public override void OnOplockBreakResolved(bool timedOut)
    {
        base.OnOplockBreakResolved(timedOut);
        if (timedOut) _oplockBreakTimeouts.Add(1);
    }

    public override void OnRequestCompleted(double milliseconds)
    {
        base.OnRequestCompleted(milliseconds);
        _requests.Add(1);
        _requestDuration.Record(milliseconds);
    }

    public override void OnBytesRead(string share, long count)
    {
        base.OnBytesRead(share, count);
        _bytesRead.Add(count, new KeyValuePair<string, object?>("smb.share", share));
    }

    public override void OnBytesWritten(string share, long count)
    {
        base.OnBytesWritten(share, count);
        _bytesWritten.Add(count, new KeyValuePair<string, object?>("smb.share", share));
    }

    public override ISmbCommandTrace? BeginCommand(SmbCommand command)
        => new CommandTrace(this, command);

    /// <summary>
    /// A per-command tracing scope: opens an <see cref="Activity"/> span (if a listener is attached) and,
    /// on dispose, records the command's duration into the <c>smb.command.duration</c> histogram tagged with
    /// the command name and resulting NT status. The Activity is current across the handler's <c>await</c>, so
    /// any nested backend spans attach beneath it.
    /// </summary>
    private sealed class CommandTrace : ISmbCommandTrace
    {
        private readonly OpenTelemetrySmbServerMetrics _owner;
        private readonly SmbCommand _command;
        private readonly Activity? _activity;
        private readonly long _startTimestamp;
        private NtStatus _status = NtStatus.Success;

        public CommandTrace(OpenTelemetrySmbServerMetrics owner, SmbCommand command)
        {
            _owner = owner;
            _command = command;
            _startTimestamp = Stopwatch.GetTimestamp();
            _activity = owner._activitySource.StartActivity($"smb.{command}", ActivityKind.Server);
            _activity?.SetTag("smb.command", command.ToString());
        }

        public void SetStatus(NtStatus status) => _status = status;

        public void Dispose()
        {
            double ms = Stopwatch.GetElapsedTime(_startTimestamp).TotalMilliseconds;
            var commandTag = new KeyValuePair<string, object?>("smb.command", _command.ToString());
            var statusTag = new KeyValuePair<string, object?>("smb.status", _status.ToString());
            _owner._commandDuration.Record(ms, commandTag, statusTag);

            if (_activity is not null)
            {
                _activity.SetTag("smb.status", _status.ToString());
                // Treat any 0xC0000000-class code as an error span; informational/pending stay Unset.
                if (((uint)_status & 0xC0000000u) == 0xC0000000u)
                    _activity.SetStatus(ActivityStatusCode.Error, _status.ToString());
                _activity.Dispose();
            }
        }
    }

    public void Dispose()
    {
        _meter.Dispose();
        _activitySource.Dispose();
        GC.SuppressFinalize(this);
    }
}
