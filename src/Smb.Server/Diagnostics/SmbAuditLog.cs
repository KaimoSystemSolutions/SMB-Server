using Smb.Protocol.Enums;

namespace Smb.Server.Diagnostics;

/// <summary>Severity of an audit event (mirrors the usual logging levels, ascending).</summary>
public enum SmbLogLevel
{
    Trace,
    Debug,
    Information,
    Warning,
    Error,
    Critical,
}

/// <summary>
/// Security-relevant server events (Phase 8 / M8.1). The numeric values echo the equivalent Windows
/// Security-log event IDs where one exists, so operators can map them onto familiar SIEM rules.
/// </summary>
public enum SmbAuditEventType
{
    /// <summary>A TCP connection was accepted.</summary>
    ConnectionAccepted = 1000,

    /// <summary>A TCP connection was closed / torn down.</summary>
    ConnectionClosed = 1001,

    /// <summary>A session authenticated successfully (≈ Windows 4624).</summary>
    AuthenticationSucceeded = 4624,

    /// <summary>An authentication attempt failed (≈ Windows 4625).</summary>
    AuthenticationFailed = 4625,

    /// <summary>A session logged off / was torn down (≈ Windows 4634).</summary>
    SessionLogoff = 4634,

    /// <summary>A file handle was closed (≈ Windows 4658).</summary>
    FileClosed = 4658,

    /// <summary>An object (file) was deleted (≈ Windows 4660).</summary>
    FileDeleted = 4660,

    /// <summary>A security descriptor / permission was changed (≈ Windows 4670).</summary>
    PermissionChanged = 4670,

    /// <summary>Access to a share was granted at TREE_CONNECT (≈ Windows 5140).</summary>
    ShareAccessGranted = 5140,

    /// <summary>Access to a share was denied at TREE_CONNECT (≈ Windows 5143).</summary>
    ShareAccessDenied = 5143,

    /// <summary>A file was opened (≈ Windows 5145 detailed file-share access).</summary>
    FileOpened = 5145,
}

/// <summary>
/// A single structured audit record. A value type so emitting one allocates nothing beyond the fields
/// the caller already holds; <see cref="ISmbAuditLogger.Log"/> takes it by <c>in</c> reference.
/// </summary>
public readonly record struct SmbAuditEvent
{
    /// <summary>What happened.</summary>
    public required SmbAuditEventType EventType { get; init; }

    /// <summary>Severity.</summary>
    public SmbLogLevel Level { get; init; }

    /// <summary>When it happened (from the server's <c>TimeProvider</c>).</summary>
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>Authenticated principal (<c>DOMAIN\user</c> or UPN), if known.</summary>
    public string? User { get; init; }

    /// <summary>Remote client endpoint (<c>ip:port</c>), if known.</summary>
    public string? ClientAddress { get; init; }

    /// <summary>Share name, for share/file events.</summary>
    public string? Share { get; init; }

    /// <summary>File path (share-relative), for file events.</summary>
    public string? Path { get; init; }

    /// <summary>Result status of the operation.</summary>
    public NtStatus Status { get; init; }

    /// <summary>Optional free-text detail.</summary>
    public string? Message { get; init; }

    /// <summary>The numeric event id (see <see cref="SmbAuditEventType"/>).</summary>
    public int EventId => (int)EventType;

    /// <summary>A single-line, structured rendering suitable for a text log sink.</summary>
    public override string ToString()
    {
        var sb = new System.Text.StringBuilder(128);
        sb.Append(Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz"))
          .Append(" [").Append(Level).Append("] ")
          .Append(EventId).Append(' ').Append(EventType);
        if (User is not null) sb.Append(" user=").Append(User);
        if (ClientAddress is not null) sb.Append(" client=").Append(ClientAddress);
        if (Share is not null) sb.Append(" share=").Append(Share);
        if (Path is not null) sb.Append(" path=").Append(Path);
        if (Status != NtStatus.Success) sb.Append(" status=").Append(Status);
        if (Message is not null) sb.Append(" msg=").Append(Message);
        return sb.ToString();
    }
}

/// <summary>
/// Structured audit-logging seam (Phase 8 / M8.1). Deliberately dependency-free so the core forces no
/// logging framework on consumers; adapt it to <c>Microsoft.Extensions.Logging</c>, Serilog, a SIEM
/// pipeline, etc. with a thin implementation. The default is <see cref="NullSmbAuditLogger"/> (off).
/// </summary>
public interface ISmbAuditLogger
{
    /// <summary>True if events at <paramref name="level"/> would be recorded (lets callers skip work).</summary>
    bool IsEnabled(SmbLogLevel level);

    /// <summary>Records an audit event. Implementations must be thread-safe (called from many connections).</summary>
    void Log(in SmbAuditEvent auditEvent);
}

/// <summary>No-op audit logger (default). Reports every level disabled so callers short-circuit.</summary>
public sealed class NullSmbAuditLogger : ISmbAuditLogger
{
    public static readonly NullSmbAuditLogger Instance = new();
    private NullSmbAuditLogger() { }
    public bool IsEnabled(SmbLogLevel level) => false;
    public void Log(in SmbAuditEvent auditEvent) { }
}

/// <summary>
/// Forwards audit events at or above <see cref="MinLevel"/> to a callback — the simplest way to wire
/// the seam to a real sink (e.g. <c>evt =&gt; logger.Log(evt)</c> or a console writer).
/// </summary>
public sealed class DelegatingSmbAuditLogger : ISmbAuditLogger
{
    private readonly Action<SmbAuditEvent> _sink;

    public DelegatingSmbAuditLogger(Action<SmbAuditEvent> sink, SmbLogLevel minLevel = SmbLogLevel.Information)
    {
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        MinLevel = minLevel;
    }

    /// <summary>Lowest level that is forwarded.</summary>
    public SmbLogLevel MinLevel { get; }

    public bool IsEnabled(SmbLogLevel level) => level >= MinLevel;

    public void Log(in SmbAuditEvent auditEvent)
    {
        if (IsEnabled(auditEvent.Level))
            _sink(auditEvent);
    }
}
