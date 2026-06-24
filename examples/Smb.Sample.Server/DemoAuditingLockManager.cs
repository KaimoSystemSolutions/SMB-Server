using Smb.Server.Locking;
using Smb.Server.State;

namespace Smb.Sample.Server;

/// <summary>
/// <b>Beispiel: eigene Byte-Range-Lock-Verwaltung in die Lib einklinken.</b>
/// <para>
/// Die Lib gibt nur die Naht <see cref="ILockManager"/> vor und liefert mit
/// <c>InMemoryLockManager</c> einen prozesslokalen Default. Wer mehr braucht, implementiert das
/// Interface selbst und verdrahtet es über <c>SmbServerBuilder.UseLockManager(...)</c> — nichts am
/// Core muss angefasst werden. Typische Gründe für eine eigene Implementierung:
/// </para>
/// <list type="bullet">
///   <item>persistenter <b>Audit-Trail</b> aller Sperren (das macht diese Demo),</item>
///   <item>Delegation ans <b>Betriebssystem</b> (<c>FileStream.Lock</c> auf den realen Pfad
///         <see cref="SmbOpen.LocalOpen"/>.Path) — dann sehen auch andere Prozesse bzw. NFS die
///         Sperre (Cross-Protocol-Locking, relevant z.B. unter TrueNAS),</item>
///   <item>Koordination über einen <b>Cluster</b> (verteilte Lock-Tabelle).</item>
/// </list>
/// <para>
/// Bewusst als <b>Decorator</b> gebaut: Die eigentliche Konflikt-/Warte-Logik bleibt beim inneren
/// Manager (Default In-Memory), dieser Wrapper ergänzt nur den Querschnittsaspekt „Auditing". So
/// muss man die (subtile) Lock-Semantik nicht neu erfinden, um eigene Aspekte zu ergänzen.
/// </para>
/// </summary>
public sealed class DemoAuditingLockManager : ILockManager
{
    private readonly ILockManager _inner;
    private readonly string _auditFile;
    private readonly Action<string>? _log;
    private readonly object _fileGate = new();

    public DemoAuditingLockManager(string auditFile, ILockManager? inner = null, Action<string>? log = null)
    {
        _inner = inner ?? new InMemoryLockManager();
        _auditFile = Path.GetFullPath(auditFile);
        _log = log;
        Directory.CreateDirectory(Path.GetDirectoryName(_auditFile)!);
    }

    public async Task<LockOutcome> ApplyAsync(
        SmbOpen owner, IReadOnlyList<LockElement> elements, bool failImmediately, CancellationToken ct)
    {
        bool unlock = elements.Count > 0 && elements[0].Unlock;
        LockOutcome outcome = await _inner.ApplyAsync(owner, elements, failImmediately, ct).ConfigureAwait(false);
        Audit($"{(unlock ? "UNLOCK" : "LOCK")} {Describe(owner, elements)} → {outcome}");
        return outcome;
    }

    public bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool forWrite)
    {
        bool ok = _inner.IsRangeAccessible(owner, offset, length, forWrite);
        if (!ok)
            Audit($"{(forWrite ? "WRITE" : "READ")} abgewiesen (Lock-Konflikt): {Key(owner)} [{offset}..{offset + length}]");
        return ok;
    }

    public void ReleaseOwner(SmbOpen owner)
    {
        _inner.ReleaseOwner(owner);
        Audit($"RELEASE {Key(owner)} (Handle geschlossen)");
    }

    private void Audit(string message)
    {
        string line = $"{DateTime.UtcNow:O}  {message}";
        _log?.Invoke(line);
        lock (_fileGate)
            File.AppendAllText(_auditFile, line + Environment.NewLine);
    }

    private static string Describe(SmbOpen owner, IReadOnlyList<LockElement> elements)
    {
        var parts = new List<string>(elements.Count);
        foreach (LockElement l in elements)
            parts.Add($"[{l.Offset}..{l.Offset + l.Length}{(l.Exclusive ? " excl" : " shared")}]");
        return $"{Key(owner)} {string.Join(",", parts)}";
    }

    private static string Key(SmbOpen owner) => owner.LocalOpen?.PhysicalPath ?? owner.PathName;
}
