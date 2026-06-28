using Smb.Server.Locking;
using Smb.Server.State;

namespace Smb.Sample.Server;

/// <summary>
/// <b>Example: plugging custom byte-range lock management into the library.</b>
/// <para>
/// The library only defines the seam <see cref="ILockManager"/> and ships with
/// <c>InMemoryLockManager</c> as a process-local default. Whoever needs more implements
/// the interface and wires it via <c>SmbServerBuilder.UseLockManager(...)</c> — nothing in
/// the core needs to be changed. Typical reasons for a custom implementation:
/// </para>
/// <list type="bullet">
///   <item>persistent <b>audit trail</b> of all locks (what this demo does),</item>
///   <item>delegation to the <b>OS</b> (<c>FileStream.Lock</c> on the real path
///         <see cref="SmbOpen.LocalOpen"/>.Path) — then other processes or NFS also see
///         the lock (cross-protocol locking, relevant e.g. under TrueNAS),</item>
///   <item>coordination via a <b>cluster</b> (distributed lock table).</item>
/// </list>
/// <para>
/// Intentionally built as a <b>decorator</b>: the actual conflict/waiting logic stays with
/// the inner manager (default in-memory); this wrapper only adds the cross-cutting concern
/// of auditing. That way you don't have to re-implement the (subtle) lock semantics just
/// to add your own aspects.
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
            Audit($"{(forWrite ? "WRITE" : "READ")} denied (lock conflict): {Key(owner)} [{offset}..{offset + length}]");
        return ok;
    }

    public void ReleaseOwner(SmbOpen owner)
    {
        _inner.ReleaseOwner(owner);
        Audit($"RELEASE {Key(owner)} (handle closed)");
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
