using Smb.Server.State;

namespace Smb.Server.Locking;

/// <summary>Ein normalisiertes Byte-Range-Lock-/Unlock-Element (aus dem LOCK-Request abgeleitet).</summary>
public readonly record struct LockElement(ulong Offset, ulong Length, bool Exclusive, bool Unlock);

/// <summary>Ergebnis einer Lock-/Unlock-Anforderung (mappt 1:1 auf NTSTATUS im Dispatcher).</summary>
public enum LockOutcome
{
    /// <summary>Alle Elemente gewährt bzw. freigegeben → <c>STATUS_SUCCESS</c>.</summary>
    Granted,
    /// <summary>Bereich kollidiert mit einem Lock eines anderen Open → <c>STATUS_LOCK_NOT_GRANTED</c>.</summary>
    Conflict,
    /// <summary>Unlock eines nicht gehaltenen Bereichs → <c>STATUS_RANGE_NOT_LOCKED</c>.</summary>
    RangeNotLocked,
    /// <summary>Ein wartender (blockierender) Lock wurde via CANCEL/Close abgebrochen → <c>STATUS_CANCELLED</c>.</summary>
    Cancelled,
}

/// <summary>
/// <b>Einhak-Punkt für Byte-Range-Locking (SMB2 LOCK, Context §15).</b> Der Server delegiert
/// jede Sperr-Entscheidung hierher; die Default-Implementierung <see cref="InMemoryLockManager"/>
/// hält die Locks prozesslokal. Eine eigene Implementierung kann das Locking z.B. an das
/// Betriebssystem (<c>FileStream.Lock</c>) oder einen Cluster-Koordinator delegieren — relevant,
/// wenn dieselbe Datei auch über andere Protokolle (NFS, lokal) gesperrt werden soll.
/// Verdrahtung: <c>SmbServerBuilder.UseLockManager(...)</c>.
/// </summary>
public interface ILockManager
{
    /// <summary>
    /// Nimmt (oder gibt frei) alle Elemente eines LOCK-Requests <b>atomar</b> für ein Open
    /// (MS-SMB2 §3.3.5.14). Die Elemente sind entweder ausschließlich Locks oder ausschließlich
    /// Unlocks (vom Aufrufer geprüft).
    /// <para>
    /// Kann ein einzelnes Lock nicht sofort gewährt werden und <paramref name="failImmediately"/>
    /// ist <c>false</c>, läuft der zurückgegebene Task <b>asynchron weiter</b>, bis der Bereich
    /// frei wird (→ <see cref="LockOutcome.Granted"/>) oder <paramref name="ct"/> ausgelöst wird
    /// (CANCEL/Close → <see cref="LockOutcome.Cancelled"/>). Bei sofortiger Entscheidung ist der
    /// Task bereits abgeschlossen (synchroner Schnellpfad).
    /// </para>
    /// </summary>
    Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> elements, bool failImmediately, CancellationToken ct);

    /// <summary>
    /// Schneller, nie blockierender Konflikt-Check für READ/WRITE (MS-SMB2 §3.3.5.10/§3.3.5.12):
    /// Ist der Bereich aus Sicht von <paramref name="owner"/> zugreifbar? <paramref name="forWrite"/>
    /// =true prüft auch gegen <i>shared</i> Locks anderer Opens, =false nur gegen exklusive.
    /// Eigene Locks des <paramref name="owner"/> blockieren dessen eigenen Zugriff nie.
    /// </summary>
    bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool forWrite);

    /// <summary>
    /// Gibt beim CLOSE alle Locks dieses Open frei und weckt dadurch evtl. wartende Locks
    /// anderer Opens (MS-SMB2 §3.3.5.10: Close gibt alle Locks frei).
    /// </summary>
    void ReleaseOwner(SmbOpen owner);
}
