using Smb.Protocol.Enums;
using Smb.Server.State;

namespace Smb.Server.Oplocks;

/// <summary>
/// Ein fälliger Oplock-Break: Der <see cref="Holder"/> hält aktuell einen Oplock, der wegen eines
/// neuen, konfligierenden Zugriffs auf <see cref="NewLevel"/> herabgestuft werden muss. Der
/// Dispatcher verschickt daraufhin eine OPLOCK_BREAK-Notification an den Halter (Effect).
/// </summary>
public readonly record struct OplockBreak(SmbOpen Holder, OplockLevel NewLevel);

/// <summary>
/// Ergebnis einer Oplock-Anforderung beim CREATE: das tatsächlich gewährte Level plus die durch
/// diesen Open ausgelösten Breaks an <i>andere</i> Halter.
/// </summary>
public readonly record struct OplockGrant(OplockLevel GrantedLevel, IReadOnlyList<OplockBreak> Breaks)
{
    public static readonly OplockGrant None = new(OplockLevel.None, Array.Empty<OplockBreak>());
}

/// <summary>
/// <b>Einhak-Punkt für Oplocks (SMB2, Context §15, MS-SMB2 §3.3.5.9/§3.3.4.6).</b> Der Server
/// delegiert jede Oplock-Entscheidung hierher; die Default-Implementierung
/// <see cref="InMemoryOplockManager"/> verwaltet die gewährten Oplocks prozesslokal je Datei.
/// <para>
/// Die Schnittstelle ist <b>reiner Zustand</b> (Parse↔State↔Effect, Context §2): Sie <i>entscheidet</i>,
/// welche Breaks fällig sind, verschickt sie aber nicht — das übernimmt der Dispatcher out-of-band
/// über <see cref="SmbConnection.SendRawAsync"/>. So bleibt die Oplock-Policy frei von I/O und
/// testbar; eine eigene Implementierung kann sie z.B. an einen Cluster-Koordinator delegieren.
/// </para>
/// Verdrahtung: <c>SmbServerOptions.OplockManager</c>.
/// </summary>
public interface IOplockManager
{
    /// <summary>
    /// Registriert einen neuen Open und gewährt — abhängig von bereits offenen Handles derselben
    /// Datei — das passende Oplock-Level (MS-SMB2 §3.3.5.9). Konfligiert die Anforderung mit
    /// bestehenden Oplocks anderer Opens, enthält <see cref="OplockGrant.Breaks"/> die fälligen
    /// Herabstufungen; deren Halter werden vom Dispatcher benachrichtigt.
    /// </summary>
    OplockGrant RequestOplock(SmbOpen open, OplockLevel requested);

    /// <summary>
    /// Verarbeitet das OPLOCK_BREAK-Acknowledgment eines Clients (§3.3.5.22.1): der Halter bestätigt
    /// die Herabstufung seines Oplocks auf <paramref name="newLevel"/>. Liefert das nun gültige Level
    /// (in der Regel <paramref name="newLevel"/>) für die Antwort zurück.
    /// </summary>
    OplockLevel Acknowledge(SmbOpen open, OplockLevel newLevel);

    /// <summary>Gibt beim CLOSE den Oplock dieses Open frei (MS-SMB2 §3.3.5.10).</summary>
    void ReleaseOwner(SmbOpen open);
}

/// <summary>
/// <see cref="IOplockManager"/>, der nie einen Oplock gewährt — CREATE liefert stets
/// <see cref="OplockLevel.None"/>. Damit lassen sich Oplocks vollständig abschalten
/// (Verdrahtung: <c>SmbServerOptions.OplockManager = new NullOplockManager()</c>).
/// </summary>
public sealed class NullOplockManager : IOplockManager
{
    public OplockGrant RequestOplock(SmbOpen open, OplockLevel requested) => OplockGrant.None;
    public OplockLevel Acknowledge(SmbOpen open, OplockLevel newLevel) => OplockLevel.None;
    public void ReleaseOwner(SmbOpen open) { }
}
