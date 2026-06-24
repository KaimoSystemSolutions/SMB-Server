namespace Smb.FileSystem.Versioning;

/// <summary>
/// Ein <see cref="IFileStore"/>, der frühere Datei-Versionen als Snapshots vorhält und sie
/// für <c>FSCTL_SRV_ENUMERATE_SNAPSHOTS</c> (MS-SMB2 §2.2.32.2) sowie <c>@GMT-…</c>-Pfade
/// bereitstellt. Die Zeitpunkte sind UTC und werden vom Server in <c>@GMT-…</c>-Token formatiert.
/// </summary>
public interface ISnapshotStore
{
    /// <summary>
    /// Snapshot-Zeitpunkte (UTC, aufsteigend) für einen share-relativen Pfad. Ein leerer Pfad
    /// (bzw. die Share-Wurzel) liefert die Vereinigung aller Snapshots (<see cref="GetAllSnapshots"/>).
    /// </summary>
    IReadOnlyList<DateTime> GetSnapshots(string path);

    /// <summary>Alle bekannten Snapshot-Zeitpunkte über alle Dateien (UTC, aufsteigend, dedupliziert).</summary>
    IReadOnlyList<DateTime> GetAllSnapshots();
}
