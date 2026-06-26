using Smb.Protocol.Enums;
using Smb.Server.State;

namespace Smb.Server.Oplocks;

/// <summary>
/// Prozesslokaler Default-<see cref="IOplockManager"/>: verwaltet die gewährten Oplocks in-memory,
/// gruppiert pro Datei (Schlüssel = realer Backend-Pfad des Open, identisch zum
/// <see cref="Locking.InMemoryLockManager"/>). Die Granting-Policy ist bewusst konservativ:
/// <list type="bullet">
/// <item>Ein <b>einzelner</b> Open auf eine Datei erhält den angeforderten Oplock — auch
/// Exclusive/Batch.</item>
/// <item>Sobald ein <b>weiterer</b> Open dieselbe Datei öffnet, brechen gehaltene Exclusive/Batch-
/// Oplocks auf <see cref="OplockLevel.LevelII"/> (Read-Caching bleibt); der neue Open erhält selbst
/// höchstens Level II.</item>
/// </list>
/// Damit ist die Kern-Mechanik (Grant → Break → Acknowledge → Release) abgebildet. Bewusst <i>nicht</i>
/// modelliert sind das Brechen von Level II auf None bei schreibendem Zweitzugriff sowie das Warten
/// auf das Acknowledgment, bevor der konfligierende Zugriff fortfährt — beides bleibt einem späteren
/// Schliff vorbehalten (siehe README-Roadmap).
/// </summary>
public sealed class InMemoryOplockManager : IOplockManager
{
    private readonly object _gate = new();
    private readonly Dictionary<string, FileOplockState> _files = new(StringComparer.OrdinalIgnoreCase);

    public OplockGrant RequestOplock(SmbOpen open, OplockLevel requested)
    {
        // Nur klassische Oplocks behandeln; ein Lease (0xFF) läuft über CREATE-Contexts und ist
        // (noch) nicht implementiert → kein Oplock.
        if (requested is not (OplockLevel.LevelII or OplockLevel.Exclusive or OplockLevel.Batch))
            return OplockGrant.None;

        string key = FileKey(open);
        lock (_gate)
        {
            FileOplockState state = GetOrAdd(key);

            if (state.Holders.Count == 0)
            {
                // Solo-Open: bekommt das angeforderte Level (auch Exclusive/Batch).
                state.Holders.Add(new Holder(open, requested));
                return new OplockGrant(requested, Array.Empty<OplockBreak>());
            }

            // Weiterer Open auf dieselbe Datei: gehaltene Exclusive/Batch-Oplocks müssen auf Level II
            // herabbrechen. Ein exklusiver Oplock wird bei Mehrfach-Open nicht (mehr) gewährt.
            var breaks = new List<OplockBreak>();
            foreach (Holder h in state.Holders)
            {
                if (h.Level is OplockLevel.Exclusive or OplockLevel.Batch)
                {
                    h.Level = OplockLevel.LevelII;
                    breaks.Add(new OplockBreak(h.Open, OplockLevel.LevelII));
                }
            }

            state.Holders.Add(new Holder(open, OplockLevel.LevelII));
            return new OplockGrant(OplockLevel.LevelII, breaks);
        }
    }

    public OplockLevel Acknowledge(SmbOpen open, OplockLevel newLevel)
    {
        lock (_gate)
        {
            if (!_files.TryGetValue(FileKey(open), out FileOplockState? state))
                return OplockLevel.None;

            foreach (Holder h in state.Holders)
            {
                if (ReferenceEquals(h.Open, open))
                {
                    h.Level = newLevel;   // Ein Acknowledgment stuft nur herab; der Client bestimmt das Ziel-Level.
                    return h.Level;
                }
            }
            return OplockLevel.None;
        }
    }

    public void ReleaseOwner(SmbOpen open)
    {
        string key = FileKey(open);
        lock (_gate)
        {
            if (!_files.TryGetValue(key, out FileOplockState? state)) return;
            state.Holders.RemoveAll(h => ReferenceEquals(h.Open, open));
            if (state.Holders.Count == 0)
                _files.Remove(key);
        }
    }

    // --- intern ---

    private FileOplockState GetOrAdd(string key)
    {
        if (!_files.TryGetValue(key, out FileOplockState? state))
            _files[key] = state = new FileOplockState();
        return state;
    }

    private static string FileKey(SmbOpen open) => open.LocalOpen?.PhysicalPath ?? open.PathName;

    private sealed class Holder(SmbOpen open, OplockLevel level)
    {
        public SmbOpen Open { get; } = open;
        public OplockLevel Level { get; set; } = level;
    }

    private sealed class FileOplockState
    {
        public List<Holder> Holders { get; } = new();
    }
}
