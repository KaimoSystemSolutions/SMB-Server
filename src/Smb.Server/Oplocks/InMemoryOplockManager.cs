using Smb.Protocol.Enums;
using Smb.Server.State;

namespace Smb.Server.Oplocks;

/// <summary>
/// Process-local default <see cref="IOplockManager"/>: manages granted oplocks in memory,
/// grouped per file (key = actual backend path of the open, identical to
/// <see cref="Locking.InMemoryLockManager"/>). The granting policy is intentionally conservative:
/// <list type="bullet">
/// <item>A <b>single</b> open on a file receives the requested oplock level — including
/// Exclusive/Batch.</item>
/// <item>Once a <b>second</b> open accesses the same file, held Exclusive/Batch oplocks break
/// down to <see cref="OplockLevel.LevelII"/> (read caching is preserved); the new open receives
/// at most Level II itself.</item>
/// </list>
/// This covers the core mechanics (Grant → Break → Acknowledge → Release). Intentionally <i>not</i>
/// modelled: breaking Level II to None on a writing second access, and waiting for the
/// acknowledgment before the conflicting access proceeds — both are deferred to a later pass
/// (see README roadmap).
/// </summary>
public sealed class InMemoryOplockManager : IOplockManager
{
    private readonly object _gate = new();
    private readonly Dictionary<string, FileOplockState> _files = new(StringComparer.OrdinalIgnoreCase);

    public OplockGrant RequestOplock(SmbOpen open, OplockLevel requested)
    {
        // Only handle classic oplocks; a lease (0xFF) goes via CREATE contexts and is
        // not yet implemented → no oplock.
        if (requested is not (OplockLevel.LevelII or OplockLevel.Exclusive or OplockLevel.Batch))
            return OplockGrant.None;

        string key = FileKey(open);
        lock (_gate)
        {
            FileOplockState state = GetOrAdd(key);

            if (state.Holders.Count == 0)
            {
                // Solo open: receives the requested level (including Exclusive/Batch).
                state.Holders.Add(new Holder(open, requested));
                return new OplockGrant(requested, Array.Empty<OplockBreak>());
            }

            // Another open on the same file: held Exclusive/Batch oplocks must break to Level II.
            // An exclusive oplock is no longer granted with multiple opens.
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
                    h.Level = newLevel;   // An acknowledgment only downgrades; the client determines the target level.
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

    // --- internal ---

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
