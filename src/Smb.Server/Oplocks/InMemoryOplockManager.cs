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
/// This covers the core mechanics (Grant → Break → Acknowledge → Release).
/// <para>
/// <b>Waiting for the acknowledgment is not this class's job</b> (and, since W1, happens): the dispatcher
/// parks the conflicting CREATE behind every break this manager reports until the holder acknowledges or
/// the break times out (<c>SmbServerOptions.OplockBreakTimeout</c>, §3.3.5.9.8). Note the split that
/// implies: the state here is downgraded <i>eagerly</i>, when the break is decided — the wait is about the
/// holder's client-side dirty data, not about this dictionary. A custom manager inherits that behaviour by
/// simply reporting its breaks.
/// </para>
/// <para>Still intentionally not modelled: breaking Level II to None on a writing second access.</para>
/// </summary>
public sealed class InMemoryOplockManager : IOplockManager
{
    private readonly object _gate = new();
    private readonly Dictionary<string, FileOplockState> _files = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// open → the file key it was registered under. Captured at grant and used at Acknowledge/Release —
    /// <b>never recomputed</b>. <see cref="FileKey"/> reads the open's backend physical path, which a rename
    /// relocates in place (<c>IFileHandle.Relocate</c>); recomputing the key at release then looks under the
    /// NEW name and leaves the holder registered under the OLD one. That leaked holder is a phantom every
    /// later open reusing the original name breaks — and it can never acknowledge, so the triggering CREATE
    /// parks for the whole break timeout (the PowerPoint-save / shortcut-wizard freeze, measured
    /// 2026-07-17). The lease manager avoids this the same way, via <c>LeaseHolder.FileKey</c>.
    /// </summary>
    private readonly Dictionary<SmbOpen, string> _openKeys = new();

    public OplockGrant RequestOplock(SmbOpen open, OplockLevel requested)
    {
        // Only handle classic oplocks. A lease (0xFF) is requested through a CREATE context and served by
        // ILeaseManager instead (see InMemoryLeaseManager) — the two are mutually exclusive per open, so
        // there is no oplock to grant here.
        if (requested is not (OplockLevel.LevelII or OplockLevel.Exclusive or OplockLevel.Batch))
            return OplockGrant.None;

        string key = FileKey(open);
        lock (_gate)
        {
            FileOplockState state = GetOrAdd(key);
            _openKeys[open] = key;   // remember where this open lives, so a later rename can't strand it

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
            if (!_openKeys.TryGetValue(open, out string? key) || !_files.TryGetValue(key, out FileOplockState? state))
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
        lock (_gate)
        {
            // Release under the key the open was registered with (see _openKeys) — not FileKey(open), which
            // a rename may have moved out from under it.
            if (!_openKeys.Remove(open, out string? key) || !_files.TryGetValue(key, out FileOplockState? state))
                return;
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
