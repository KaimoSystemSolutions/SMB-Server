using Smb.FileSystem;

namespace Smb.Server.Sharing;

/// <summary>
/// Process-local default <see cref="IShareModeManager"/>. Holds the open registrations per file and
/// applies the Windows sharing-compatibility rule <b>symmetrically</b>: a new open N and an existing
/// open E can coexist iff N's access is permitted by E's share mode AND E's access is permitted by
/// N's share mode (MS-SMB2 §3.3.5.9). The key is the share-scoped logical path supplied by the
/// dispatcher (so two opens of the same path conflict regardless of session/connection).
/// </summary>
public sealed class InMemoryShareModeManager : IShareModeManager
{
    private readonly object _gate = new();
    private readonly Dictionary<string, List<Entry>> _files = new(StringComparer.Ordinal);

    public bool TryOpen(string fileKey, object owner, FileAccessIntent access, FileShareMode share)
    {
        lock (_gate)
        {
            if (_files.TryGetValue(fileKey, out List<Entry>? list))
            {
                foreach (Entry e in list)
                    if (!Compatible(access, e.Share) || !Compatible(e.Access, share))
                        return false;
            }
            else
            {
                _files[fileKey] = list = new List<Entry>();
            }
            list.Add(new Entry(owner, access, share));
            return true;
        }
    }

    public void Close(string fileKey, object owner)
    {
        lock (_gate)
        {
            if (!_files.TryGetValue(fileKey, out List<Entry>? list)) return;
            list.RemoveAll(e => ReferenceEquals(e.Owner, owner));
            if (list.Count == 0) _files.Remove(fileKey);
        }
    }

    /// <summary>An access intent is compatible with a share mode iff every requested right is shared.</summary>
    private static bool Compatible(FileAccessIntent access, FileShareMode share)
        => (!access.HasFlag(FileAccessIntent.Read)   || share.HasFlag(FileShareMode.Read))
        && (!access.HasFlag(FileAccessIntent.Write)  || share.HasFlag(FileShareMode.Write))
        && (!access.HasFlag(FileAccessIntent.Delete) || share.HasFlag(FileShareMode.Delete));

    private readonly record struct Entry(object Owner, FileAccessIntent Access, FileShareMode Share);
}
