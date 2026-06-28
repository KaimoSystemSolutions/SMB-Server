namespace Smb.Server.Notification;

/// <summary>Which changes a CHANGE_NOTIFY observes (= SMB2 CompletionFilter, MS-SMB2 §2.2.35).</summary>
[Flags]
public enum ChangeNotifyFilter : uint
{
    None = 0,
    FileName = 0x00000001,
    DirName = 0x00000002,
    Attributes = 0x00000004,
    Size = 0x00000008,
    LastWrite = 0x00000010,
    LastAccess = 0x00000020,
    Creation = 0x00000040,
    Ea = 0x00000080,
    Security = 0x00000100,
    StreamName = 0x00000200,
    StreamSize = 0x00000400,
    StreamWrite = 0x00000800,
}

/// <summary>Type of a directory change (FILE_NOTIFY_INFORMATION Action, MS-FSCC §2.7.1).</summary>
public enum FileNotifyAction : uint
{
    Added = 1,
    Removed = 2,
    Modified = 3,
    RenamedOldName = 4,
    RenamedNewName = 5,
}

/// <summary>A single observed change (name relative to the watched directory, '\'-separated).</summary>
public readonly record struct FileNotifyEvent(FileNotifyAction Action, string RelativeName);

/// <summary>
/// <b>CHANGE_NOTIFY seam (Context §16).</b> Delivers directory changes to the server.
/// Default <see cref="FileSystemDirectoryWatcher"/> (based on
/// <see cref="System.IO.FileSystemWatcher"/>); a custom implementation can attach to inotify,
/// ZFS events, or a distributed change bus. Wiring:
/// <c>SmbServerBuilder.UseDirectoryWatcher(...)</c>.
/// </summary>
public interface IDirectoryWatcher
{
    /// <summary>
    /// Begins watching <paramref name="directoryFullPath"/>. When matching changes occur,
    /// <paramref name="onChanges"/> is called with one or more events. Returns an
    /// <see cref="IDisposable"/> to stop watching — or <c>null</c> if this path cannot be
    /// watched (in which case the server responds with <c>STATUS_NOT_SUPPORTED</c>).
    /// </summary>
    IDisposable? Watch(
        string directoryFullPath, bool watchSubtree, ChangeNotifyFilter filter,
        Action<IReadOnlyList<FileNotifyEvent>> onChanges);
}

/// <summary>Default: watches real directories via <see cref="FileSystemWatcher"/>.</summary>
public sealed class FileSystemDirectoryWatcher : IDirectoryWatcher
{
    public IDisposable? Watch(
        string directoryFullPath, bool watchSubtree, ChangeNotifyFilter filter,
        Action<IReadOnlyList<FileNotifyEvent>> onChanges)
    {
        if (string.IsNullOrEmpty(directoryFullPath) || !Directory.Exists(directoryFullPath))
            return null;

        FileSystemWatcher? w = null;
        try
        {
            string root = Path.GetFullPath(directoryFullPath);
            w = new FileSystemWatcher(root)
            {
                IncludeSubdirectories = watchSubtree,
                NotifyFilter = MapFilter(filter),
            };

            void Emit(FileNotifyAction action, string fullPath)
                => onChanges([new FileNotifyEvent(action, Relative(root, fullPath))]);

            w.Created += (_, e) => Emit(FileNotifyAction.Added, e.FullPath);
            w.Deleted += (_, e) => Emit(FileNotifyAction.Removed, e.FullPath);
            w.Changed += (_, e) => Emit(FileNotifyAction.Modified, e.FullPath);
            w.Renamed += (_, e) => onChanges(
            [
                new FileNotifyEvent(FileNotifyAction.RenamedOldName, Relative(root, e.OldFullPath)),
                new FileNotifyEvent(FileNotifyAction.RenamedNewName, Relative(root, e.FullPath)),
            ]);

            w.EnableRaisingEvents = true;
            return w;
        }
        catch
        {
            w?.Dispose();
            return null;
        }
    }

    private static NotifyFilters MapFilter(ChangeNotifyFilter f)
    {
        NotifyFilters n = 0;
        if (f.HasFlag(ChangeNotifyFilter.FileName)) n |= NotifyFilters.FileName;
        if (f.HasFlag(ChangeNotifyFilter.DirName)) n |= NotifyFilters.DirectoryName;
        if (f.HasFlag(ChangeNotifyFilter.Attributes)) n |= NotifyFilters.Attributes;
        if (f.HasFlag(ChangeNotifyFilter.Size)) n |= NotifyFilters.Size;
        if (f.HasFlag(ChangeNotifyFilter.LastWrite)) n |= NotifyFilters.LastWrite;
        if (f.HasFlag(ChangeNotifyFilter.LastAccess)) n |= NotifyFilters.LastAccess;
        if (f.HasFlag(ChangeNotifyFilter.Creation)) n |= NotifyFilters.CreationTime;
        if (f.HasFlag(ChangeNotifyFilter.Security)) n |= NotifyFilters.Security;
        // Default if no (known) bits are set.
        return n == 0 ? NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite : n;
    }

    private static string Relative(string root, string fullPath)
        => Path.GetRelativePath(root, fullPath).Replace('/', '\\');
}

/// <summary>Watcher that watches nothing — CHANGE_NOTIFY becomes <c>STATUS_NOT_SUPPORTED</c>.</summary>
public sealed class NullDirectoryWatcher : IDirectoryWatcher
{
    public IDisposable? Watch(
        string directoryFullPath, bool watchSubtree, ChangeNotifyFilter filter,
        Action<IReadOnlyList<FileNotifyEvent>> onChanges) => null;
}
