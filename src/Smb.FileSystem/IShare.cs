namespace Smb.FileSystem;

/// <summary>
/// A published SMB share (Context §3.3.1.6 / §12). Bundles name, type, backend and
/// security/encryption policy.
/// </summary>
public interface IShare
{
    /// <summary>Share name without a path (e.g. "Data", "IPC$").</summary>
    string Name { get; }

    ShareType Type { get; }

    /// <summary>Backend file system (for PIPE/IPC$ possibly null, or a named-pipe backend).</summary>
    IFileStore? FileStore { get; }

    /// <summary>Forces encryption for this share (Context §11, §20).</summary>
    bool EncryptData { get; }

    /// <summary>
    /// Continuous availability (SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY, §2.2.10). When set the share
    /// grants <b>persistent</b> handles (survive across sessions and, with a serializable handle store,
    /// server restarts). Off by default; a plain share still grants durable handles.
    /// </summary>
    bool ContinuousAvailability { get; }

    /// <summary>Optional comment/remark (TREE_CONNECT info).</summary>
    string Remark { get; }
}

/// <summary>Default share implementation over an <see cref="IFileStore"/>.</summary>
public sealed class Share : IShare
{
    public required string Name { get; init; }
    public ShareType Type { get; init; } = ShareType.Disk;
    public IFileStore? FileStore { get; init; }
    public bool EncryptData { get; init; }
    public bool ContinuousAvailability { get; init; }
    public string Remark { get; init; } = string.Empty;

    /// <summary>Creates the mandatory <c>IPC$</c> share (PIPE) that many clients connect first (Context §12, §23).</summary>
    public static Share CreateIpc() => new()
    {
        Name = "IPC$",
        Type = ShareType.Pipe,
        Remark = "Remote IPC",
    };
}

/// <summary>
/// Registry of a server's published shares (Context §19, <c>ShareList</c>). Thread-safe so shares
/// can be added/removed at runtime while connections are served.
/// </summary>
public sealed class ShareCollection
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, IShare> _shares =
        new(StringComparer.OrdinalIgnoreCase);

    public ShareCollection Add(IShare share)
    {
        _shares[share.Name] = share;
        return this;
    }

    /// <summary>Removes a share by name (runtime reconfiguration). Returns false if it was not present.</summary>
    public bool Remove(string name) => _shares.TryRemove(name, out _);

    public bool TryGet(string name, out IShare share) => _shares.TryGetValue(name, out share!);

    public bool Contains(string name) => _shares.ContainsKey(name);

    /// <summary>Snapshot of the currently published shares (safe to enumerate under concurrent mutation).</summary>
    public IReadOnlyCollection<IShare> All => _shares.Values.ToArray();
}
