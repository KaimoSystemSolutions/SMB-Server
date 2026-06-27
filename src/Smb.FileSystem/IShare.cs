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
    public string Remark { get; init; } = string.Empty;

    /// <summary>Creates the mandatory <c>IPC$</c> share (PIPE) that many clients connect first (Context §12, §23).</summary>
    public static Share CreateIpc() => new()
    {
        Name = "IPC$",
        Type = ShareType.Pipe,
        Remark = "Remote IPC",
    };
}

/// <summary>Registry of a server's published shares (Context §19, <c>ShareList</c>).</summary>
public sealed class ShareCollection
{
    private readonly Dictionary<string, IShare> _shares = new(StringComparer.OrdinalIgnoreCase);

    public ShareCollection Add(IShare share)
    {
        _shares[share.Name] = share;
        return this;
    }

    public bool TryGet(string name, out IShare share) => _shares.TryGetValue(name, out share!);

    public bool Contains(string name) => _shares.ContainsKey(name);

    public IReadOnlyCollection<IShare> All => _shares.Values;
}
