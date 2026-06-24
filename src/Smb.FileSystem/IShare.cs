namespace Smb.FileSystem;

/// <summary>
/// Ein bereitgestellter SMB-Share (Context §3.3.1.6 / §12). Bündelt Name, Typ, Backend
/// und Sicherheits-/Verschlüsselungs-Policy.
/// </summary>
public interface IShare
{
    /// <summary>Share-Name ohne Pfad (z.B. "Data", "IPC$").</summary>
    string Name { get; }

    ShareType Type { get; }

    /// <summary>Backend-Dateisystem (für PIPE/IPC$ ggf. null bzw. Named-Pipe-Backend).</summary>
    IFileStore? FileStore { get; }

    /// <summary>Erzwingt Verschlüsselung für diesen Share (Context §11, §20).</summary>
    bool EncryptData { get; }

    /// <summary>Optionaler Kommentar/Remark (TREE_CONNECT-Info).</summary>
    string Remark { get; }
}

/// <summary>Standard-Share-Implementierung über einen <see cref="IFileStore"/>.</summary>
public sealed class Share : IShare
{
    public required string Name { get; init; }
    public ShareType Type { get; init; } = ShareType.Disk;
    public IFileStore? FileStore { get; init; }
    public bool EncryptData { get; init; }
    public string Remark { get; init; } = string.Empty;

    /// <summary>Erzeugt den Pflicht-Share <c>IPC$</c> (PIPE), den viele Clients zuerst verbinden (Context §12, §23).</summary>
    public static Share CreateIpc() => new()
    {
        Name = "IPC$",
        Type = ShareType.Pipe,
        Remark = "Remote IPC",
    };
}

/// <summary>Registrierung der bereitgestellten Shares eines Servers (Context §19, <c>ShareList</c>).</summary>
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
