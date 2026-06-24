using Smb.Protocol.Enums;

namespace Smb.FileSystem;

/// <summary>
/// Backend-Handle einer geöffneten Datei/eines Verzeichnisses (entspricht
/// <c>Open.LocalOpen</c>, Context §19). Lebenszyklus an das SMB-<c>Open</c> gekoppelt.
/// </summary>
public interface IFileHandle : IDisposable
{
    string Path { get; }
    bool IsDirectory { get; }
    FileEntryInfo GetInfo();
}

/// <summary>
/// NTFS-semantisches Datei-Backend hinter einem Share (Context §2, §13). Liefert
/// NT-Status-Codes; ein konkretes Backend (lokales FS, virtuell, …) mappt seine Semantik
/// hierauf. Pfade sind share-relativ, mit '\\' getrennt, ohne führenden Backslash.
/// </summary>
public interface IFileStore
{
    /// <summary>Öffnet/erstellt gemäß CreateDisposition. <paramref name="createAction"/> meldet, was geschah.</summary>
    FileStoreResult<IFileHandle> Create(
        string path,
        FileAccessIntent access,
        CreateDispositionIntent disposition,
        bool directoryRequired,
        bool nonDirectoryRequired,
        out CreateOutcome createAction);

    /// <summary>Liest aus einem offenen Handle.</summary>
    FileStoreResult<int> Read(IFileHandle handle, long offset, Span<byte> buffer);

    /// <summary>Schreibt in ein offenes Handle, liefert die Anzahl geschriebener Bytes.</summary>
    FileStoreResult<int> Write(IFileHandle handle, long offset, ReadOnlySpan<byte> data);

    /// <summary>Listet ein Verzeichnis (optional mit Wildcard-Suchmuster).</summary>
    FileStoreResult<IReadOnlyList<FileEntryInfo>> QueryDirectory(IFileHandle handle, string searchPattern);

    /// <summary>Setzt die Dateigröße (SET FileEndOfFileInformation).</summary>
    NtStatus SetEndOfFile(IFileHandle handle, long length);

    /// <summary>Benennt um/verschiebt (SET FileRenameInformation).</summary>
    NtStatus Rename(IFileHandle handle, string newPath, bool replaceIfExists);

    /// <summary>Markiert zum Löschen beim Schließen (SET FileDispositionInformation / DELETE_ON_CLOSE).</summary>
    NtStatus SetDeleteOnClose(IFileHandle handle, bool delete);

    /// <summary>Flusht Puffer auf das Backend.</summary>
    NtStatus Flush(IFileHandle handle);
}

/// <summary>Vereinfachte Zugriffsabsicht (aus CREATE DesiredAccess abgeleitet, Context §13.1).</summary>
[Flags]
public enum FileAccessIntent
{
    None = 0,
    Read = 1,
    Write = 2,
    Delete = 4,
    ReadWrite = Read | Write,
}

/// <summary>CreateDisposition-Absicht (Context §13).</summary>
public enum CreateDispositionIntent
{
    Supersede = 0,
    Open = 1,
    Create = 2,
    OpenIf = 3,
    Overwrite = 4,
    OverwriteIf = 5,
}

/// <summary>CreateAction der Response (Context §13.3).</summary>
public enum CreateOutcome
{
    Superseded = 0,
    Opened = 1,
    Created = 2,
    Overwritten = 3,
}
