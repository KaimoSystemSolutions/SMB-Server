namespace Smb.FileSystem;

/// <summary>
/// The authenticated caller of the SMB request that is currently being dispatched
/// (Domain\User). Plain value type so the file-system layer needs no reference to the auth layer.
/// </summary>
public readonly record struct CallerInfo(string Domain, string User);

/// <summary>
/// Ambient, per-request caller identity for the <see cref="IFileStore"/> backend.
///
/// <para><see cref="IFileStore"/> methods carry no identity parameter — the backend is normally a
/// pure file store. A backend that enforces <b>per-user</b> authorization (e.g. ACLs evaluated per
/// operation) can instead read <see cref="Current"/>, which the server sets from the session
/// identity right before invoking the backend and resets afterwards. The value flows across the
/// synchronous-to-async bridge a backend may use (<c>AsyncLocal</c> is captured by
/// <c>Task.Run</c>).</para>
///
/// <para>The built-in stores (<c>LocalFileStore</c>, <c>VersioningFileStore</c>) ignore this and
/// behave exactly as before, so existing setups and tests are unaffected.</para>
/// </summary>
public static class SmbCaller
{
    private static readonly AsyncLocal<CallerInfo?> _current = new();

    /// <summary>The caller on the current async flow, or <c>null</c> if none was set.</summary>
    public static CallerInfo? Current
    {
        get => _current.Value;
        set => _current.Value = value;
    }
}
