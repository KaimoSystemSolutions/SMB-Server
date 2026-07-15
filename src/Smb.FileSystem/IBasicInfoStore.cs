using Smb.Protocol.Enums;
using Smb.Protocol.Messages;

namespace Smb.FileSystem;

/// <summary>
/// An <see cref="IFileStore"/> that can apply <c>FileBasicInformation</c> (MS-FSCC §2.4.7) — the four
/// timestamps and the DOS attributes — from a SET_INFO. A backend opts in by implementing this interface;
/// the dispatcher checks for it with <c>is</c>, the same pattern as <see cref="ISparseFileStore"/>.
/// <para>
/// <b>A backend that omits it still gets STATUS_SUCCESS, and the update is dropped.</b> That is deliberate,
/// and it is a lie: SET_INFO/FileBasicInformation is on the normal path of ordinary Windows operations —
/// every file copy stamps the destination's timestamps at the end, and Explorer's read-only/hidden checkboxes
/// are nothing else — so answering STATUS_NOT_SUPPORTED would make those operations fail outright on backends
/// that cannot store the metadata. Accepting-and-dropping keeps them working with wrong timestamps. Implement
/// this interface wherever the metadata can actually be stored; <see cref="Local.LocalFileStore"/> does.
/// </para>
/// </summary>
public interface IBasicInfoStore
{
    /// <summary>
    /// Applies the non-null fields of <paramref name="update"/> to the open file; null fields must be left
    /// exactly as they are (the client asked for no change — see <see cref="SetInfoMessage.ParseBasicInfo"/>).
    /// Returns <c>STATUS_ACCESS_DENIED</c> on a read-only backend, as the write paths do.
    /// </summary>
    ValueTask<NtStatus> SetBasicInfoAsync(
        IFileHandle handle, FileBasicInfoUpdate update, CancellationToken cancellationToken = default);
}
