using Smb.Protocol.Enums;

namespace Smb.FileSystem;

/// <summary>
/// One extended attribute (Phase 9 / M9.2): an OEM/ASCII <see cref="Name"/> with an opaque byte value
/// and MS-FSCC flags (e.g. <c>FILE_NEED_EA = 0x80</c>).
/// </summary>
public readonly record struct ExtendedAttribute(string Name, byte[] Value, byte Flags = 0);

/// <summary>
/// Optional backend capability for extended attributes (Phase 9 / M9.2). A backend that implements this
/// answers QUERY_INFO / SET_INFO <c>FileFullEaInformation</c>. Checked with <c>is</c> by the dispatcher
/// — a store that does not implement it reports no EAs and rejects EA writes with
/// <c>STATUS_NOT_SUPPORTED</c>. This is the seam a deployment maps onto real OS xattr APIs.
/// </summary>
public interface IExtendedAttributeStore
{
    /// <summary>Returns all extended attributes on the file behind <paramref name="handle"/> (possibly empty).</summary>
    ValueTask<FileStoreResult<IReadOnlyList<ExtendedAttribute>>> GetExtendedAttributesAsync(
        IFileHandle handle, CancellationToken cancellationToken = default);

    /// <summary>
    /// Applies an EA change set (MS-FSCC §2.4.15): each entry adds or replaces the named attribute; an
    /// entry with a zero-length value deletes it. Entries not named are left untouched.
    /// </summary>
    ValueTask<NtStatus> SetExtendedAttributesAsync(
        IFileHandle handle, IReadOnlyList<ExtendedAttribute> entries, CancellationToken cancellationToken = default);
}
