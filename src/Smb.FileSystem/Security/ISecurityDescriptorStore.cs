using System.Collections.Concurrent;
using Smb.Protocol.Security;

namespace Smb.FileSystem.Security;

/// <summary>
/// Persists per-file <see cref="SecurityDescriptor"/>s for a backend that does not carry native ACLs
/// (Phase 3). Keyed by the backend's physical path. This is the seam a deployment overrides to map SMB
/// security descriptors onto real NTFS ACLs (Windows) or POSIX ACLs / extended attributes (Linux/ZFS);
/// the default <see cref="InMemorySecurityDescriptorStore"/> keeps them in process memory, which is
/// enough for SMB-level authorization (Phase 3 access checks) and tests.
/// </summary>
public interface ISecurityDescriptorStore
{
    /// <summary>Returns the stored descriptor for <paramref name="key"/>, or <c>null</c> if none was set.</summary>
    SecurityDescriptor? TryGet(string key);

    /// <summary>Stores (replaces) the descriptor for <paramref name="key"/>.</summary>
    void Set(string key, SecurityDescriptor descriptor);

    /// <summary>Removes any descriptor for <paramref name="key"/> (e.g. on delete).</summary>
    void Remove(string key);
}

/// <summary>
/// Default process-local <see cref="ISecurityDescriptorStore"/>. Physical-path keyed and case-sensitive
/// (correct on Linux/ZFS; on Windows the path casing is consistent within one resolution).
/// </summary>
public sealed class InMemorySecurityDescriptorStore : ISecurityDescriptorStore
{
    private readonly ConcurrentDictionary<string, SecurityDescriptor> _map = new(StringComparer.Ordinal);

    public SecurityDescriptor? TryGet(string key) => _map.TryGetValue(key, out SecurityDescriptor? sd) ? sd : null;

    public void Set(string key, SecurityDescriptor descriptor) => _map[key] = descriptor;

    public void Remove(string key) => _map.TryRemove(key, out _);
}
