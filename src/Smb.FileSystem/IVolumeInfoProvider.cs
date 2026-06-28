namespace Smb.FileSystem;

/// <summary>Volume identity and capacity for QUERY_INFO FileSystem classes (MS-FSCC §2.5).</summary>
/// <param name="Label">Volume label (e.g. the share/server name).</param>
/// <param name="SerialNumber">32-bit volume serial number.</param>
/// <param name="TotalBytes">Total capacity in bytes (negative = unknown → placeholder).</param>
/// <param name="AvailableBytes">Free space in bytes available to the caller (negative = unknown).</param>
public readonly record struct VolumeInfo(string Label, uint SerialNumber, long TotalBytes, long AvailableBytes);

/// <summary>
/// Optional capability of an <see cref="IFileStore"/>: report the real volume label, serial number
/// and free space for QUERY_INFO FileSystem requests (<c>FileFsVolumeInformation</c>,
/// <c>FileFs(Full)SizeInformation</c>). If a share's store does not implement this, the server
/// returns generic placeholder values.
/// </summary>
public interface IVolumeInfoProvider
{
    /// <summary>Current volume label/serial and capacity for the backing store.</summary>
    VolumeInfo GetVolumeInfo();
}
