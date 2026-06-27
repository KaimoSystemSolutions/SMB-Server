using System.Text;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages.Fscc;

/// <summary>Input data for FSCC structures (populated by the backend, Context §16).</summary>
public sealed class FsccFileStat
{
    public required string Name { get; init; }
    public uint FileAttributes { get; init; }
    public long EndOfFile { get; init; }
    public long AllocationSize { get; init; }
    public long CreationTime { get; init; }
    public long LastAccessTime { get; init; }
    public long LastWriteTime { get; init; }
    public long ChangeTime { get; init; }
    public bool IsDirectory { get; init; }
    public long IndexNumber { get; init; }
    public uint NumberOfLinks { get; init; } = 1;
}

/// <summary>
/// Serialization of the MS-FSCC structures for QUERY_DIRECTORY and QUERY_INFO (Context §16).
/// Implements the set of classes needed for browsing/reading.
/// </summary>
public static class FsccStructures
{
    // ---------------------------------------------------------------------
    //  QUERY_DIRECTORY: directory listing
    // ---------------------------------------------------------------------

    /// <summary>
    /// Serializes a list of entries in the given directory-info class. Entries are 8-byte aligned
    /// and chained via <c>NextEntryOffset</c>; the last one has <c>NextEntryOffset=0</c> (Context §14).
    /// </summary>
    public static byte[] BuildDirectoryListing(IReadOnlyList<FsccFileStat> entries, FileInformationClass infoClass)
    {
        var w = new GrowableWriter(256);
        for (int i = 0; i < entries.Count; i++)
        {
            int entryStart = w.Position;
            WriteDirectoryEntry(w, entries[i], infoClass);

            // Align to 8 bytes (except for the last entry).
            bool last = i == entries.Count - 1;
            if (!last)
            {
                int padded = Align8(w.Position - entryStart);
                int pad = padded - (w.Position - entryStart);
                if (pad > 0) w.WriteZeros(pad);
                w.PatchUInt32(entryStart, (uint)(w.Position - entryStart)); // NextEntryOffset
            }
            else
            {
                w.PatchUInt32(entryStart, 0);
            }
        }
        return w.ToArray();
    }

    private static void WriteDirectoryEntry(GrowableWriter w, FsccFileStat e, FileInformationClass infoClass)
    {
        byte[] name = Encoding.Unicode.GetBytes(e.Name);

        w.WriteUInt32(0);              // NextEntryOffset (patched later)
        w.WriteUInt32(0);              // FileIndex

        switch (infoClass)
        {
            case FileInformationClass.FileNamesInformation:
                w.WriteUInt32((uint)name.Length);
                w.WriteBytes(name);
                return;

            case FileInformationClass.FileDirectoryInformation:
                WriteCommonTimesAndSizes(w, e);
                w.WriteUInt32((uint)name.Length);
                w.WriteBytes(name);
                return;

            case FileInformationClass.FileFullDirectoryInformation:
            case FileInformationClass.FileIdFullDirectoryInformation:
                WriteCommonTimesAndSizes(w, e);
                w.WriteUInt32((uint)name.Length);
                w.WriteUInt32(0);          // EaSize
                if (infoClass == FileInformationClass.FileIdFullDirectoryInformation)
                {
                    w.WriteUInt32(0);      // Reserved
                    w.WriteUInt64((ulong)e.IndexNumber); // FileId
                }
                w.WriteBytes(name);
                return;

            case FileInformationClass.FileBothDirectoryInformation:
            case FileInformationClass.FileIdBothDirectoryInformation:
            default:
                WriteCommonTimesAndSizes(w, e);
                w.WriteUInt32((uint)name.Length);
                w.WriteUInt32(0);          // EaSize
                w.WriteByte(0);            // ShortNameLength
                w.WriteByte(0);            // Reserved1
                w.WriteBytes(new byte[24]); // ShortName (8.3)
                if (infoClass == FileInformationClass.FileIdBothDirectoryInformation)
                {
                    w.WriteUInt16(0);      // Reserved2
                    w.WriteUInt64((ulong)e.IndexNumber); // FileId
                }
                w.WriteBytes(name);
                return;
        }
    }

    private static void WriteCommonTimesAndSizes(GrowableWriter w, FsccFileStat e)
    {
        w.WriteUInt64((ulong)e.CreationTime);
        w.WriteUInt64((ulong)e.LastAccessTime);
        w.WriteUInt64((ulong)e.LastWriteTime);
        w.WriteUInt64((ulong)e.ChangeTime);
        w.WriteUInt64((ulong)e.EndOfFile);
        w.WriteUInt64((ulong)e.AllocationSize);
        w.WriteUInt32(e.FileAttributes);
    }

    // ---------------------------------------------------------------------
    //  QUERY_INFO: FileInformation (InfoType FILE)
    // ---------------------------------------------------------------------

    public static byte[]? BuildFileInformation(FsccFileStat e, FileInformationClass infoClass) => infoClass switch
    {
        FileInformationClass.FileBasicInformation => FileBasic(e),
        FileInformationClass.FileStandardInformation => FileStandard(e),
        FileInformationClass.FileInternalInformation => U64((ulong)e.IndexNumber),
        FileInformationClass.FileEaInformation => U32(0),
        FileInformationClass.FilePositionInformation => U64(0),
        FileInformationClass.FileNetworkOpenInformation => FileNetworkOpen(e),
        FileInformationClass.FileAttributeTagInformation => FileAttributeTag(e),
        FileInformationClass.FileAllInformation => FileAll(e),
        FileInformationClass.FileNameInformation => FileName(e),
        _ => null,
    };

    private static byte[] FileBasic(FsccFileStat e)
    {
        var b = new byte[40];
        var w = new SpanWriter(b);
        w.WriteInt64(e.CreationTime);
        w.WriteInt64(e.LastAccessTime);
        w.WriteInt64(e.LastWriteTime);
        w.WriteInt64(e.ChangeTime);
        w.WriteUInt32(e.FileAttributes);
        w.WriteUInt32(0); // Reserved
        return b;
    }

    private static byte[] FileStandard(FsccFileStat e)
    {
        var b = new byte[24];
        var w = new SpanWriter(b);
        w.WriteInt64(e.AllocationSize);
        w.WriteInt64(e.EndOfFile);
        w.WriteUInt32(e.NumberOfLinks);
        w.WriteByte(0);                       // DeletePending
        w.WriteByte((byte)(e.IsDirectory ? 1 : 0)); // Directory
        w.WriteUInt16(0);                     // Reserved
        return b;
    }

    private static byte[] FileNetworkOpen(FsccFileStat e)
    {
        var b = new byte[56];
        var w = new SpanWriter(b);
        w.WriteInt64(e.CreationTime);
        w.WriteInt64(e.LastAccessTime);
        w.WriteInt64(e.LastWriteTime);
        w.WriteInt64(e.ChangeTime);
        w.WriteInt64(e.AllocationSize);
        w.WriteInt64(e.EndOfFile);
        w.WriteUInt32(e.FileAttributes);
        w.WriteUInt32(0); // Reserved
        return b;
    }

    private static byte[] FileAttributeTag(FsccFileStat e)
    {
        var b = new byte[8];
        var w = new SpanWriter(b);
        w.WriteUInt32(e.FileAttributes);
        w.WriteUInt32(0); // ReparseTag
        return b;
    }

    private static byte[] FileName(FsccFileStat e)
    {
        byte[] name = Encoding.Unicode.GetBytes(e.Name);
        var w = new GrowableWriter(4 + name.Length);
        w.WriteUInt32((uint)name.Length);
        w.WriteBytes(name);
        return w.ToArray();
    }

    private static byte[] FileAll(FsccFileStat e)
    {
        byte[] name = Encoding.Unicode.GetBytes(e.Name);
        var w = new GrowableWriter(96 + name.Length);
        w.WriteBytes(FileBasic(e));                       // BasicInformation (40)
        w.WriteBytes(FileStandard(e));                    // StandardInformation (24)
        w.WriteUInt64((ulong)e.IndexNumber);              // InternalInformation (8)
        w.WriteUInt32(0);                                 // EaInformation (4)
        w.WriteUInt32(0x001F01FF);                        // AccessInformation: AccessFlags (4)
        w.WriteUInt64(0);                                 // PositionInformation (8)
        w.WriteUInt32(0);                                 // ModeInformation (4)
        w.WriteUInt32(0);                                 // AlignmentInformation (4)
        w.WriteUInt32((uint)name.Length);                 // NameInformation: length (4)
        w.WriteBytes(name);                               // + name
        return w.ToArray();
    }

    // ---------------------------------------------------------------------
    //  QUERY_INFO: FileSystemInformation (InfoType FILESYSTEM)
    // ---------------------------------------------------------------------

    public static byte[]? BuildFileSystemInformation(FsInformationClass infoClass, string volumeLabel, uint serialNumber)
        => infoClass switch
        {
            FsInformationClass.FileFsVolumeInformation => FsVolume(volumeLabel, serialNumber),
            FsInformationClass.FileFsSizeInformation => FsSize(),
            FsInformationClass.FileFsFullSizeInformation => FsFullSize(),
            FsInformationClass.FileFsDeviceInformation => FsDevice(),
            FsInformationClass.FileFsAttributeInformation => FsAttribute(),
            _ => null,
        };

    private static byte[] FsVolume(string label, uint serial)
    {
        byte[] name = Encoding.Unicode.GetBytes(label);
        var w = new GrowableWriter(18 + name.Length);
        w.WriteUInt64(0);                 // VolumeCreationTime
        w.WriteUInt32(serial);            // VolumeSerialNumber
        w.WriteUInt32((uint)name.Length); // VolumeLabelLength
        w.WriteByte(0);                   // SupportsObjects
        w.WriteByte(0);                   // Reserved
        w.WriteBytes(name);
        return w.ToArray();
    }

    private static byte[] FsSize()
    {
        var b = new byte[24];
        var w = new SpanWriter(b);
        w.WriteInt64(1 << 20);  // TotalAllocationUnits (placeholder)
        w.WriteInt64(1 << 19);  // AvailableAllocationUnits
        w.WriteUInt32(8);       // SectorsPerAllocationUnit
        w.WriteUInt32(512);     // BytesPerSector
        return b;
    }

    private static byte[] FsFullSize()
    {
        var b = new byte[32];
        var w = new SpanWriter(b);
        w.WriteInt64(1 << 20);  // TotalAllocationUnits
        w.WriteInt64(1 << 19);  // CallerAvailableAllocationUnits
        w.WriteInt64(1 << 19);  // ActualAvailableAllocationUnits
        w.WriteUInt32(8);       // SectorsPerAllocationUnit
        w.WriteUInt32(512);     // BytesPerSector
        return b;
    }

    private static byte[] FsDevice()
    {
        var b = new byte[8];
        var w = new SpanWriter(b);
        w.WriteUInt32(0x00000007); // FILE_DEVICE_DISK
        w.WriteUInt32(0x00000020); // Characteristics (FILE_DEVICE_IS_MOUNTED)
        return b;
    }

    private static byte[] FsAttribute()
    {
        byte[] name = Encoding.Unicode.GetBytes("NTFS");
        var w = new GrowableWriter(12 + name.Length);
        w.WriteUInt32(0x0000002F);        // FileSystemAttributes (Case-Preserving, Unicode, …)
        w.WriteUInt32(255);               // MaximumComponentNameLength
        w.WriteUInt32((uint)name.Length); // FileSystemNameLength
        w.WriteBytes(name);
        return w.ToArray();
    }

    private static byte[] U32(uint v) { var b = new byte[4]; new SpanWriter(b).WriteUInt32(v); return b; }
    private static byte[] U64(ulong v) { var b = new byte[8]; new SpanWriter(b).WriteUInt64(v); return b; }
    private static int Align8(int v) => (v + 7) & ~7;
}
