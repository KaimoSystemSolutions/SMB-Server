namespace Smb.Protocol.Enums;

/// <summary>CreateDisposition (Context §13, MS-SMB2 §2.2.13).</summary>
public enum CreateDisposition : uint
{
    Supersede = 0,
    Open = 1,
    Create = 2,
    OpenIf = 3,
    Overwrite = 4,
    OverwriteIf = 5,
}

/// <summary>CreateOptions (subset, Context §13, MS-SMB2 §2.2.13).</summary>
[Flags]
public enum CreateOptions : uint
{
    None = 0x00000000,
    DirectoryFile = 0x00000001,
    WriteThrough = 0x00000002,
    SequentialOnly = 0x00000004,
    NonDirectoryFile = 0x00000040,
    DeleteOnClose = 0x00001000,
    OpenByFileId = 0x00002000,
    OpenReparsePoint = 0x00200000,
    OpenForBackupIntent = 0x00004000,
}

/// <summary>CreateAction in the CREATE response (Context §13.3).</summary>
public enum CreateAction : uint
{
    Superseded = 0,
    Opened = 1,
    Created = 2,
    Overwritten = 3,
}

/// <summary>Oplock level (Context §13, §15).</summary>
public enum OplockLevel : byte
{
    None = 0x00,
    LevelII = 0x01,
    Exclusive = 0x08,
    Batch = 0x09,
    Lease = 0xFF,
}

/// <summary>InfoType in QUERY_INFO/SET_INFO (Context §14, MS-SMB2 §2.2.37).</summary>
public enum InfoType : byte
{
    File = 0x01,
    FileSystem = 0x02,
    Security = 0x03,
    Quota = 0x04,
}

/// <summary>FileInformationClass numbers (Context §16, MS-FSCC §2.4).</summary>
public enum FileInformationClass : byte
{
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation = 2,
    FileBothDirectoryInformation = 3,
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FileInternalInformation = 6,
    FileEaInformation = 7,
    FileNameInformation = 9,
    FileFullEaInformation = 15,
    FileRenameInformation = 10,
    FileNamesInformation = 12,
    FileDispositionInformation = 13,
    FilePositionInformation = 14,
    FileAllInformation = 18,
    FileAllocationInformation = 19,
    FileEndOfFileInformation = 20,
    FileAlternateNameInformation = 21,
    FileStreamInformation = 22,
    FileNetworkOpenInformation = 34,
    FileAttributeTagInformation = 35,
    FileIdBothDirectoryInformation = 37,
    FileIdFullDirectoryInformation = 38,
}

/// <summary>FileSystemInformationClass numbers (Context §16, MS-FSCC §2.5).</summary>
public enum FsInformationClass : byte
{
    FileFsVolumeInformation = 1,
    FileFsSizeInformation = 3,
    FileFsDeviceInformation = 4,
    FileFsAttributeInformation = 5,
    FileFsFullSizeInformation = 7,
}
