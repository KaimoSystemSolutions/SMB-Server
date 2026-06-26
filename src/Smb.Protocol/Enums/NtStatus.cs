namespace Smb.Protocol.Enums;

/// <summary>
/// NTSTATUS-Codes, die ein SMB2-Server am häufigsten benötigt (Context §18, MS-ERREF §2.3).
/// Severity steckt in Bits 30–31 (0=Success, 1=Info, 2=Warning, 3=Error), Context §17.
/// </summary>
public enum NtStatus : uint
{
    Success = 0x00000000,
    Pending = 0x00000103,
    NotifyEnumDir = 0x0000010C,

    BufferOverflow = 0x80000005,
    NoMoreFiles = 0x80000006,

    MoreProcessingRequired = 0xC0000016,
    InvalidParameter = 0xC000000D,
    InvalidInfoClass = 0xC0000003,
    EndOfFile = 0xC0000011,
    NoSuchFile = 0xC000000F,
    AccessDenied = 0xC0000022,
    NetworkNameDeleted = 0xC00000C9,
    ObjectNameInvalid = 0xC0000033,
    ObjectNameNotFound = 0xC0000034,
    ObjectNameCollision = 0xC0000035,
    ObjectPathNotFound = 0xC000003A,
    SharingViolation = 0xC0000043,
    FileLockConflict = 0xC0000054,
    LockNotGranted = 0xC0000055,
    RangeNotLocked = 0xC000007E,
    LogonFailure = 0xC000006D,
    NotSupported = 0xC00000BB,
    InsufficientResources = 0xC000009A,
    BadNetworkName = 0xC00000BE,
    Cancelled = 0xC0000120,
    FileClosed = 0xC0000128,
    DiskFull = 0xC000007F,
    DirectoryNotEmpty = 0xC0000101,
    NotADirectory = 0xC0000103,
    FileIsADirectory = 0xC00000BA,
    UserSessionDeleted = 0xC0000203,
    InvalidDeviceRequest = 0xC0000010,
}

/// <summary>NTSTATUS-Auswertung anhand des Severity-Felds (Context §17).</summary>
public static class NtStatusExtensions
{
    /// <summary>True, wenn Severity = Success (Bits 30–31 == 0).</summary>
    public static bool IsSuccess(this NtStatus status) => ((uint)status >> 30) == 0;

    /// <summary>True, wenn Severity = Error (Bits 30–31 == 3).</summary>
    public static bool IsError(this NtStatus status) => ((uint)status >> 30) == 3;
}
