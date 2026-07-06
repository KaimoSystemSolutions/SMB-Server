namespace Smb.Protocol.Enums;

/// <summary>
/// Lease caching state (SMB 2.1+, MS-SMB2 §2.2.13.2.8 <c>LeaseState</c>). A lease lets a client
/// cache reads, writes and/or the open handle. Unlike the classic <see cref="OplockLevel"/> the
/// three capabilities are independent flags, so a lease can grant e.g. Read+Handle without Write.
/// <list type="bullet">
/// <item><b>Read (R)</b> — client may cache read data (comparable to a Level II oplock).</item>
/// <item><b>Handle (H)</b> — client may keep the handle open after the application closes it
/// (deferred close), avoiding re-open round-trips.</item>
/// <item><b>Write (W)</b> — client may cache writes locally; exclusive, only one lease at a time.</item>
/// </list>
/// </summary>
[Flags]
public enum LeaseState : uint
{
    None = 0x00000000,
    Read = 0x00000001,     // SMB2_LEASE_READ_CACHING
    Handle = 0x00000002,   // SMB2_LEASE_HANDLE_CACHING
    Write = 0x00000004,    // SMB2_LEASE_WRITE_CACHING

    /// <summary>Read + Handle (common for shared read access with deferred close).</summary>
    ReadHandle = Read | Handle,

    /// <summary>Read + Write (exclusive caching without deferred close).</summary>
    ReadWrite = Read | Write,

    /// <summary>Read + Write + Handle — the strongest lease (equivalent to a Batch oplock).</summary>
    ReadWriteHandle = Read | Write | Handle,
}

/// <summary>
/// Lease flags (MS-SMB2 §2.2.13.2.8/§2.2.13.2.10 <c>LeaseFlags</c>, §2.2.23.2 lease break).
/// </summary>
[Flags]
public enum LeaseFlags : uint
{
    None = 0x00000000,

    /// <summary>A lease break is in progress (set by the server in a break notification).</summary>
    BreakInProgress = 0x00000002,

    /// <summary>The <c>ParentLeaseKey</c> field is valid (lease V2 only, directory leasing).</summary>
    ParentLeaseKeySet = 0x00000004,
}
