namespace Smb.Protocol.Security;

/// <summary>
/// Access-mask bits for files/directories (MS-SMB2 §2.2.13.1.1 / MS-DTYP §2.4.3). Combined into the
/// <c>AccessMask</c> of an ACE and the <c>DesiredAccess</c> of a CREATE.
/// </summary>
public static class AccessMask
{
    public const uint FileReadData = 0x00000001;
    public const uint FileWriteData = 0x00000002;
    public const uint FileAppendData = 0x00000004;
    public const uint FileReadEa = 0x00000008;
    public const uint FileWriteEa = 0x00000010;
    public const uint FileExecute = 0x00000020;
    public const uint FileDeleteChild = 0x00000040;
    public const uint FileReadAttributes = 0x00000080;
    public const uint FileWriteAttributes = 0x00000100;

    public const uint Delete = 0x00010000;
    public const uint ReadControl = 0x00020000;
    public const uint WriteDac = 0x00040000;
    public const uint WriteOwner = 0x00080000;
    public const uint Synchronize = 0x00100000;

    public const uint MaximumAllowed = 0x02000000;

    public const uint GenericAll = 0x10000000;
    public const uint GenericExecute = 0x20000000;
    public const uint GenericWrite = 0x40000000;
    public const uint GenericRead = 0x80000000;

    /// <summary>Any bit that lets a caller modify file content (write or append).</summary>
    public const uint WriteAccess = FileWriteData | FileAppendData;

    // Per-object generic mapping for files (MS-DTYP §2.4.4.1 / winnt.h FILE_GENERIC_*). A DACL is
    // written with specific rights, so a DesiredAccess/ACE that carries a generic bit must be mapped
    // to the equivalent specific rights before the access check (MS-DTYP §2.5.3.2 step 2).
    public const uint FileGenericRead = ReadControl | FileReadData | FileReadAttributes | FileReadEa | Synchronize;
    public const uint FileGenericWrite = ReadControl | FileWriteData | FileWriteAttributes | FileWriteEa | FileAppendData | Synchronize;
    public const uint FileGenericExecute = ReadControl | FileReadAttributes | FileExecute | Synchronize;

    /// <summary>FILE_ALL_ACCESS (0x001F01FF) — every specific/standard right a file grants.</summary>
    public const uint FileAllAccess =
        FileReadData | FileWriteData | FileAppendData | FileReadEa | FileWriteEa | FileExecute |
        FileDeleteChild | FileReadAttributes | FileWriteAttributes |
        Delete | ReadControl | WriteDac | WriteOwner | Synchronize;

    /// <summary>
    /// Replaces the generic bits (<see cref="GenericRead"/>/<c>Write</c>/<c>Execute</c>/<c>All</c>) of
    /// <paramref name="mask"/> with the equivalent specific file rights, leaving all other bits
    /// (including <see cref="MaximumAllowed"/>) untouched. Idempotent for masks that carry no generic bits.
    /// </summary>
    public static uint MapGenericToSpecific(uint mask)
    {
        uint result = mask & ~(GenericRead | GenericWrite | GenericExecute | GenericAll);
        if ((mask & GenericRead) != 0) result |= FileGenericRead;
        if ((mask & GenericWrite) != 0) result |= FileGenericWrite;
        if ((mask & GenericExecute) != 0) result |= FileGenericExecute;
        if ((mask & GenericAll) != 0) result |= FileAllAccess;
        return result;
    }
}
