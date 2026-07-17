using Smb.FileSystem;

namespace Smb.Server.Rpc;

/// <summary>A share visible in enumeration (name, STYPE, remark).</summary>
public readonly record struct ShareEntry(string Name, uint Type, string Remark);

/// <summary>
/// Server Service (srvsvc) RPC endpoint, as far as needed for share enumeration and the shell's
/// path resolution (MS-SRVS). Supports <c>NetrShareEnum</c> (Opnum 15, Level 1) and
/// <c>NetrShareGetInfo</c> (Opnum 16, Level 1; higher levels are denied exactly like a Windows
/// server denies them to non-admins). Bind is acknowledged.
/// <para>
/// NetrShareGetInfo is not optional in practice: the Windows shell calls it while resolving a UNC
/// path for a packaged app (Windows 11 Notepad among them). A DCERPC fault there made the shell
/// abort the open and report the file as <i>not found</i> — while classic Win32 applications on
/// the same share kept working, since they never consult srvsvc (measured 2026-07-16).
/// </para>
/// </summary>
public sealed class SrvsvcEndpoint : IRpcEndpoint
{
    private const ushort OpnumNetrShareEnum = 15;
    private const ushort OpnumNetrShareGetInfo = 16;

    // Win32 error codes returned in the NDR return-value slot (MS-SRVS §3.1.4.10).
    private const uint ErrorSuccess = 0;
    private const uint ErrorAccessDenied = 5;
    private const uint NerrNetNameNotFound = 2310;

    // STYPE values (MS-SRVS §2.2.2.4).
    public const uint StypeDisktree = 0x00000000;
    public const uint StypePrintq = 0x00000001;
    public const uint StypeIpc = 0x00000003;
    public const uint StypeSpecial = 0x80000000;

    private readonly IReadOnlyList<ShareEntry> _shares;

    public SrvsvcEndpoint(IReadOnlyList<ShareEntry> shares) => _shares = shares;

    /// <summary>Maps the SMB share type to the SRVSVC STYPE.</summary>
    public static uint MapStype(ShareType type) => type switch
    {
        ShareType.Pipe => StypeIpc | StypeSpecial, // IPC$
        ShareType.Print => StypePrintq,
        _ => StypeDisktree,
    };

    public byte[] HandlePdu(ReadOnlySpan<byte> pdu)
    {
        DcerpcRequest req;
        try { req = Dcerpc.Parse(pdu); }
        catch { return []; }

        switch (req.Type)
        {
            case DcerpcPduType.Bind:
            case DcerpcPduType.AlterContext:
                return Dcerpc.BuildBindAck(req.CallId, @"\PIPE\srvsvc");

            case DcerpcPduType.Request when req.Opnum == OpnumNetrShareEnum:
                return Dcerpc.BuildResponse(req.CallId, BuildShareEnumLevel1());

            case DcerpcPduType.Request when req.Opnum == OpnumNetrShareGetInfo:
                return Dcerpc.BuildResponse(req.CallId, HandleShareGetInfo(req.Stub));

            case DcerpcPduType.Request:
                return Dcerpc.BuildFault(req.CallId, 0x1C010002 /* nca_op_rng_error */);

            default:
                return [];
        }
    }

    /// <summary>
    /// NetrShareGetInfo (Opnum 16, MS-SRVS §3.1.4.10): looks the named share up and answers with
    /// SHARE_INFO_1. Levels above 1 (2/502/503 carry the server-local path and ACLs) are answered
    /// with ERROR_ACCESS_DENIED — the same thing a Windows server tells a non-administrator — so a
    /// caller that probes high first falls back to level 1 instead of failing. An unknown share
    /// name gets NERR_NetNameNotFound. Every answer is a well-formed RESPONSE, never a FAULT: the
    /// shell treats a fault as "path unresolvable" and the user sees "file not found".
    /// </summary>
    private byte[] HandleShareGetInfo(ReadOnlySpan<byte> stub)
    {
        string? netName = null;
        uint level = 0;
        try
        {
            int pos = 0;
            // ServerName: [unique][string] — referent id, then (when non-null) a conformant varying string.
            uint serverRef = ReadUInt32(stub, ref pos);
            if (serverRef != 0) SkipConformantVaryingString(stub, ref pos);
            // NetName: [string] ref pointer — the string follows inline.
            netName = ReadConformantVaryingString(stub, ref pos);
            level = ReadUInt32(stub, ref pos);
        }
        catch
        {
            // Malformed stub → treat as unknown share below rather than faulting the call.
        }

        ShareEntry? share = null;
        foreach (ShareEntry s in _shares)
            if (string.Equals(s.Name, netName, StringComparison.OrdinalIgnoreCase))
                share = s;

        var n = new NdrWriter();
        if (share is null)
        {
            n.UInt32(level);         // union switch mirrors the request
            n.UInt32(0);             // null info pointer
            n.UInt32(NerrNetNameNotFound);
            return n.ToArray();
        }

        switch (level)
        {
            case 0:                  // SHARE_INFO_0: the name only
                n.UInt32(0);
                n.ReferentId();      // -> SHARE_INFO_0
                n.ReferentId();      // shi0_netname
                n.WideStringNullTerminated(share.Value.Name);
                n.UInt32(ErrorSuccess);
                return n.ToArray();

            case 1:                  // SHARE_INFO_1: name, type, remark
                n.UInt32(1);
                n.ReferentId();      // -> SHARE_INFO_1
                n.ReferentId();      // shi1_netname
                n.UInt32(share.Value.Type);
                n.ReferentId();      // shi1_remark
                n.WideStringNullTerminated(share.Value.Name);
                n.WideStringNullTerminated(share.Value.Remark);
                n.UInt32(ErrorSuccess);
                return n.ToArray();

            default:                 // 2/502/503 carry server-local paths/ACLs → non-admin answer
                n.UInt32(level);
                n.UInt32(0);
                n.UInt32(ErrorAccessDenied);
                return n.ToArray();
        }
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> buf, ref int pos)
    {
        uint v = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(buf.Slice(pos, 4));
        pos += 4;
        return v;
    }

    /// <summary>Reads an NDR conformant varying wide string (max, offset, actual, chars, 4-byte pad).</summary>
    private static string ReadConformantVaryingString(ReadOnlySpan<byte> buf, ref int pos)
    {
        ReadUInt32(buf, ref pos);                       // max_count
        ReadUInt32(buf, ref pos);                       // offset
        int actual = (int)ReadUInt32(buf, ref pos);     // actual_count (chars incl. terminator)
        string s = System.Text.Encoding.Unicode.GetString(buf.Slice(pos, actual * 2)).TrimEnd('\0');
        pos += actual * 2;
        if (pos % 4 != 0) pos += 4 - pos % 4;           // align(4)
        return s;
    }

    private static void SkipConformantVaryingString(ReadOnlySpan<byte> buf, ref int pos)
        => _ = ReadConformantVaryingString(buf, ref pos);

    /// <summary>NDR stub for a NetrShareEnum response, Level 1 (SHARE_INFO_1_CONTAINER).</summary>
    private byte[] BuildShareEnumLevel1()
    {
        int count = _shares.Count;
        var n = new NdrWriter();

        n.UInt32(1);                 // InfoStruct.Level
        n.UInt32(1);                 // ShareInfo union: switch = 1
        n.ReferentId();              // -> SHARE_INFO_1_CONTAINER
        n.UInt32((uint)count);       // EntriesRead
        n.ReferentId();              // -> SHARE_INFO_1[]
        n.UInt32((uint)count);       // conformant array max_count

        // Inline part per entry: netname-ptr, type, remark-ptr.
        foreach (ShareEntry s in _shares)
        {
            n.ReferentId();          // shi1_netname
            n.UInt32(s.Type);        // shi1_type
            n.ReferentId();          // shi1_remark
        }

        // Deferred strings per entry (order: netname, remark).
        foreach (ShareEntry s in _shares)
        {
            n.WideStringNullTerminated(s.Name);
            n.WideStringNullTerminated(s.Remark);
        }

        n.UInt32((uint)count);       // TotalEntries
        n.ReferentId();              // ResumeHandle (unique ptr)
        n.UInt32(0);                 // ResumeHandle value
        n.UInt32(0);                 // return code = ERROR_SUCCESS
        return n.ToArray();
    }
}
