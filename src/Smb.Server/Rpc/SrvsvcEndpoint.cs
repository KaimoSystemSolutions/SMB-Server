using Smb.FileSystem;

namespace Smb.Server.Rpc;

/// <summary>A share visible in enumeration (name, STYPE, remark).</summary>
public readonly record struct ShareEntry(string Name, uint Type, string Remark);

/// <summary>
/// Server Service (srvsvc) RPC endpoint, as far as needed for share enumeration
/// (MS-SRVS). Supports <c>NetrShareEnum</c> (Opnum 15), Level 1. Bind is acknowledged.
/// </summary>
public sealed class SrvsvcEndpoint : IRpcEndpoint
{
    private const ushort OpnumNetrShareEnum = 15;

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

            case DcerpcPduType.Request:
                return Dcerpc.BuildFault(req.CallId, 0x1C010002 /* nca_op_rng_error */);

            default:
                return [];
        }
    }

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
