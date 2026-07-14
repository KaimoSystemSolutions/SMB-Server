using System.Buffers.Binary;
using System.Collections.Concurrent;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Rpc;
using Smb.Server.State;
using Smb.Server.Witness;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// C1.3 — <c>WitnessrAsyncNotify</c> end-to-end over the dispatcher: the call pends with STATUS_PENDING,
/// a server-side notification is delivered out-of-band as a RESP_ASYNC_NOTIFY IOCTL response, and CANCEL
/// aborts a pending notify. Drives the real IOCTL/FSCTL_PIPE_TRANSCEIVE path against <c>\PIPE\witness</c>.
/// </summary>
public class WitnessAsyncNotifyTests
{
    private const uint FullAccess = 0x001F01FF;

    [Fact]
    public void AsyncNotify_PendsThenDeliversNotification_OutOfBand()
    {
        var (d, state, conn, sid, tid) = Setup();
        (ulong pid, ulong vid) = CreateWitnessPipe(d, conn, sid, tid);
        byte[] handle = Register(d, conn, sid, tid, pid, vid);

        var sent = new ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        // AsyncNotify → interim STATUS_PENDING (async header).
        byte[] interim = Transceive(d, conn, sid, tid, pid, vid, mid: 10, BuildRequestPdu(10, (ushort)WitnessOpnum.AsyncNotify, handle));
        Smb2Header ih = Smb2Header.Read(interim);
        Assert.Equal(NtStatus.Pending, ih.Status);
        Assert.True(ih.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand));

        // Server-side trigger via the public failover API (C1.4): a resource on \\cluster went unavailable.
        int notified = state.WitnessRegistrations.NotifyResourceChange(@"\\cluster", WitnessResourceChange.Unavailable, "Data");
        Assert.Equal(1, notified);

        byte[] final = WaitForSend(sent);
        Smb2Header fh = Smb2Header.Read(final);
        Assert.Equal(NtStatus.Success, fh.Status);
        Assert.True(fh.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand));
        Assert.Equal(ih.AsyncId, fh.AsyncId);

        // The IOCTL output carries a DCERPC response whose stub is a RESP_ASYNC_NOTIFY of type ResourceChange.
        var r = new NdrReader(DcerpcStub(IoctlOutput(final)));
        Assert.NotEqual(0u, r.ReferentId());
        Assert.Equal((uint)WitnessNotifyType.ResourceChange, r.UInt32());
    }

    [Fact]
    public void Cancel_AbortsPendingAsyncNotify_WithStatusCancelled()
    {
        var (d, state, conn, sid, tid) = Setup();
        (ulong pid, ulong vid) = CreateWitnessPipe(d, conn, sid, tid);
        byte[] handle = Register(d, conn, sid, tid, pid, vid);

        var sent = new ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        byte[] interim = Transceive(d, conn, sid, tid, pid, vid, mid: 10, BuildRequestPdu(10, (ushort)WitnessOpnum.AsyncNotify, handle));
        Assert.Equal(NtStatus.Pending, Smb2Header.Read(interim).Status);

        // CANCEL referencing the pending notify's MessageId (10) aborts it.
        byte[] cancelBody = new byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(cancelBody, 4);
        byte[] cancel = TestHelpers.Concat(TestHelpers.BuildHeader(SmbCommand.Cancel, 10, sid, tid), cancelBody);
        Assert.Empty(d.ProcessMessage(conn, cancel));

        Assert.Equal(NtStatus.Cancelled, Smb2Header.Read(WaitForSend(sent)).Status);
    }

    // --- witness client helpers ---------------------------------------------------------------------

    private static (ulong pid, ulong vid) CreateWitnessPipe(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            5, sid, tid, "witness", desiredAccess: FullAccess,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8)));
    }

    /// <summary>Registers over the pipe and returns the 20-byte context handle.</summary>
    private static byte[] Register(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong pid, ulong vid)
    {
        var stub = new NdrWriter();
        stub.UInt32(WitnessVersion.V1);
        stub.ReferentId(); stub.WideStringNullTerminated(@"\\cluster");
        stub.ReferentId(); stub.WideStringNullTerminated("10.0.0.5");
        stub.ReferentId(); stub.WideStringNullTerminated("CLIENT01");

        byte[] resp = Transceive(d, conn, sid, tid, pid, vid, mid: 6, BuildRequestPdu(6, (ushort)WitnessOpnum.Register, stub.ToArray()));
        ReadOnlySpan<byte> respStub = DcerpcStub(IoctlOutput(resp));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(respStub.Slice(20, 4))); // ERROR_SUCCESS
        return respStub[..20].ToArray();
    }

    private static byte[] Transceive(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong pid, ulong vid, ulong mid, byte[] pdu)
        => d.ProcessMessage(conn, TestHelpers.BuildIoctlRequest(mid, sid, tid, pid, vid, IoctlMessage.FsctlPipeTransceive, pdu));

    /// <summary>Extracts the IOCTL response OutputBuffer from a full response message.</summary>
    private static byte[] IoctlOutput(byte[] msg)
    {
        int off = (int)BinaryPrimitives.ReadUInt32LittleEndian(msg.AsSpan(Smb2Header.Size + 32, 4));
        int count = (int)BinaryPrimitives.ReadUInt32LittleEndian(msg.AsSpan(Smb2Header.Size + 36, 4));
        return off == 0 ? [] : msg.AsSpan(off, count).ToArray();
    }

    /// <summary>The NDR stub of a DCERPC RESPONSE PDU (past its 24-byte header).</summary>
    private static byte[] DcerpcStub(byte[] pdu) => pdu[24..];

    private static byte[] BuildRequestPdu(uint callId, ushort opnum, ReadOnlySpan<byte> stub)
    {
        var w = new Smb.Protocol.Wire.GrowableWriter(24 + stub.Length);
        w.WriteByte(5); w.WriteByte(0); w.WriteByte((byte)DcerpcPduType.Request); w.WriteByte(0x03);
        w.WriteUInt32(0x00000010); // packed_drep (LE)
        w.WriteUInt16(0);          // frag_length (unused by the parser)
        w.WriteUInt16(0);          // auth_length
        w.WriteUInt32(callId);
        w.WriteUInt32((uint)stub.Length); // alloc_hint
        w.WriteUInt16(0);          // p_cont_id
        w.WriteUInt16(opnum);      // opnum
        w.WriteBytes(stub);
        return w.ToArray();
    }

    private static byte[] WaitForSend(ConcurrentQueue<byte[]> queue)
    {
        for (int i = 0; i < 250; i++)
        {
            if (queue.TryDequeue(out byte[]? msg)) return msg;
            Thread.Sleep(20);
        }
        throw new Xunit.Sdk.XunitException("No out-of-band witness response received within the time limit.");
    }

    // --- setup --------------------------------------------------------------------------------------

    private static (Smb2Dispatcher d, SmbServerState state, SmbConnection conn, ulong sid, uint tid) Setup()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());

        var state = new SmbServerState(options);
        var d = new Smb2Dispatcher(state);
        var conn = new SmbConnection();

        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sid = Smb2Header.Read(r1).SessionId;
        d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sid, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        uint tid = Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(3, sid, @"\\s\IPC$"))).TreeId;
        return (d, state, conn, sid, tid);
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }
}
