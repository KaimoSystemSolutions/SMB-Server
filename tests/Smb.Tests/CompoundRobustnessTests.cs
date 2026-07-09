using System.Buffers.Binary;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Robustness of the compound-request splitter (<see cref="Smb2Dispatcher.ProcessMessage"/>): a
/// client-controlled <c>NextCommand</c> must never make the splitter throw and drop the whole
/// connection — it must answer with a clean STATUS_INVALID_PARAMETER (§3.3.5.2 / Context §7).
/// </summary>
public class CompoundRobustnessTests
{
    [Theory]
    [InlineData(0xFFFFFF00u)] // far past the end of the buffer → Slice length overflow
    [InlineData(0x80000000u)] // high bit set → negative when cast to int
    [InlineData(0x00000010u)] // shorter than a 64-byte header
    public void BogusNextCommand_ReturnsInvalidParameter_WithoutThrowing(uint nextCommand)
    {
        var (d, conn) = NewServer();
        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb210]));

        byte[] frame = TestHelpers.BuildEchoRequest(1);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(20, 4), nextCommand); // patch NextCommand (header offset 20)

        byte[] resp = d.ProcessMessage(conn, frame); // must not throw
        Assert.Equal(NtStatus.InvalidParameter, Smb2Header.Read(resp).Status);
    }

    private static (Smb2Dispatcher, SmbConnection) NewServer()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());
        return (new Smb2Dispatcher(new SmbServerState(options)), new SmbConnection());
    }
}
