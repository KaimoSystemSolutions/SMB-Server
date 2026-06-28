using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;
using Xunit;

namespace Smb.Tests;

public class HeaderTests
{
    [Fact]
    public void SyncHeader_RoundTrips()
    {
        var header = new Smb2Header
        {
            CreditCharge = 1,
            Status = NtStatus.Success,
            Command = SmbCommand.TreeConnect,
            CreditRequestResponse = 31,
            Flags = Smb2HeaderFlags.None,
            NextCommand = 0,
            MessageId = 42,
            TreeId = 7,
            SessionId = 0x1122334455667788,
        };

        byte[] bytes = header.ToArray();
        Assert.Equal(Smb2Header.Size, bytes.Length);

        Smb2Header parsed = Smb2Header.Read(bytes);
        Assert.Equal(SmbCommand.TreeConnect, parsed.Command);
        Assert.Equal(42ul, parsed.MessageId);
        Assert.Equal(7u, parsed.TreeId);
        Assert.Equal(0x1122334455667788ul, parsed.SessionId);
        Assert.Equal(31, parsed.CreditRequestResponse);
        Assert.False(parsed.IsAsync);
    }

    [Fact]
    public void AsyncHeader_RoundTripsAsyncId()
    {
        var header = new Smb2Header
        {
            Command = SmbCommand.ChangeNotify,
            Flags = Smb2HeaderFlags.AsyncCommand | Smb2HeaderFlags.ServerToRedir,
            MessageId = 9,
            AsyncId = 0xAABBCCDDEEFF0011,
            SessionId = 5,
            Status = NtStatus.Pending,
        };

        Smb2Header parsed = Smb2Header.Read(header.ToArray());
        Assert.True(parsed.IsAsync);
        Assert.Equal(0xAABBCCDDEEFF0011ul, parsed.AsyncId);
        Assert.Equal(NtStatus.Pending, parsed.Status);
    }

    [Fact]
    public void Read_RejectsWrongProtocolId()
    {
        var bytes = new byte[64];
        bytes[0] = 0xFF; // SMB1 statt SMB2
        Assert.Throws<SmbWireFormatException>(() => Smb2Header.Read(bytes));
    }

    [Fact]
    public void Read_RejectsWrongStructureSize()
    {
        var header = new Smb2Header { Command = SmbCommand.Echo };
        byte[] bytes = header.ToArray();
        // Corrupt StructureSize (offset 4).
        bytes[4] = 0x41;
        Assert.Throws<SmbWireFormatException>(() => Smb2Header.Read(bytes));
    }

    [Fact]
    public void CreateResponse_CopiesIdsAndSetsServerToRedir()
    {
        var request = new Smb2Header
        {
            Command = SmbCommand.Create,
            MessageId = 100,
            SessionId = 50,
            TreeId = 3,
        };

        Smb2Header response = request.CreateResponse(NtStatus.Success);
        Assert.True(response.Flags.HasFlag(Smb2HeaderFlags.ServerToRedir));
        Assert.Equal(100ul, response.MessageId);
        Assert.Equal(50ul, response.SessionId);
        Assert.Equal(3u, response.TreeId);
        Assert.Equal(NtStatus.Success, response.Status);
    }

    [Fact]
    public void ProtocolId_OnTheWire_IsFe534d42()
    {
        byte[] bytes = new Smb2Header { Command = SmbCommand.Negotiate }.ToArray();
        Assert.Equal(new byte[] { 0xFE, 0x53, 0x4D, 0x42 }, bytes[..4]);
    }
}
