using Smb.Protocol.Transport;
using Smb.Protocol.Wire;
using Xunit;

namespace Smb.Tests;

public class WireTests
{
    [Fact]
    public void SpanWriterReader_RoundTripsAllPrimitives_LittleEndian()
    {
        var buffer = new byte[64];
        var w = new SpanWriter(buffer);
        w.WriteByte(0x12);
        w.WriteUInt16(0x3456);
        w.WriteUInt32(0x789ABCDE);
        w.WriteUInt64(0x0102030405060708);

        var r = new SpanReader(buffer);
        Assert.Equal(0x12, r.ReadByte());
        Assert.Equal(0x3456, r.ReadUInt16());
        Assert.Equal(0x789ABCDEu, r.ReadUInt32());
        Assert.Equal(0x0102030405060708ul, r.ReadUInt64());
    }

    [Fact]
    public void SpanWriter_WritesLittleEndian()
    {
        var buffer = new byte[4];
        var w = new SpanWriter(buffer);
        w.WriteUInt32(0x01020304);
        // Little-endian: least significant byte first.
        Assert.Equal(new byte[] { 0x04, 0x03, 0x02, 0x01 }, buffer);
    }

    [Fact]
    public void SpanWriter_AlignTo_PadsWithZeros()
    {
        var buffer = new byte[16];
        var w = new SpanWriter(buffer);
        w.WriteByte(0xFF);
        w.WriteByte(0xFF);
        w.WriteByte(0xFF);
        w.AlignTo(8);
        Assert.Equal(8, w.Position);
        Assert.Equal(0, buffer[3]);
    }

    [Fact]
    public void SpanReader_ReadingPastEnd_Throws()
    {
        static void ReadTooMuch()
        {
            var r = new SpanReader(new byte[2]);
            r.ReadUInt16();
            r.ReadByte(); // past the end
        }
        Assert.Throws<SmbWireFormatException>(ReadTooMuch);
    }

    [Fact]
    public void NbssFrame_LengthIsBigEndian()
    {
        // Length 0x00ABCDEF → bytes 0x00, 0xAB, 0xCD, 0xEF after the type byte.
        var header = new byte[4];
        NbssFrame.WriteHeader(header, 0x00ABCDEF);
        Assert.Equal(NbssFrame.SessionMessageType, header[0]);
        Assert.Equal(0xAB, header[1]);
        Assert.Equal(0xCD, header[2]);
        Assert.Equal(0xEF, header[3]);
        Assert.Equal(0x00ABCDEF, NbssFrame.ReadLength(header));
    }

    [Fact]
    public void NbssFrame_Wrap_PrependsCorrectLength()
    {
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        byte[] frame = NbssFrame.Wrap(payload);
        Assert.Equal(NbssFrame.HeaderLength + payload.Length, frame.Length);
        Assert.Equal(payload.Length, NbssFrame.ReadLength(frame));
        Assert.Equal(payload, frame[4..]);
    }

    [Fact]
    public void NbssFrame_RejectsOversizePayload()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => NbssFrame.WriteHeader(new byte[4], NbssFrame.MaxPayloadLength + 1));

    [Fact]
    public void GrowableWriter_GrowsAndPatches()
    {
        var w = new GrowableWriter(4);
        int pos = w.Position;
        w.WriteUInt16(0);                 // placeholder
        for (int i = 0; i < 100; i++) w.WriteByte((byte)i); // forces growth
        w.PatchUInt16(pos, 0xBEEF);

        byte[] result = w.ToArray();
        Assert.Equal(102, result.Length);
        Assert.Equal(0xEF, result[0]);
        Assert.Equal(0xBE, result[1]);
    }
}
