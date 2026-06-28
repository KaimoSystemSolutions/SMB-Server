using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;
using Smb.Auth.Ntlm;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Smb.Protocol.Wire;

namespace Smb.Sample.Server;

/// <summary>
/// Compact SMB client for the demo only: connects via TCP, authenticates via NTLM with
/// credentials, connects a share, lists the directory and reads a file.
/// Uses dialect 2.1 (without signing/encryption) to keep the demo lean.
/// </summary>
internal sealed class DemoClient : IDisposable
{
    private readonly TcpClient _tcp = new();
    private NetworkStream _stream = null!;
    private ulong _messageId;
    private ulong _sessionId;
    private uint _treeId;

    public async Task ConnectAsync(string host, int port)
    {
        await _tcp.ConnectAsync(host, port);
        _stream = _tcp.GetStream();
        await RoundtripAsync(BuildNegotiate());
    }

    public async Task<bool> LoginAsync(string domain, string user, string password)
    {
        var ntlm = new NtlmClient(domain, user, password);

        byte[] r1 = await RoundtripAsync(BuildSessionSetup(0, ntlm.BuildNegotiate()));
        var h1 = Smb2Header.Read(r1);
        _sessionId = h1.SessionId;
        if (h1.Status != NtStatus.MoreProcessingRequired) return false;

        byte[] r2 = await RoundtripAsync(BuildSessionSetup(_sessionId, ntlm.BuildAuthenticate(SecurityBuffer(r1))));
        return Smb2Header.Read(r2).Status == NtStatus.Success;
    }

    public async Task<bool> TreeConnectAsync(string uncPath)
    {
        byte[] resp = await RoundtripAsync(BuildTreeConnect(uncPath));
        var h = Smb2Header.Read(resp);
        _treeId = h.TreeId;
        return h.Status == NtStatus.Success;
    }

    public async Task<IReadOnlyList<string>> ListDirectoryAsync()
    {
        (ulong p, ulong v, NtStatus st) = await OpenAsync("", CreateDisposition.Open, CreateOptions.DirectoryFile);
        if (st != NtStatus.Success) return [];

        byte[] resp = await RoundtripAsync(BuildQueryDirectory(p, v));
        await RoundtripAsync(BuildClose(p, v));
        if (Smb2Header.Read(resp).Status != NtStatus.Success) return [];
        return ParseNames(resp);
    }

    public async Task<string?> ReadFileAsync(string name)
    {
        (ulong p, ulong v, NtStatus st) = await OpenAsync(name, CreateDisposition.Open, CreateOptions.NonDirectoryFile);
        if (st != NtStatus.Success) return null;

        byte[] resp = await RoundtripAsync(BuildRead(p, v, 4096));
        await RoundtripAsync(BuildClose(p, v));
        if (Smb2Header.Read(resp).Status != NtStatus.Success) return null;

        int dataLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 4, 4));
        return Encoding.UTF8.GetString(resp.AsSpan(80, dataLen));
    }

    private async Task<(ulong persistent, ulong vol, NtStatus status)> OpenAsync(
        string name, CreateDisposition disposition, CreateOptions options)
    {
        byte[] resp = await RoundtripAsync(BuildCreate(name, disposition, options));
        var h = Smb2Header.Read(resp);
        if (h.Status != NtStatus.Success) return (0, 0, h.Status);
        ulong persistent = BinaryPrimitives.ReadUInt64LittleEndian(resp.AsSpan(Smb2Header.Size + 64, 8));
        ulong vol = BinaryPrimitives.ReadUInt64LittleEndian(resp.AsSpan(Smb2Header.Size + 72, 8));
        return (persistent, vol, NtStatus.Success);
    }

    // --- Transport ---

    private async Task<byte[]> RoundtripAsync(byte[] message)
    {
        await _stream.WriteAsync(NbssFrame.Wrap(message));
        await _stream.FlushAsync();
        var prefix = new byte[4];
        await _stream.ReadExactlyAsync(prefix);
        var payload = new byte[NbssFrame.ReadLength(prefix)];
        await _stream.ReadExactlyAsync(payload);
        return payload;
    }

    // --- Request builders (compact, dialect 2.1) ---

    private byte[] Header(SmbCommand cmd) => new Smb2Header
    {
        Command = cmd, MessageId = _messageId++, SessionId = _sessionId, TreeId = _treeId, CreditRequestResponse = 64,
    }.ToArray();

    private byte[] BuildNegotiate()
    {
        var b = new GrowableWriter(64);
        b.WriteUInt16(36); b.WriteUInt16(1); b.WriteUInt16(1); b.WriteUInt16(0);
        b.WriteUInt32((uint)Smb2Capabilities.LargeMtu);
        b.WriteBytes(new byte[16]); b.WriteUInt64(0); // ClientGuid + ClientStartTime
        b.WriteUInt16((ushort)SmbDialect.Smb210);
        return Concat(Header(SmbCommand.Negotiate), b.ToArray());
    }

    private byte[] BuildSessionSetup(ulong sessionId, byte[] token)
    {
        _sessionId = sessionId;
        var b = new GrowableWriter(40 + token.Length);
        b.WriteUInt16(25); b.WriteByte(0); b.WriteByte(1); b.WriteUInt32(0); b.WriteUInt32(0);
        int offPos = b.Position; b.WriteUInt16(0); b.WriteUInt16((ushort)token.Length); b.WriteUInt64(0);
        int start = b.Position; b.WriteBytes(token);
        b.PatchUInt16(offPos, (ushort)(Smb2Header.Size + start));
        return Concat(Header(SmbCommand.SessionSetup), b.ToArray());
    }

    private byte[] BuildTreeConnect(string path)
    {
        byte[] p = Encoding.Unicode.GetBytes(path);
        var b = new GrowableWriter(16 + p.Length);
        b.WriteUInt16(9); b.WriteUInt16(0);
        int offPos = b.Position; b.WriteUInt16(0); b.WriteUInt16((ushort)p.Length);
        int start = b.Position; b.WriteBytes(p);
        b.PatchUInt16(offPos, (ushort)(Smb2Header.Size + start));
        return Concat(Header(SmbCommand.TreeConnect), b.ToArray());
    }

    private byte[] BuildCreate(string name, CreateDisposition disposition, CreateOptions options)
    {
        byte[] n = Encoding.Unicode.GetBytes(name);
        var b = new GrowableWriter(64 + n.Length);
        b.WriteUInt16(57); b.WriteByte(0); b.WriteByte(0); b.WriteUInt32(2);
        b.WriteUInt64(0); b.WriteUInt64(0);
        b.WriteUInt32(0x00000001);        // DesiredAccess = FILE_READ_DATA
        b.WriteUInt32(0); b.WriteUInt32(0x07);
        b.WriteUInt32((uint)disposition); b.WriteUInt32((uint)options);
        int offPos = b.Position; b.WriteUInt16(0); b.WriteUInt16((ushort)n.Length);
        b.WriteUInt32(0); b.WriteUInt32(0);
        int start = b.Position; if (n.Length > 0) b.WriteBytes(n); else b.WriteByte(0);
        b.PatchUInt16(offPos, (ushort)(Smb2Header.Size + start));
        return Concat(Header(SmbCommand.Create), b.ToArray());
    }

    private byte[] BuildQueryDirectory(ulong p, ulong v)
    {
        byte[] pat = Encoding.Unicode.GetBytes("*");
        var b = new GrowableWriter(40 + pat.Length);
        b.WriteUInt16(33); b.WriteByte((byte)FileInformationClass.FileIdBothDirectoryInformation); b.WriteByte(0);
        b.WriteUInt32(0); b.WriteUInt64(p); b.WriteUInt64(v);
        int offPos = b.Position; b.WriteUInt16(0); b.WriteUInt16((ushort)pat.Length); b.WriteUInt32(65536);
        int start = b.Position; b.WriteBytes(pat);
        b.PatchUInt16(offPos, (ushort)(Smb2Header.Size + start));
        return Concat(Header(SmbCommand.QueryDirectory), b.ToArray());
    }

    private byte[] BuildRead(ulong p, ulong v, uint length)
    {
        var b = new GrowableWriter(50);
        b.WriteUInt16(49); b.WriteByte(0); b.WriteByte(0); b.WriteUInt32(length); b.WriteUInt64(0);
        b.WriteUInt64(p); b.WriteUInt64(v); b.WriteUInt32(0); b.WriteUInt32(0); b.WriteUInt32(0);
        b.WriteUInt16(0); b.WriteUInt16(0); b.WriteByte(0);
        return Concat(Header(SmbCommand.Read), b.ToArray());
    }

    private byte[] BuildClose(ulong p, ulong v)
    {
        var b = new GrowableWriter(24);
        b.WriteUInt16(24); b.WriteUInt16(0); b.WriteUInt32(0); b.WriteUInt64(p); b.WriteUInt64(v);
        return Concat(Header(SmbCommand.Close), b.ToArray());
    }

    // --- Parse helpers ---

    private static byte[] SecurityBuffer(byte[] resp)
    {
        int off = BinaryPrimitives.ReadUInt16LittleEndian(resp.AsSpan(Smb2Header.Size + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(resp.AsSpan(Smb2Header.Size + 6, 2));
        return len == 0 ? [] : resp.AsSpan(off, len).ToArray();
    }

    private static List<string> ParseNames(byte[] resp)
    {
        int bufLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(resp.AsSpan(Smb2Header.Size + 4, 4));
        ReadOnlySpan<byte> buf = resp.AsSpan(72, bufLen);
        var names = new List<string>();
        int pos = 0;
        while (pos < buf.Length)
        {
            int next = (int)BinaryPrimitives.ReadUInt32LittleEndian(buf.Slice(pos, 4));
            int nameLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(buf.Slice(pos + 60, 4));
            names.Add(Encoding.Unicode.GetString(buf.Slice(pos + 104, nameLen)));
            if (next == 0) break;
            pos += next;
        }
        return names;
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0); b.CopyTo(r, a.Length);
        return r;
    }

    public void Dispose() => _tcp.Dispose();
}
