using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Smb.Auth;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Host;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// M6 — Per-share encryption (SMB2_SHAREFLAG_ENCRYPT_DATA, §3.3.5.7 / §3.3.4.1.4 /
/// §3.3.5.2.11). Covers: TREE_CONNECT hardening (no 3.x encryption → ACCESS_DENIED),
/// marking the tree, rejection of unencrypted requests on an encrypted tree,
/// the <c>RejectUnencryptedAccess</c> option, and actual response encryption via the host.
/// </summary>
public class PerShareEncryptionTests : IDisposable
{
    private readonly string _shareDir;

    public PerShareEncryptionTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbenc_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "secret.txt"), "strictly confidential");
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    private (Smb2Dispatcher dispatcher, SmbServerState state, SmbConnection conn) NewServer(bool rejectUnencrypted = true)
    {
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new DevSpnegoNegotiator(),
            RequireMessageSigning = false,
            AllowAnonymousAccess = true,
            RejectGuestAccess = true,
            MaxDialect = SmbDialect.Smb311,
            RejectUnencryptedAccess = rejectUnencrypted,
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share
        {
            Name = "Secret", Type = ShareType.Disk, EncryptData = true,
            FileStore = new LocalFileStore(_shareDir, readOnly: true),
        });
        options.Shares.Add(new Share
        {
            Name = "Plain", Type = ShareType.Disk,
            FileStore = new LocalFileStore(_shareDir, readOnly: true),
        });

        var state = new SmbServerState(options);
        return (new Smb2Dispatcher(state), state, new SmbConnection());
    }

    /// <summary>NEGOTIATE (+ optional cipher) and SESSION_SETUP (Dev = anonymous, one step).</summary>
    private static ulong Handshake(Smb2Dispatcher d, SmbConnection conn, SmbDialect dialect, bool withCipher)
    {
        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest(
            [dialect], ciphers: withCipher ? [SmbCipherId.Aes128Gcm] : null));
        byte[] ss = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
        return Smb2Header.Read(ss).SessionId;
    }

    private static byte[] OpenRootCreate(ulong messageId, ulong sessionId, uint treeId) =>
        TestHelpers.BuildCreateRequest(messageId, sessionId, treeId, name: "",
            desiredAccess: 0x00000001, disposition: (uint)CreateDisposition.Open,
            options: (uint)CreateOptions.DirectoryFile);

    [Fact]
    public void TreeConnect_EncryptedShare_On311WithCipher_MarksTreeAndSetsShareFlag()
    {
        var (d, state, conn) = NewServer();
        ulong sid = Handshake(d, conn, SmbDialect.Smb311, withCipher: true);
        Assert.True(conn.SupportsEncryption);

        byte[] tc = d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\server\Secret"));
        Smb2Header h = Smb2Header.Read(tc);
        Assert.Equal(NtStatus.Success, h.Status);

        // ShareFlags (body offset 4) carries SMB2_SHAREFLAG_ENCRYPT_DATA.
        uint shareFlags = BinaryPrimitives.ReadUInt32LittleEndian(tc.AsSpan(Smb2Header.Size + 4, 4));
        Assert.True((shareFlags & (uint)ShareFlags.EncryptData) != 0, "ShareFlags must report EncryptData.");

        // Tree state requires encryption.
        SmbTreeConnect tree = state.SessionGlobalList[sid].TreeConnects[h.TreeId];
        Assert.True(tree.EncryptData);
    }

    [Fact]
    public void TreeConnect_EncryptedShare_OnConnectionWithoutEncryption_AccessDenied()
    {
        var (d, _, conn) = NewServer();
        // SMB 2.1 cannot encrypt → the server must not hand out the share in plaintext.
        ulong sid = Handshake(d, conn, SmbDialect.Smb210, withCipher: false);
        Assert.False(conn.SupportsEncryption);

        byte[] tc = d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\server\Secret"));
        Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(tc).Status);
    }

    [Fact]
    public void TreeConnect_PlainShare_On311_DoesNotRequireEncryption()
    {
        var (d, state, conn) = NewServer();
        ulong sid = Handshake(d, conn, SmbDialect.Smb311, withCipher: true);

        byte[] tc = d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\server\Plain"));
        Smb2Header h = Smb2Header.Read(tc);
        Assert.Equal(NtStatus.Success, h.Status);
        Assert.False(state.SessionGlobalList[sid].TreeConnects[h.TreeId].EncryptData);
    }

    [Fact]
    public void Request_OnEncryptedTree_Unencrypted_IsRejected()
    {
        var (d, _, conn) = NewServer();
        ulong sid = Handshake(d, conn, SmbDialect.Smb311, withCipher: true);
        uint treeId = Smb2Header.Read(
            d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\server\Secret"))).TreeId;

        // Unencrypted CREATE on the encryption-required tree → ACCESS_DENIED.
        byte[] resp = d.ProcessMessage(conn, OpenRootCreate(3, sid, treeId), transportEncrypted: false);
        Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void Request_OnEncryptedTree_Encrypted_IsProcessed()
    {
        var (d, _, conn) = NewServer();
        ulong sid = Handshake(d, conn, SmbDialect.Smb311, withCipher: true);
        uint treeId = Smb2Header.Read(
            d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\server\Secret"))).TreeId;

        // Same CREATE but delivered encrypted → passes the gate and is processed.
        byte[] resp = d.ProcessMessage(conn, OpenRootCreate(3, sid, treeId), transportEncrypted: true);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public void Request_OnEncryptedTree_Unencrypted_Allowed_WhenRejectionDisabled()
    {
        var (d, _, conn) = NewServer(rejectUnencrypted: false);
        ulong sid = Handshake(d, conn, SmbDialect.Smb311, withCipher: true);
        uint treeId = Smb2Header.Read(
            d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\server\Secret"))).TreeId;

        // With enforcement disabled, the unencrypted request is processed normally.
        byte[] resp = d.ProcessMessage(conn, OpenRootCreate(3, sid, treeId), transportEncrypted: false);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
    }

    [Fact]
    public async Task Host_EncryptsTreeConnectResponse_ForEncryptedShare()
    {
        await using var server = SmbServerBuilder.Create()
            .WithEndpoint(IPAddress.Loopback, 0)
            .UseDevAuthentication()
            .AddShare(Share.CreateIpc())
            .AddShare(new Share
            {
                Name = "Secret", Type = ShareType.Disk, EncryptData = true,
                FileStore = new LocalFileStore(_shareDir, readOnly: true),
            })
            .Build();
        await server.StartAsync();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, server.Endpoint.Port);
        await using NetworkStream stream = client.GetStream();

        // 1) NEGOTIATE (3.1.1 + GCM) — plaintext.
        await SendFramed(stream, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311], ciphers: [SmbCipherId.Aes128Gcm]));
        Assert.True(TestHelpers.IsSmb2(await ReadFramed(stream)));

        // 2) SESSION_SETUP (Dev = anonymous, one step) — plaintext.
        await SendFramed(stream, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
        byte[] ssResp = await ReadFramed(stream);
        ulong sessionId = Smb2Header.Read(ssResp).SessionId;
        Assert.Equal(NtStatus.Success, Smb2Header.Read(ssResp).Status);

        // 3) TREE_CONNECT to the encrypted share — request in plaintext, response MUST come back
        //    encrypted (TRANSFORM frame) because the share enforces encryption (§3.3.4.1.4).
        await SendFramed(stream, TestHelpers.BuildTreeConnectRequest(2, sessionId, @"\\server\Secret"));
        byte[] tcResp = await ReadFramed(stream);
        Assert.True(SmbProtocolIds.IsTransform(tcResp),
            "The TREE_CONNECT response of an encrypted share must be sent as an encrypted TRANSFORM frame.");

        await server.StopAsync();
    }

    private static async Task SendFramed(NetworkStream stream, byte[] message)
    {
        await stream.WriteAsync(NbssFrame.Wrap(message));
        await stream.FlushAsync();
    }

    private static async Task<byte[]> ReadFramed(NetworkStream stream)
    {
        var prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix);
        var payload = new byte[NbssFrame.ReadLength(prefix)];
        await stream.ReadExactlyAsync(payload);
        return payload;
    }
}
