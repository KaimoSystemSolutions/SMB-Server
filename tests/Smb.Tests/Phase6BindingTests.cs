using System.Buffers.Binary;
using System.Security.Cryptography;
using Smb.Auth;
using Smb.Crypto;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 6 / M6.1 — SMB 3.x session binding (multichannel, §3.3.5.5.2): a second connection joins an
/// existing session as an additional channel, verified by a signature under the session key, sharing
/// the session's identity, tree connects and opens, and signing per-channel (3.1.1 §3.3.5.5.3).
/// </summary>
public class Phase6BindingTests
{
    private const uint FileReadData = 0x0000_0001;

    private static (Smb2Dispatcher d, SmbServerState state, string dir) NewServer(byte[] sessionKey, SecurityIdentity identity)
    {
        string dir = Path.Combine(Path.GetTempPath(), "smb6_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "hello.txt"), "HELLO");

        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new DevSpnegoNegotiator(sessionKey, identity),
            RequireMessageSigning = true,
            MaxDialect = SmbDialect.Smb311,
        };
        options.Shares.Add(new Share { Name = "Data", Type = ShareType.Disk, FileStore = new LocalFileStore(dir, readOnly: false) });
        var state = new SmbServerState(options);
        return (new Smb2Dispatcher(state), state, dir);
    }

    private static SecurityIdentity Alice()
        => new() { DomainName = "DOM", UserName = "alice", UserSid = "S-1-5-21-1-2-3-1001" };

    /// <summary>NEGOTIATE 3.1.1 (AES-CMAC signing) on a fresh connection.</summary>
    private static SmbConnection Negotiate(Smb2Dispatcher d)
    {
        var conn = new SmbConnection();
        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest(
            [SmbDialect.Smb311], signingAlgs: [SmbSigningAlgorithmId.AesCmac]));
        return conn;
    }

    /// <summary>Establishes a valid session on a fresh connection (Dev negotiator single-steps).</summary>
    private static (SmbConnection conn, ulong sid) Login(Smb2Dispatcher d, ulong messageId = 1)
    {
        SmbConnection conn = Negotiate(d);
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(messageId, 0, [0x01]));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(resp).Status);
        return (conn, Smb2Header.Read(resp).SessionId);
    }

    [Fact]
    public void Bind_SecondConnection_SharesOpen_AndSignsPerChannel()
    {
        byte[] sessionKey = RandomNumberGenerator.GetBytes(16);
        var (d, state, dir) = NewServer(sessionKey, Alice());
        try
        {
            SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac;

            // Channel A: authenticate, connect the share, open a file.
            (SmbConnection connA, ulong sid) = Login(d);
            SmbSession session = state.SessionGlobalList[sid];
            byte[] keyA = session.SigningKey;

            uint tid = Smb2Header.Read(d.ProcessMessage(connA,
                TestHelpers.BuildTreeConnectRequest(2, sid, @"\\s\Data", keyA, alg))).TreeId;
            byte[] createResp = d.ProcessMessage(connA, TestHelpers.BuildCreateRequest(
                3, sid, tid, "hello.txt", FileReadData, (uint)CreateDisposition.Open,
                (uint)CreateOptions.NonDirectoryFile, keyA, alg));
            Assert.Equal(NtStatus.Success, Smb2Header.Read(createResp).Status);
            (ulong pid, ulong vid) = ExtractCreateFileId(createResp);

            // Channel B: bind to the existing session. The binding SESSION_SETUP is signed with the
            // session key (§3.3.5.5.2). The Dev negotiator single-steps the GSS re-auth to success.
            SmbConnection connB = Negotiate(d);
            byte[] bindResp = d.ProcessMessage(connB, TestHelpers.BuildSessionSetupRequest(
                1, sid, [0x01], signingKey: keyA, alg: alg, sessionFlags: SessionSetupFlags.Binding));
            Assert.Equal(NtStatus.Success, Smb2Header.Read(bindResp).Status);

            // The session is now reachable on channel B with its own signing key.
            Assert.True(connB.Sessions.ContainsKey(sid));
            Assert.True(session.Channels.ContainsKey(connB.ConnectionId));
            byte[] keyB = session.Channels[connB.ConnectionId].SigningKey;
            Assert.False(keyA.AsSpan().SequenceEqual(keyB),
                "The 3.1.1 channel signing key must differ from the session key (its own preauth hash).");

            // The final binding response is signed with the new channel key (the client verifies it so).
            Smb2Header bindHeader = Smb2Header.Read(bindResp);
            Assert.True(bindHeader.Flags.HasFlag(Smb2HeaderFlags.Signed));
            Assert.True(Smb2Signer.Verify(alg, keyB, bindResp, bindHeader.MessageId, isServer: true, isCancel: false));

            // READ the shared open from channel B, signed with the CHANNEL key → shares the open.
            byte[] readResp = d.ProcessMessage(connB,
                TestHelpers.BuildReadRequest(2, sid, tid, pid, vid, length: 5, offset: 0, keyB, alg));
            Assert.Equal(NtStatus.Success, Smb2Header.Read(readResp).Status);
            Assert.Equal(5u, BinaryPrimitives.ReadUInt32LittleEndian(readResp.AsSpan(Smb2Header.Size + 4, 4)));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Bind_OnChannelB_RejectsWrongOrMissingSignature()
    {
        byte[] sessionKey = RandomNumberGenerator.GetBytes(16);
        var (d, state, dir) = NewServer(sessionKey, Alice());
        try
        {
            (SmbConnection _, ulong sid) = Login(d);

            // Unsigned binding request → ACCESS_DENIED (binding must prove possession of the session key).
            SmbConnection connB = Negotiate(d);
            byte[] unsigned = d.ProcessMessage(connB, TestHelpers.BuildSessionSetupRequest(
                1, sid, [0x01], sessionFlags: SessionSetupFlags.Binding));
            Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(unsigned).Status);
            Assert.False(connB.Sessions.ContainsKey(sid));

            // Signed with the wrong key → ACCESS_DENIED.
            byte[] wrongResp = d.ProcessMessage(connB, TestHelpers.BuildSessionSetupRequest(
                2, sid, [0x01], signingKey: RandomNumberGenerator.GetBytes(16),
                alg: SmbSigningAlgorithmId.AesCmac, sessionFlags: SessionSetupFlags.Binding));
            Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(wrongResp).Status);
            Assert.False(connB.Sessions.ContainsKey(sid));
            Assert.False(state.SessionGlobalList[sid].Channels.ContainsKey(connB.ConnectionId));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Bind_UnknownSession_ReturnsUserSessionDeleted()
    {
        byte[] sessionKey = RandomNumberGenerator.GetBytes(16);
        var (d, _, dir) = NewServer(sessionKey, Alice());
        try
        {
            SmbConnection connB = Negotiate(d);
            byte[] resp = d.ProcessMessage(connB, TestHelpers.BuildSessionSetupRequest(
                1, sessionId: 0x9999, token: [0x01], signingKey: RandomNumberGenerator.GetBytes(16),
                alg: SmbSigningAlgorithmId.AesCmac, sessionFlags: SessionSetupFlags.Binding));
            Assert.Equal(NtStatus.UserSessionDeleted, Smb2Header.Read(resp).Status);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void ClosingBoundChannel_KeepsSession_UntilLastChannelCloses()
    {
        byte[] sessionKey = RandomNumberGenerator.GetBytes(16);
        var (d, state, dir) = NewServer(sessionKey, Alice());
        try
        {
            (SmbConnection connA, ulong sid) = Login(d);
            SmbSession session = state.SessionGlobalList[sid];
            byte[] keyA = session.SigningKey;

            SmbConnection connB = Negotiate(d);
            Assert.Equal(NtStatus.Success, Smb2Header.Read(d.ProcessMessage(connB,
                TestHelpers.BuildSessionSetupRequest(1, sid, [0x01], signingKey: keyA,
                    alg: SmbSigningAlgorithmId.AesCmac, sessionFlags: SessionSetupFlags.Binding))).Status);

            // Closing the bound channel drops only that channel; the session survives on channel A.
            d.OnConnectionClosed(connB);
            Assert.True(state.SessionGlobalList.ContainsKey(sid));
            Assert.False(session.Channels.ContainsKey(connB.ConnectionId));
            Assert.True(session.Channels.ContainsKey(connA.ConnectionId));

            // Closing the last channel tears the session down.
            d.OnConnectionClosed(connA);
            Assert.False(state.SessionGlobalList.ContainsKey(sid));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    private static (ulong persistent, ulong vol) ExtractCreateFileId(byte[] response)
    {
        const int body = Smb2Header.Size;
        ulong persistent = BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 64, 8));
        ulong vol = BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 72, 8));
        return (persistent, vol);
    }
}
