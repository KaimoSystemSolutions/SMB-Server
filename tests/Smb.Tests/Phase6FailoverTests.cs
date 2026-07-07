using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Smb.Auth;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Locking;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Phase 6 / M6.3 — channel failover: when a bound channel drops, the session and its opens survive on
/// the remaining channel(s) and in-flight async operations (blocking LOCK / CHANGE_NOTIFY) complete,
/// their final response rerouted to a surviving channel (§3.3.5).
/// </summary>
public class Phase6FailoverTests : IDisposable
{
    private readonly string _dir;

    public Phase6FailoverTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "smb6fo_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "lock.txt"), new string('x', 100));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { /* ignore */ }
    }

    [Fact]
    public void SelectSendChannel_PrefersLiveChannel_ThenFailsOver()
    {
        var connA = new SmbConnection();
        var connB = new SmbConnection();
        var session = new SmbSession { SessionId = 1, SessionGlobalId = 1, Connection = connA };
        session.Channels[connA.ConnectionId] = new SmbChannel { Connection = connA, SigningKey = [] };
        session.Channels[connB.ConnectionId] = new SmbChannel { Connection = connB, SigningKey = [] };
        connA.SendRawAsync = (_, _) => Task.CompletedTask;
        connB.SendRawAsync = (_, _) => Task.CompletedTask;

        Assert.Same(connB, session.SelectSendChannel(preferred: connB));

        // Preferred channel dropped → fail over to the other live channel.
        connB.SendRawAsync = null;
        Assert.Same(connA, session.SelectSendChannel(preferred: connB));

        // No channel can send → null.
        connA.SendRawAsync = null;
        Assert.Null(session.SelectSendChannel(preferred: connB));
    }

    [Fact]
    public async Task BlockingLock_FinalResponse_ReroutesToSurvivingChannel_WhenOriginatingChannelDrops()
    {
        byte[] sessionKey = RandomNumberGenerator.GetBytes(16);
        var identity = new SecurityIdentity { DomainName = "DOM", UserName = "alice", UserSid = "S-1-5-21-9-9-9-1001" };
        var gated = new GatedLockManager();

        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new DevSpnegoNegotiator(sessionKey, identity),
            RequireMessageSigning = false,
            LockManager = gated,
        };
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_dir, readOnly: false) });
        var state = new SmbServerState(options);
        var d = new Smb2Dispatcher(state);
        const SmbSigningAlgorithmId alg = SmbSigningAlgorithmId.AesCmac;

        // Channel A: login, connect share, open the file. Sink A collects out-of-band responses.
        var connA = new SmbConnection();
        var sinkA = new ConcurrentQueue<byte[]>();
        connA.SendRawAsync = (b, _) => { sinkA.Enqueue(b); return Task.CompletedTask; };
        d.ProcessMessage(connA, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311], signingAlgs: [alg]));
        ulong sid = Smb2Header.Read(d.ProcessMessage(connA, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]))).SessionId;
        SmbSession session = state.SessionGlobalList[sid];
        byte[] keyA = session.SigningKey;
        uint tid = Smb2Header.Read(d.ProcessMessage(connA, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\s\Files"))).TreeId;
        byte[] createResp = d.ProcessMessage(connA, TestHelpers.BuildCreateRequest(
            3, sid, tid, "lock.txt", 0x3, (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(createResp).Status);
        (ulong pid, ulong vid) = ExtractCreateFileId(createResp);

        // Channel B: bind (signed with the session key). Sink B collects its out-of-band responses.
        var connB = new SmbConnection();
        connB.SendRawAsync = (b, _) => { /* discarded; B is about to drop */ return Task.CompletedTask; };
        d.ProcessMessage(connB, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311], signingAlgs: [alg]));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(d.ProcessMessage(connB, TestHelpers.BuildSessionSetupRequest(
            1, sid, [0x01], signingKey: keyA, alg: alg, sessionFlags: SessionSetupFlags.Binding))).Status);

        // A blocking LOCK on channel B → interim STATUS_PENDING (the manager blocks).
        byte[] interim = d.ProcessMessage(connB, TestHelpers.BuildLockRequest(
            2, sid, tid, pid, vid, [(0, 10, (uint)LockFlags.ExclusiveLock)]));
        Smb2Header ih = Smb2Header.Read(interim);
        Assert.Equal(NtStatus.Pending, ih.Status);
        Assert.NotEqual(0ul, ih.AsyncId);

        // Channel B drops while the lock is still blocked. The session survives on channel A, so the
        // pending lock is NOT cancelled.
        connB.SendRawAsync = null;
        d.OnConnectionClosed(connB);
        Assert.True(state.SessionGlobalList.ContainsKey(sid));
        Assert.False(session.Channels.ContainsKey(connB.ConnectionId));

        // The lock is granted → the final response reroutes to the surviving channel A.
        gated.Complete(LockOutcome.Granted);
        Smb2Header fh = Smb2Header.Read(await WaitForSend(sinkA));
        Assert.Equal(NtStatus.Success, fh.Status);
        Assert.Equal(SmbCommand.Lock, fh.Command);
        Assert.Equal(ih.AsyncId, fh.AsyncId);
    }

    private static async Task<byte[]> WaitForSend(ConcurrentQueue<byte[]> queue)
    {
        for (int i = 0; i < 150; i++)
        {
            if (queue.TryDequeue(out byte[]? msg)) return msg;
            await Task.Delay(20);
        }
        throw new Xunit.Sdk.XunitException("No rerouted out-of-band response received in time.");
    }

    private static (ulong persistent, ulong vol) ExtractCreateFileId(byte[] response)
    {
        const int body = Smb2Header.Size;
        ulong persistent = BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 64, 8));
        ulong vol = BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 72, 8));
        return (persistent, vol);
    }

    private sealed class GatedLockManager : ILockManager
    {
        private readonly TaskCompletionSource<LockOutcome> _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> e, bool fail, CancellationToken ct)
        {
            ct.Register(() => _tcs.TrySetResult(LockOutcome.Cancelled));
            return _tcs.Task;
        }
        public void Complete(LockOutcome outcome) => _tcs.TrySetResult(outcome);
        public bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool forWrite) => true;
        public void ReleaseOwner(SmbOpen owner) { }
    }
}
