using System.Buffers.Binary;
using System.Collections.Concurrent;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// [W1] Break-before-grant (MS-SMB2 §3.3.5.9.8): a CREATE that costs another holder its write/handle
/// caching does not get its response — and with it the FileId — until the holder has acknowledged the
/// break or the break has timed out. Before W1 the holder was downgraded in state while its dirty pages
/// were still client-side, so the second opener could read stale data (baseline finding #2), and a holder
/// that never acknowledged was never cleaned up (#3).
/// <para>
/// The cases below cover, in order: the park→ack→complete round trip, the deadlock that the roadmap's
/// W1.0 analysis predicted (the acknowledgment arriving on the same connection as the parked CREATE), the
/// timeout when no acknowledgment comes, a late acknowledgment being a clean no-op, a break that needs no
/// acknowledgment not parking anything, and the documented opt-out.
/// </para>
/// </summary>
public class BreakBeforeGrantTests : IDisposable
{
    private readonly string _shareDir;
    private const byte LeaseOplock = 0xFF;   // SMB2_OPLOCK_LEVEL_LEASE
    private readonly ManualTimeProvider _time = new(DateTimeOffset.UnixEpoch);

    public BreakBeforeGrantTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbbbg_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "doc.txt"), new string('x', 100));
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    [Fact]
    public async Task ConflictingCreate_ParksBehindBreak_AndCompletesOnAcknowledgment()
    {
        var lab = Setup();

        // Holder takes a Batch oplock (solo open) and answers synchronously — nothing to break.
        byte[] first = lab.Open(10, oplock: (byte)OplockLevel.Batch);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(first).Status);
        (ulong fp, ulong fv) = CreateFileId(first);

        // Second open breaks the holder Batch→LevelII: it must flush, so this CREATE parks.
        Assert.Empty(lab.Open(11, oplock: (byte)OplockLevel.Batch));   // no in-band response at all

        // What went out instead, and in this order: the STATUS_PENDING interim first, only then the
        // notification — otherwise the holder could acknowledge before the client has seen the AsyncId the
        // final response is tagged with (§2.2.24).
        byte[] interim = await lab.NextSent();
        Smb2Header ih = Smb2Header.Read(interim);
        Assert.Equal(NtStatus.Pending, ih.Status);
        Assert.Equal(SmbCommand.Create, ih.Command);
        Assert.Equal(11ul, ih.MessageId);
        Assert.True(ih.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand));
        Assert.NotEqual(0ul, ih.AsyncId);

        byte[] notify = await lab.NextSent();
        Assert.Equal(SmbCommand.OplockBreak, Smb2Header.Read(notify).Command);
        Assert.Equal(0xFFFFFFFFFFFFFFFFul, Smb2Header.Read(notify).MessageId);

        // Still parked: no final response before the acknowledgment.
        Assert.False(await lab.AnythingSentWithin(TimeSpan.FromMilliseconds(150)));
        Assert.Equal(1, lab.Metrics.PendingBreaks);

        // Holder acknowledges → the CREATE completes out-of-band, tagged with the interim's AsyncId.
        byte[] ackResponse = lab.Dispatcher.ProcessMessage(lab.Connection,
            TestHelpers.BuildOplockBreakAck(12, lab.SessionId, lab.TreeId, fp, fv, (byte)OplockLevel.LevelII));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(ackResponse).Status);

        byte[] final = await lab.NextSent();
        Smb2Header fh = Smb2Header.Read(final);
        Assert.Equal(NtStatus.Success, fh.Status);
        Assert.Equal(SmbCommand.Create, fh.Command);
        Assert.Equal(11ul, fh.MessageId);
        Assert.Equal(ih.AsyncId, fh.AsyncId);                       // correlates with the interim
        Assert.Equal((byte)OplockLevel.LevelII, GrantedOplock(final));
        Assert.NotEqual((0ul, 0ul), CreateFileId(final));           // the FileId the client was waiting for

        Assert.Equal(0, lab.Metrics.PendingBreaks);
        Assert.Equal(1, lab.Metrics.OplockBreaksSent);
        Assert.Equal(0, lab.Metrics.OplockBreakTimeouts);
    }

    /// <summary>
    /// The failure mode the roadmap's W1.0 analysis predicted: the acknowledgment that releases a parked
    /// CREATE arrives on the same connection the CREATE came in on. It deadlocks if the CREATE's *frame*
    /// stays in flight while parked, because OPLOCK_BREAK runs as a barrier that first drains all in-flight
    /// frames. Parking the response rather than the frame is what avoids it — and this test is the proof,
    /// driven through the real host read loop rather than the dispatcher, so the barrier is really there.
    /// </summary>
    [Fact]
    public async Task AcknowledgmentOnTheSameConnection_ReleasesParkedCreate_WithoutDeadlock()
    {
        var lab = Setup();

        byte[] first = lab.Open(10, oplock: (byte)OplockLevel.Batch);
        (ulong fp, ulong fv) = CreateFileId(first);
        Assert.Empty(lab.Open(11, oplock: (byte)OplockLevel.Batch));
        await lab.NextSent();   // interim
        await lab.NextSent();   // break notification

        // The acknowledgment is dispatched while the CREATE is parked. If the CREATE still occupied the
        // connection, this would not even be read until the break timed out (35 s).
        Task<byte[]> ack = Task.Run(() => lab.Dispatcher.ProcessMessage(lab.Connection,
            TestHelpers.BuildOplockBreakAck(12, lab.SessionId, lab.TreeId, fp, fv, (byte)OplockLevel.LevelII)));

        Assert.Same(ack, await Task.WhenAny(ack, Task.Delay(TimeSpan.FromSeconds(5))));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(await ack).Status);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(await lab.NextSent()).Status);   // the parked CREATE's final
    }

    [Fact]
    public async Task NoAcknowledgment_BreakTimesOut_AndCreateCompletesAnyway()
    {
        var lab = Setup();

        lab.Open(10, oplock: (byte)OplockLevel.Batch);
        Assert.Empty(lab.Open(11, oplock: (byte)OplockLevel.Batch));
        await lab.NextSent();   // interim
        await lab.NextSent();   // break notification

        // Holder stays silent. A client that stops acknowledging must not be able to freeze another
        // client's CREATE — that would be the very freeze W1 exists to remove, only self-inflicted.
        Assert.False(await lab.AnythingSentWithin(TimeSpan.FromMilliseconds(150)));

        _time.Advance(TimeSpan.FromSeconds(35));   // drive the clock: the suite must stay fast and non-flaky

        byte[] final = await lab.NextSent();
        Assert.Equal(NtStatus.Success, Smb2Header.Read(final).Status);
        Assert.Equal((byte)OplockLevel.LevelII, GrantedOplock(final));
        Assert.Equal(1, lab.Metrics.OplockBreakTimeouts);
        Assert.Equal(0, lab.Metrics.PendingBreaks);
    }

    [Fact]
    public async Task AcknowledgmentAfterTheTimeout_IsAnsweredButReleasesNothing()
    {
        var lab = Setup();

        byte[] first = lab.Open(10, oplock: (byte)OplockLevel.Batch);
        (ulong fp, ulong fv) = CreateFileId(first);
        lab.Open(11, oplock: (byte)OplockLevel.Batch);
        await lab.NextSent();
        await lab.NextSent();
        _time.Advance(TimeSpan.FromSeconds(35));
        await lab.NextSent();   // the CREATE already went ahead

        // The late acknowledgment is still a valid frame and gets its normal OPLOCK_BREAK response
        // (§2.2.25.1) — it just has no waiter left to release, and must not resurrect one.
        byte[] ack = lab.Dispatcher.ProcessMessage(lab.Connection,
            TestHelpers.BuildOplockBreakAck(12, lab.SessionId, lab.TreeId, fp, fv, (byte)OplockLevel.LevelII));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(ack).Status);
        Assert.Equal(SmbCommand.OplockBreak, Smb2Header.Read(ack).Command);

        Assert.False(await lab.AnythingSentWithin(TimeSpan.FromMilliseconds(150)));   // no second final
        Assert.Equal(1, lab.Metrics.OplockBreakTimeouts);                             // counted once, not twice
        Assert.Equal(0, lab.Metrics.PendingBreaks);
    }

    /// <summary>
    /// §2.2.23.2: a downgrade that costs the holder only read caching needs no acknowledgment — there is
    /// nothing to flush. Waiting for one would stall the CREATE until the timeout for no benefit, which is
    /// exactly the "waiting where Windows does not expect it is a new stall" trap.
    /// </summary>
    [Fact]
    public void BreakThatNeedsNoAcknowledgment_DoesNotPark()
    {
        var lab = Setup();

        // Holder caches reads only (R). A second distinct lease key still forces a break decision in the
        // manager, but R→R takes nothing away that has to be flushed.
        byte[] first = lab.OpenWithLease(10, Key(0x01), LeaseState.Read);
        Assert.Equal(LeaseState.Read, GrantedLeaseState(first));

        byte[] second = lab.OpenWithLease(11, Key(0x02), LeaseState.Read);
        Assert.Equal(NtStatus.Success, Smb2Header.Read(second).Status);   // answered in-band, not parked
        Assert.Equal(0, lab.Metrics.OplockBreaksSent);
    }

    [Fact]
    public void ZeroBreakTimeout_DisablesBlocking_AndCreateAnswersImmediately()
    {
        // The documented opt-out (SmbServerOptions.OplockBreakTimeout <= 0): the pre-W1 behaviour, for a
        // deployment that would rather have a stale read than any wait.
        var lab = Setup(breakTimeout: TimeSpan.Zero);

        lab.Open(10, oplock: (byte)OplockLevel.Batch);
        byte[] second = lab.Open(11, oplock: (byte)OplockLevel.Batch);

        Assert.Equal(NtStatus.Success, Smb2Header.Read(second).Status);
        Assert.Equal((byte)OplockLevel.LevelII, GrantedOplock(second));
        Assert.Equal(0, lab.Metrics.OplockBreaksSent);
    }

    [Fact]
    public async Task LeaseBreak_LosingWriteCaching_ParksUntilTheLeaseAcknowledgment()
    {
        var lab = Setup();
        byte[] k1 = Key(0x01), k2 = Key(0x02);

        Assert.Equal(LeaseState.ReadWriteHandle, GrantedLeaseState(lab.OpenWithLease(10, k1, LeaseState.ReadWriteHandle)));

        // Distinct second key → the holder loses W and H → ack required → park.
        Assert.Empty(lab.OpenWithLease(11, k2, LeaseState.ReadWriteHandle));
        Assert.Equal(NtStatus.Pending, Smb2Header.Read(await lab.NextSent()).Status);
        Assert.Equal(SmbCommand.OplockBreak, Smb2Header.Read(await lab.NextSent()).Command);
        Assert.False(await lab.AnythingSentWithin(TimeSpan.FromMilliseconds(150)));

        // The lease acknowledgment carries no FileId — it is matched by lease key (§2.2.24.2). Matching it
        // by anything else is how F2 happened one command over.
        lab.Dispatcher.ProcessMessage(lab.Connection,
            TestHelpers.BuildLeaseBreakAck(12, lab.SessionId, lab.TreeId, k1, LeaseState.Read));

        byte[] final = await lab.NextSent();
        Assert.Equal(NtStatus.Success, Smb2Header.Read(final).Status);
        Assert.Equal(LeaseState.Read, GrantedLeaseState(final));
    }

    /// <summary>
    /// §3.3.5.9.8: the wait ends on the acknowledgment <b>or the Open being closed</b>. The Windows
    /// redirector answers a batch break on a deferred-close handle with a CLOSE and never an ack — the
    /// Explorer .lnk-creation pattern. Before the close completed the wait, every such reopen stalled
    /// for the full OplockBreakTimeout (35 s).
    /// </summary>
    [Fact]
    public async Task HolderCloses_InsteadOfAcknowledging_ReleasesParkedCreate()
    {
        var lab = Setup();

        byte[] first = lab.Open(10, oplock: (byte)OplockLevel.Batch);
        (ulong fp, ulong fv) = CreateFileId(first);
        Assert.Empty(lab.Open(11, oplock: (byte)OplockLevel.Batch));
        await lab.NextSent();   // interim
        await lab.NextSent();   // break notification
        Assert.False(await lab.AnythingSentWithin(TimeSpan.FromMilliseconds(150)));

        // The holder closes its handle instead of acknowledging.
        Assert.Equal(NtStatus.Success, Smb2Header.Read(lab.Close(12, fp, fv)).Status);

        // The parked CREATE completes promptly — no clock advance, so this is the close, not the timeout.
        byte[] final = await lab.NextSent();
        Assert.Equal(NtStatus.Success, Smb2Header.Read(final).Status);
        Assert.Equal(SmbCommand.Create, Smb2Header.Read(final).Command);
        Assert.Equal(0, lab.Metrics.PendingBreaks);
        Assert.Equal(0, lab.Metrics.OplockBreakTimeouts);   // resolved by close, not by clock
    }

    /// <summary>An ack for an already-closed FileId is answered FILE_CLOSED and must not touch the tracker.</summary>
    [Fact]
    public async Task LateAcknowledgment_AfterHolderClose_IsFileClosed_AndReleasesNothing()
    {
        var lab = Setup();

        byte[] first = lab.Open(10, oplock: (byte)OplockLevel.Batch);
        (ulong fp, ulong fv) = CreateFileId(first);
        Assert.Empty(lab.Open(11, oplock: (byte)OplockLevel.Batch));
        await lab.NextSent();
        await lab.NextSent();
        lab.Close(12, fp, fv);
        await lab.NextSent();   // the parked CREATE's final, released by the close

        byte[] ack = lab.Dispatcher.ProcessMessage(lab.Connection,
            TestHelpers.BuildOplockBreakAck(13, lab.SessionId, lab.TreeId, fp, fv, (byte)OplockLevel.LevelII));
        Assert.Equal(NtStatus.FileClosed, Smb2Header.Read(ack).Status);

        Assert.False(await lab.AnythingSentWithin(TimeSpan.FromMilliseconds(150)));   // no second final
        Assert.Equal(0, lab.Metrics.PendingBreaks);
        Assert.Equal(0, lab.Metrics.OplockBreakTimeouts);
    }

    /// <summary>
    /// The lease variant is stricter (§3.3.5.9.8): a lease survives until <b>all</b> opens sharing its
    /// key are gone, so closing one of two same-key opens must not release the waiter — only the last
    /// close does. ILeaseManager.ReleaseOwner's return value is what encodes "that was the last one".
    /// </summary>
    [Fact]
    public async Task LeaseHolder_TwoOpensSameKey_ReleasesOnlyWhenLastCloses()
    {
        var lab = Setup();
        byte[] k1 = Key(0x01), k2 = Key(0x02);

        byte[] firstOpen = lab.OpenWithLease(10, k1, LeaseState.ReadWriteHandle);
        (ulong p1, ulong v1) = CreateFileId(firstOpen);
        byte[] secondOpen = lab.OpenWithLease(11, k1, LeaseState.ReadWriteHandle);   // joins the same lease
        Assert.Equal(NtStatus.Success, Smb2Header.Read(secondOpen).Status);
        (ulong p2, ulong v2) = CreateFileId(secondOpen);

        // A distinct key costs the holder W+H → ack required → the CREATE parks.
        Assert.Empty(lab.OpenWithLease(12, k2, LeaseState.ReadWriteHandle));
        await lab.NextSent();   // interim
        await lab.NextSent();   // lease-break notification

        // First same-key open closes → the lease is still held by the second → still parked.
        Assert.Equal(NtStatus.Success, Smb2Header.Read(lab.Close(13, p1, v1)).Status);
        Assert.False(await lab.AnythingSentWithin(TimeSpan.FromMilliseconds(150)));

        // Last same-key open closes → the lease is fully released → the waiter proceeds.
        Assert.Equal(NtStatus.Success, Smb2Header.Read(lab.Close(14, p2, v2)).Status);
        byte[] final = await lab.NextSent();
        Assert.Equal(NtStatus.Success, Smb2Header.Read(final).Status);
        Assert.Equal(SmbCommand.Create, Smb2Header.Read(final).Command);
        Assert.Equal(0, lab.Metrics.PendingBreaks);
        Assert.Equal(0, lab.Metrics.OplockBreakTimeouts);
    }

    /// <summary>
    /// A holder whose connection tears down can never acknowledge — its opens are reaped by
    /// DetachSessionOpens, which must count as the §3.3.5.9.8 close. The parked CREATE lives on a
    /// different connection and must be released promptly, not after 35 s.
    /// </summary>
    [Fact]
    public async Task HolderConnectionTeardown_ReleasesParkedCreate()
    {
        var holder = Setup();
        var parker = SecondClient(holder);

        holder.Open(10, oplock: (byte)OplockLevel.Batch);
        Assert.Empty(parker.Open(20, oplock: (byte)OplockLevel.Batch));
        await parker.NextSent();   // interim → to the parked CREATE's connection
        await holder.NextSent();   // break notification → to the holder's connection
        Assert.False(await parker.AnythingSentWithin(TimeSpan.FromMilliseconds(150)));

        // The holder's connection drops (client vanished). No ack will ever come from it.
        await holder.Dispatcher.OnConnectionClosedAsync(holder.Connection);

        byte[] final = await parker.NextSent();
        Assert.Equal(NtStatus.Success, Smb2Header.Read(final).Status);
        Assert.Equal(SmbCommand.Create, Smb2Header.Read(final).Command);
        Assert.Equal(0, parker.Metrics.PendingBreaks);
        Assert.Equal(0, parker.Metrics.OplockBreakTimeouts);
    }

    /// <summary>
    /// Wire shape of the classic oplock-break notification (§3.3.4.6): TreeId 0, the holder's SessionId,
    /// and UNSIGNED even on a signing-required session (§3.2.5.1.3 exempts MessageId 0xFFFF…FF from
    /// verification; Windows never signs break notifications). The regression guard is the other half:
    /// the parked CREATE's <b>final</b> on that same session must stay signed — unsigning the
    /// notification must not bleed into ordinary responses (the F1/F5 family, walked backwards).
    /// </summary>
    [Fact]
    public async Task OplockBreakNotification_OnSignedSession_IsUnsigned_WithZeroTreeId_ButFinalStaysSigned()
    {
        var lab = Setup(requireSigning: true);

        byte[] first = lab.Open(10, oplock: (byte)OplockLevel.Batch);
        (ulong fp, ulong fv) = CreateFileId(first);
        Assert.Empty(lab.Open(11, oplock: (byte)OplockLevel.Batch));

        byte[] interim = await lab.NextSent();
        Assert.Equal(NtStatus.Pending, Smb2Header.Read(interim).Status);

        byte[] notify = await lab.NextSent();
        Smb2Header nh = Smb2Header.Read(notify);
        Assert.Equal(SmbCommand.OplockBreak, nh.Command);
        Assert.Equal(0xFFFFFFFFFFFFFFFFul, nh.MessageId);
        Assert.Equal(0u, nh.TreeId);                                    // §3.3.4.6
        Assert.Equal(lab.SessionId, nh.SessionId);                      // classic break keeps the session id
        Assert.False(nh.Flags.HasFlag(Smb2HeaderFlags.Signed),
            "a break notification must go out unsigned — a client that tries to verify it discards it, " +
            "the holder never acks, and the parked CREATE waits out the break timeout.");

        lab.Dispatcher.ProcessMessage(lab.Connection, TestHelpers.BuildOplockBreakAck(
            12, lab.SessionId, lab.TreeId, fp, fv, (byte)OplockLevel.LevelII, lab.SigningKey));

        byte[] final = await lab.NextSent();
        Assert.Equal(NtStatus.Success, Smb2Header.Read(final).Status);
        Assert.True(Smb2Header.Read(final).Flags.HasFlag(Smb2HeaderFlags.Signed),
            "the parked CREATE's final must stay signed on a signing-required session (F5).");
    }

    /// <summary>Lease-break notification shape (§3.3.4.7): SessionId 0, TreeId 0, unsigned (unencrypted session).</summary>
    [Fact]
    public async Task LeaseBreakNotification_HasZeroSessionAndTree_AndIsUnsigned()
    {
        var lab = Setup();

        lab.OpenWithLease(10, Key(0x01), LeaseState.ReadWriteHandle);
        Assert.Empty(lab.OpenWithLease(11, Key(0x02), LeaseState.ReadWriteHandle));
        await lab.NextSent();   // interim

        byte[] notify = await lab.NextSent();
        Smb2Header nh = Smb2Header.Read(notify);
        Assert.Equal(SmbCommand.OplockBreak, nh.Command);
        Assert.Equal(0xFFFFFFFFFFFFFFFFul, nh.MessageId);
        Assert.Equal(0ul, nh.SessionId);   // §3.3.4.7 — the client routes by the LeaseKey in the body
        Assert.Equal(0u, nh.TreeId);
        Assert.False(nh.Flags.HasFlag(Smb2HeaderFlags.Signed));
    }

    // --- setup & helpers ---

    private Lab Setup(TimeSpan? breakTimeout = null, bool requireSigning = false)
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var metrics = new SmbServerMetricsProbe();
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = requireSigning,
            TimeProvider = _time,
            Metrics = metrics,
        };
        if (breakTimeout is { } t) options.OplockBreakTimeout = t;
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_shareDir, readOnly: false) });

        var state = new SmbServerState(options);
        var dispatcher = new Smb2Dispatcher(state);
        var conn = new SmbConnection();
        var sent = new ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311],
            signingAlgs: requireSigning ? [SmbSigningAlgorithmId.AesCmac] : null));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(SecurityBuffer(r1))));
        byte[]? signingKey = requireSigning ? state.SessionGlobalList[sessionId].SigningKey : null;
        uint treeId = Smb2Header.Read(dispatcher.ProcessMessage(conn,
            TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\s\Files", signingKey))).TreeId;

        return new Lab(dispatcher, conn, sessionId, treeId, sent, metrics, signingKey);
    }

    /// <summary>A second, independent client (own connection, session and out-of-band queue) against the
    /// same dispatcher — for cases where the break holder and the parked CREATE live on different
    /// connections (teardown of one must not be teardown of the other).</summary>
    private static Lab SecondClient(Lab first)
    {
        var conn = new SmbConnection();
        var sent = new ConcurrentQueue<byte[]>();
        conn.SendRawAsync = (b, _) => { sent.Enqueue(b); return Task.CompletedTask; };

        first.Dispatcher.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = first.Dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sessionId = Smb2Header.Read(r1).SessionId;
        first.Dispatcher.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sessionId, client.BuildAuthenticate(SecurityBuffer(r1))));
        uint treeId = Smb2Header.Read(first.Dispatcher.ProcessMessage(conn,
            TestHelpers.BuildTreeConnectRequest(3, sessionId, @"\\s\Files"))).TreeId;

        return first with { Connection = conn, SessionId = sessionId, TreeId = treeId, Sent = sent };
    }

    private sealed record Lab(
        Smb2Dispatcher Dispatcher, SmbConnection Connection, ulong SessionId, uint TreeId,
        ConcurrentQueue<byte[]> Sent, SmbServerMetricsProbe Metrics, byte[]? SigningKey = null)
    {
        /// <summary>A CREATE requesting a classic oplock. Returns the raw response — <b>empty when parked</b>.</summary>
        public byte[] Open(ulong mid, byte oplock) => Dispatcher.ProcessMessage(Connection,
            TestHelpers.BuildCreateRequest(mid, SessionId, TreeId, "doc.txt", desiredAccess: 0x00000003,
                disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile,
                signingKey: SigningKey, requestedOplockLevel: oplock));

        /// <summary>A CLOSE of the given FileId, answered in-band.</summary>
        public byte[] Close(ulong mid, ulong persistent, ulong vol) => Dispatcher.ProcessMessage(Connection,
            TestHelpers.BuildCloseRequest(mid, SessionId, TreeId, persistent, vol, SigningKey));

        /// <summary>A CREATE requesting a lease. Returns the raw response — <b>empty when parked</b>.</summary>
        public byte[] OpenWithLease(ulong mid, byte[] leaseKey, LeaseState requested) => Dispatcher.ProcessMessage(Connection,
            TestHelpers.BuildCreateRequest(mid, SessionId, TreeId, "doc.txt", desiredAccess: 0x00000003,
                disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile,
                requestedOplockLevel: LeaseOplock, createContexts: TestHelpers.BuildLeaseV1Context(leaseKey, requested)));

        /// <summary>The next out-of-band message, or a failure — never a silent pass on a missing send.</summary>
        public async Task<byte[]> NextSent()
        {
            for (int i = 0; i < 200; i++)
            {
                if (Sent.TryDequeue(out byte[]? msg)) return msg;
                await Task.Delay(10);
            }
            throw new Xunit.Sdk.XunitException("Expected an out-of-band message within the time limit; none arrived.");
        }

        /// <summary>True if anything was sent within <paramref name="window"/> — for asserting a CREATE stays parked.</summary>
        public async Task<bool> AnythingSentWithin(TimeSpan window)
        {
            DateTime deadline = DateTime.UtcNow + window;
            while (DateTime.UtcNow < deadline)
            {
                if (!Sent.IsEmpty) return true;
                await Task.Delay(10);
            }
            return false;
        }
    }

    /// <summary>Reads the break counters back without a diagnostics bridge (they are plain base-class state).</summary>
    private sealed class SmbServerMetricsProbe : Smb.Server.Diagnostics.SmbServerMetrics;

    private static byte[] Key(byte value)
    {
        var k = new byte[16];
        Array.Fill(k, value);
        return k;
    }

    private static byte GrantedOplock(byte[] message) => message[Smb2Header.Size + 2];

    private static (ulong persistent, ulong vol) CreateFileId(byte[] response)
    {
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(response.AsSpan(body + 72, 8)));
    }

    private static LeaseState GrantedLeaseState(byte[] message)
    {
        int off = (int)BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(Smb2Header.Size + 80, 4));
        int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(Smb2Header.Size + 84, 4));
        CreateContext? lease = CreateContextList.Find(CreateContextList.Parse(message, off, len), CreateContextNames.Lease);
        Assert.NotNull(lease);
        return LeaseRequest.FromContext(lease!).RequestedState;   // the response context carries the granted state
    }

    private static byte[] SecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    /// <summary>
    /// Deterministic <see cref="TimeProvider"/> that also drives <see cref="ITimer"/>s — the break timeout
    /// is armed via <c>TimeProvider.CreateTimer</c>, so a provider that only overrides <c>GetUtcNow</c>
    /// (as the durable-handle tests use) would leave the timer on the real clock and the test would
    /// either sleep 35 s or flake.
    /// </summary>
    private sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
    {
        private readonly object _gate = new();
        private readonly List<FakeTimer> _timers = [];
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() { lock (_gate) return _now; }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new FakeTimer(this, callback, state, dueTime);
            lock (_gate) _timers.Add(timer);
            return timer;
        }

        public void Advance(TimeSpan by)
        {
            FakeTimer[] due;
            lock (_gate)
            {
                _now += by;
                due = _timers.Where(t => t.DueAt is { } d && d <= _now).ToArray();
            }
            foreach (FakeTimer t in due) t.Fire();
        }

        private void Remove(FakeTimer timer) { lock (_gate) _timers.Remove(timer); }

        private sealed class FakeTimer(ManualTimeProvider owner, TimerCallback callback, object? state, TimeSpan dueTime) : ITimer
        {
            public DateTimeOffset? DueAt { get; private set; } =
                dueTime == Timeout.InfiniteTimeSpan ? null : owner.GetUtcNow() + dueTime;

            public void Fire()
            {
                if (DueAt is null) return;
                DueAt = null;
                callback(state);
            }

            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                DueAt = dueTime == Timeout.InfiniteTimeSpan ? null : owner.GetUtcNow() + dueTime;
                return true;
            }

            public void Dispose() { DueAt = null; owner.Remove(this); }
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
