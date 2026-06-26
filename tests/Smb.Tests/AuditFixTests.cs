using System.Buffers.Binary;
using System.Security.Cryptography;
using Smb.Auth;
using Smb.Crypto;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Authorization;
using Smb.Server.Locking;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Regressionstests für die Sicherheits-Audit-Fixes vom 2026-06 (Marker <c>[AUDIT-2026-06]</c> im
/// Code, Details in <c>docs/SECURITY_AUDIT.md</c>). Jeder Test nagelt genau ein Finding fest und
/// schlägt an, falls der Fix zurückgedreht wird.
/// </summary>
public sealed class AuditFixTests : IDisposable
{
    private readonly string _shareDir;

    public AuditFixTests()
    {
        _shareDir = Path.Combine(Path.GetTempPath(), "smbaudit_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_shareDir);
        File.WriteAllText(Path.Combine(_shareDir, "ro.txt"), "data");
        File.WriteAllText(Path.Combine(_shareDir, "lock.txt"), new string('x', 100));
    }

    public void Dispose()
    {
        try { Directory.Delete(_shareDir, true); } catch { /* ignore */ }
    }

    // --- Finding M4: LOGOFF muss auf signaturpflichtiger Session signiert sein ---

    [Fact]
    public void Logoff_Unsigned_RejectedWhenSigningRequired()
    {
        byte[] sessionKey = RandomNumberGenerator.GetBytes(16);
        var identity = new SecurityIdentity { DomainName = "DOM", UserName = "bob" };
        var (d, state, conn) = DevServer(requireSigning: true, negotiator: new DevSpnegoNegotiator(sessionKey, identity));

        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311], signingAlgs: [SmbSigningAlgorithmId.AesCmac]));
        Smb2Header ss = Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01])));
        SmbSession session = state.SessionGlobalList[ss.SessionId];
        SmbSigningAlgorithmId alg = Smb2Signer.ResolveAlgorithm(conn.Dialect, conn.SigningAlgorithmId);

        // Eingeschleustes, unsigniertes LOGOFF → ACCESS_DENIED, Session bleibt gültig.
        byte[] denied = d.ProcessMessage(conn, TestHelpers.BuildLogoffRequest(2, ss.SessionId));
        Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(denied).Status);
        Assert.Equal(SessionState.Valid, state.SessionGlobalList[ss.SessionId].State);

        // Korrekt signiertes LOGOFF → Success.
        byte[] ok = d.ProcessMessage(conn, TestHelpers.BuildLogoffRequest(3, ss.SessionId, session.SigningKey, alg));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(ok).Status);
    }

    // --- Finding H2: MessageId-Sequenzfenster wird durchgesetzt ---

    [Fact]
    public void SequenceWindow_RejectsReplayedAndOutOfWindowMessageId()
    {
        var (d, _, conn) = DevServer(requireSigning: false, negotiator: new DevSpnegoNegotiator());
        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        ulong sid = Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]))).SessionId;

        // Gültiges ECHO (mid=2) → Success; das Fenster rückt vor.
        Assert.Equal(NtStatus.Success, Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildEchoRequest(2, sid))).Status);

        // Replay derselben MessageId (jetzt unterhalb des Fensters) → InvalidParameter.
        Assert.Equal(NtStatus.InvalidParameter, Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildEchoRequest(2, sid))).Status);

        // MessageId weit jenseits der erteilten Credits → InvalidParameter.
        Assert.Equal(NtStatus.InvalidParameter, Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildEchoRequest(10_000_000, sid))).Status);
    }

    // --- Finding H3: DesiredAccess wird gegen die MaximalAccess der Policy durchgesetzt ---

    [Fact]
    public void Create_WriteAccess_DeniedWhenPolicyGrantsReadOnly()
    {
        // FileStore ist SCHREIBBAR — die Ablehnung muss also aus der Policy (ReadOnly) kommen, nicht
        // aus dem readOnly-Flag des Stores. So beweist der Test, dass MaximalAccess greift.
        var policy = new DelegateSharePolicy(authorize: _ => ShareAccessResult.Grant(SmbAccessMask.ReadOnly));
        var (d, conn, sid, tid) = FileServer(policy: policy, readOnlyStore: false);

        const uint fileReadData = 0x00000001, fileWriteData = 0x00000002;

        byte[] writeOpen = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            5, sid, tid, "ro.txt", desiredAccess: fileWriteData,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(writeOpen).Status);

        byte[] readOpen = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            6, sid, tid, "ro.txt", desiredAccess: fileReadData,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(readOpen).Status);
    }

    [Fact]
    public void Create_WriteAccess_AllowedWhenPolicyGrantsReadWrite()
    {
        // Gegenprobe: dieselbe schreibende Anforderung wird mit ausreichender MaximalAccess gewährt.
        var policy = new DelegateSharePolicy(authorize: _ => ShareAccessResult.Grant(SmbAccessMask.ReadWrite));
        var (d, conn, sid, tid) = FileServer(policy: policy, readOnlyStore: false);

        byte[] writeOpen = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            5, sid, tid, "ro.txt", desiredAccess: 0x00000002 /* FILE_WRITE_DATA */,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(writeOpen).Status);
    }

    // --- Finding H1: gleichzeitig ausstehende async-Operationen werden gedeckelt ---

    [Fact]
    public void OutstandingAsyncRequests_AreCappedPerConnection()
    {
        var (d, conn, sid, tid) = FileServer(
            policy: new AllowAllSharePolicy(), readOnlyStore: false,
            lockManager: new NeverGrantLockManager(), maxOutstanding: 2);
        conn.SendRawAsync = (_, _) => Task.CompletedTask; // out-of-band-Senke (finale Antworten)

        (ulong p, ulong v) = OpenLockFile(d, conn, sid, tid, mid: 5);

        // Zwei blockierende Locks → beide bleiben PENDING (zählen als ausstehend).
        Assert.Equal(NtStatus.Pending, BlockingLock(d, conn, sid, tid, p, v, mid: 6, offset: 0));
        Assert.Equal(NtStatus.Pending, BlockingLock(d, conn, sid, tid, p, v, mid: 7, offset: 100));

        // Dritter blockierender Lock überschreitet die Obergrenze → INSUFFICIENT_RESOURCES.
        Assert.Equal(NtStatus.InsufficientResources, BlockingLock(d, conn, sid, tid, p, v, mid: 8, offset: 200));
    }

    // --- Setup-Helfer ---

    private static (Smb2Dispatcher d, SmbServerState state, SmbConnection conn) DevServer(
        bool requireSigning, ISpnegoNegotiator negotiator)
    {
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = negotiator,
            RequireMessageSigning = requireSigning,
            AllowAnonymousAccess = true,
        };
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Data", Type = ShareType.Disk });
        var state = new SmbServerState(options);
        return (new Smb2Dispatcher(state), state, new SmbConnection());
    }

    private (Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid) FileServer(
        IShareAccessPolicy policy, bool readOnlyStore, ILockManager? lockManager = null, int maxOutstanding = 512)
    {
        var identity = new SecurityIdentity { DomainName = "DOM", UserName = "bob" };
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new DevSpnegoNegotiator(new byte[16], identity),
            RequireMessageSigning = false,
            AllowAnonymousAccess = true,
            ShareAccessPolicy = policy,
            MaxOutstandingRequests = maxOutstanding,
        };
        if (lockManager is not null) options.LockManager = lockManager;
        options.Shares.Add(Share.CreateIpc());
        options.Shares.Add(new Share { Name = "Files", Type = ShareType.Disk, FileStore = new LocalFileStore(_shareDir, readOnly: readOnlyStore) });

        var state = new SmbServerState(options);
        var d = new Smb2Dispatcher(state);
        var conn = new SmbConnection();

        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        ulong sid = Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]))).SessionId;
        uint tid = Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildTreeConnectRequest(2, sid, @"\\s\Files"))).TreeId;
        return (d, conn, sid, tid);
    }

    private static (ulong p, ulong v) OpenLockFile(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid, ulong mid)
    {
        byte[] create = d.ProcessMessage(conn, TestHelpers.BuildCreateRequest(
            mid, sid, tid, "lock.txt", desiredAccess: 0x00000003 /* read+write */,
            disposition: (uint)CreateDisposition.Open, options: (uint)CreateOptions.NonDirectoryFile));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(create).Status);
        const int body = Smb2Header.Size;
        return (BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 64, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(create.AsSpan(body + 72, 8)));
    }

    private static NtStatus BlockingLock(Smb2Dispatcher d, SmbConnection conn, ulong sid, uint tid,
        ulong p, ulong v, ulong mid, ulong offset)
    {
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildLockRequest(mid, sid, tid, p, v,
            [(offset, 10, (uint)LockFlags.ExclusiveLock)])); // ohne FAIL_IMMEDIATELY → blockierend
        return Smb2Header.Read(resp).Status;
    }

    /// <summary>Lock-Manager, der jede Anforderung dauerhaft "pending" hält (nur Abbruch via Token).</summary>
    private sealed class NeverGrantLockManager : ILockManager
    {
        public Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> e, bool fail, CancellationToken ct)
        {
            var tcs = new TaskCompletionSource<LockOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
            ct.Register(() => tcs.TrySetResult(LockOutcome.Cancelled));
            return tcs.Task;
        }
        public bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool forWrite) => true;
        public void ReleaseOwner(SmbOpen owner) { }
    }
}
