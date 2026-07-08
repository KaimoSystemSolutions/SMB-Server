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
/// Phase 8 / M8.2 — idle/auth timeouts. Drives the dispatcher's <see cref="Smb2Dispatcher.SweepIdleTimeouts"/>
/// against a <see cref="ManualTimeProvider"/>: idle sessions expire, idle / slow-auth connections get a
/// close request, and active ones are left alone.
/// </summary>
public class TimeoutTests
{
    private readonly ManualTimeProvider _time = new(DateTimeOffset.UnixEpoch);

    [Fact]
    public void IdleSession_IsExpiredAndReleased()
    {
        var (d, state, conn, sid) = LoginState();
        Assert.True(state.SessionGlobalList.ContainsKey(sid));

        _time.Advance(TimeSpan.FromMinutes(16)); // > SessionIdleTimeout (15 min)
        d.SweepIdleTimeouts();

        Assert.False(state.SessionGlobalList.ContainsKey(sid));
        Assert.False(conn.Sessions.ContainsKey(sid));
    }

    [Fact]
    public void ActiveSession_IsNotExpired()
    {
        var (d, state, _, sid) = LoginState();

        _time.Advance(TimeSpan.FromMinutes(5)); // < SessionIdleTimeout
        d.SweepIdleTimeouts();

        Assert.True(state.SessionGlobalList.ContainsKey(sid));
    }

    [Fact]
    public void SlowAuth_ConnectionIsAskedToClose()
    {
        var (d, state) = Server();
        bool closed = false;
        var conn = new SmbConnection
        {
            CreatedTicks = _time.GetUtcNow().Ticks,
            LastActivityTicks = _time.GetUtcNow().Ticks,
            RequestClose = () => closed = true,
        };
        state.Connections[conn.ConnectionId] = conn; // never authenticates

        _time.Advance(TimeSpan.FromSeconds(31)); // > AuthenticationTimeout (30 s)
        d.SweepIdleTimeouts();

        Assert.True(closed);
    }

    [Fact]
    public void AuthenticatedConnection_NotClosedByAuthTimeout()
    {
        var (d, state, conn, _) = LoginState();
        bool closed = false;
        conn.RequestClose = () => closed = true;

        _time.Advance(TimeSpan.FromSeconds(31)); // past auth timeout, but the connection has a valid session
        d.SweepIdleTimeouts();

        Assert.False(closed);
    }

    [Fact]
    public void IdleConnection_IsAskedToClose()
    {
        var (d, state, conn, _) = LoginState();
        bool closed = false;
        conn.RequestClose = () => closed = true;

        _time.Advance(TimeSpan.FromMinutes(6)); // > ConnectionIdleTimeout (5 min)
        d.SweepIdleTimeouts();

        Assert.True(closed);
    }

    // --- helpers ---

    private (Smb2Dispatcher d, SmbServerState state) Server()
    {
        var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
            RequireMessageSigning = false,
            TimeProvider = _time,
        };
        options.Shares.Add(Share.CreateIpc());
        var state = new SmbServerState(options);
        return (new Smb2Dispatcher(state), state);
    }

    private (Smb2Dispatcher d, SmbServerState state, SmbConnection conn, ulong sid) LoginState()
    {
        var (d, state) = Server();
        var conn = new SmbConnection { CreatedTicks = _time.GetUtcNow().Ticks, LastActivityTicks = _time.GetUtcNow().Ticks };
        state.Connections[conn.ConnectionId] = conn;

        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        var client = new NtlmClient("DOM", "alice", "pw");
        byte[] r1 = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
        ulong sid = Smb2Header.Read(r1).SessionId;
        d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sid, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));
        return (d, state, conn, sid);
    }

    private static byte[] ExtractSecurityBuffer(byte[] response)
    {
        const int body = Smb2Header.Size;
        int off = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
        int len = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
        return len == 0 ? [] : response.AsSpan(off, len).ToArray();
    }

    private sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }
}
