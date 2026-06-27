using Smb.Auth;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.State;
using Xunit;

namespace Smb.Tests;

/// <summary>
/// Regression tests for fixes found during the 2026-06-27 code review (separate from the
/// 2026-06 security audit covered by <see cref="AuditFixTests"/>). Each test pins exactly one fix.
/// </summary>
public sealed class ReviewFixTests
{
    // --- A SESSION_SETUP for an already-Valid session must not tear the session down ---

    [Fact]
    public void SessionSetup_StraySetupOnValidSession_DoesNotTearItDown()
    {
        // A mechanism that authenticates once and then rejects further tokens — exactly how the
        // real NTLM mechanism behaves once it has reached its terminal (Done) state.
        var (d, state, conn) = Server(new OneShotNegotiator());

        d.ProcessMessage(conn, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        ulong sid = Smb2Header.Read(d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]))).SessionId;
        Assert.Equal(SessionState.Valid, state.SessionGlobalList[sid].State);

        // A stray/duplicate SESSION_SETUP for the now-valid session is rejected …
        byte[] resp = d.ProcessMessage(conn, TestHelpers.BuildSessionSetupRequest(2, sid, [0x02]));
        Assert.NotEqual(NtStatus.Success, Smb2Header.Read(resp).Status);

        // … but the live session survives (previously the failed re-auth deleted it).
        Assert.True(state.SessionGlobalList.ContainsKey(sid));
        Assert.Equal(SessionState.Valid, state.SessionGlobalList[sid].State);
    }

    private static (Smb2Dispatcher d, SmbServerState state, SmbConnection conn) Server(ISpnegoNegotiator negotiator)
    {
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = negotiator,
            RequireMessageSigning = false,
        };
        options.Shares.Add(Share.CreateIpc());
        var state = new SmbServerState(options);
        return (new Smb2Dispatcher(state), state, new SmbConnection());
    }

    // --- Global RequireEncryption must be enforced when no cipher can be negotiated ---

    [Fact]
    public void SessionSetup_RequireEncryption_RejectsClientThatCannotEncrypt()
    {
        // Non-anonymous identity so the session clears the guest/anonymous policy and reaches the
        // encryption check.
        var negotiator = new DevSpnegoNegotiator(new byte[16],
            new SecurityIdentity { DomainName = "DOM", UserName = "bob" });

        // (a) SMB 3.1.1 WITHOUT an encryption context → no cipher → cannot encrypt → rejected.
        var (d1, _, c1) = EncryptingServer(negotiator);
        d1.ProcessMessage(c1, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311]));
        byte[] noCipher = d1.ProcessMessage(c1, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
        Assert.Equal(NtStatus.AccessDenied, Smb2Header.Read(noCipher).Status);

        // (b) SMB 3.1.1 WITH a common cipher → can encrypt → succeeds.
        var (d2, _, c2) = EncryptingServer(negotiator);
        d2.ProcessMessage(c2, TestHelpers.BuildNegotiateRequest([SmbDialect.Smb311], ciphers: [SmbCipherId.Aes128Gcm]));
        byte[] withCipher = d2.ProcessMessage(c2, TestHelpers.BuildSessionSetupRequest(1, 0, [0x01]));
        Assert.Equal(NtStatus.Success, Smb2Header.Read(withCipher).Status);
    }

    private static (Smb2Dispatcher d, SmbServerState state, SmbConnection conn) EncryptingServer(ISpnegoNegotiator negotiator)
    {
        var options = new SmbServerOptions
        {
            ServerGuid = new byte[16],
            SpnegoNegotiator = negotiator,
            RequireMessageSigning = false,
            RequireEncryption = true,
        };
        options.Shares.Add(Share.CreateIpc());
        var state = new SmbServerState(options);
        return (new Smb2Dispatcher(state), state, new SmbConnection());
    }

    /// <summary>SPNEGO negotiator whose context succeeds on the first token and fails afterwards.</summary>
    private sealed class OneShotNegotiator : ISpnegoNegotiator
    {
        public byte[] CreateInitialServerToken() => [];
        public ISpnegoServerContext CreateServerContext() => new Context();

        private sealed class Context : ISpnegoServerContext
        {
            private bool _done;

            public GssResult Accept(ReadOnlySpan<byte> spnegoToken)
            {
                if (_done) return GssResult.Failed(NtStatus.AccessDenied);
                _done = true;
                var identity = new SecurityIdentity { DomainName = "DOM", UserName = "bob" };
                return GssResult.Succeeded(new byte[16], identity);
            }
        }
    }
}
