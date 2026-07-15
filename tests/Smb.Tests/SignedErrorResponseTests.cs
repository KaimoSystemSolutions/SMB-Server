using Smb.Auth;
using Smb.Auth.Ntlm;
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
/// §3.3.4.1.1: on a signed session the response to a signed request must itself be signed — <b>including</b>
/// error responses. This was the bug behind the Windows Explorer freezes: every <c>BuildError</c> path emitted
/// an unsigned response, and a Windows client that fails to verify a response signature does not fail the call,
/// it <i>discards the message</i> (§3.2.5.1.3). The operation then never completes and Explorer hangs until the
/// client's own timeout. Any status the server declines with (a missing file, a sharing violation, a denied
/// access) hit this, which is why it looked like "almost every operation freezes".
/// <para>
/// Both dispatch paths are covered because they assemble responses independently: the sequential path
/// (<see cref="Smb2Dispatcher.ProcessMessage"/>) and the concurrent path
/// (<see cref="Smb2Dispatcher.ExecutePreparedFrameAsync"/>), which is where CREATE/QUERY_INFO/READ actually
/// run once <see cref="SmbServerOptions.ConcurrentMetadataOps"/> is on — the configuration the freeze fix
/// recommends. The original fix landed on the sequential path only and the real client stayed broken.
/// </para>
/// </summary>
public class SignedErrorResponseTests
{
    private const uint FileReadData = 0x1;
    private static readonly SmbSigningAlgorithmId Alg = SmbSigningAlgorithmId.AesCmac;

    [Fact]
    public void SequentialPath_ErrorResponse_ToSignedRequest_IsSigned()
    {
        using var lab = new SignedSessionLab(concurrentMetadata: false);

        // CREATE of a file that does not exist → STATUS_OBJECT_NAME_NOT_FOUND via BuildError.
        byte[] response = lab.Dispatcher.ProcessMessage(lab.Connection, lab.SignedCreate(10, "missing.txt"));

        AssertSignedError(lab, response, 10, NtStatus.ObjectNameNotFound);
    }

    [Fact]
    public async Task ConcurrentPath_ErrorResponse_ToSignedRequest_IsSigned()
    {
        using var lab = new SignedSessionLab(concurrentMetadata: true);

        byte[] request = lab.SignedCreate(10, "missing.txt");
        Assert.True(lab.Dispatcher.TryBeginConcurrentFrame(lab.Connection, request, false, out var frame),
            "CREATE must take the concurrent path with ConcurrentMetadataOps on — otherwise this test " +
            "silently re-tests the sequential path.");
        byte[] response = await lab.Dispatcher.ExecutePreparedFrameAsync(lab.Connection, lab.Dispatcher.ReserveScope(frame));

        AssertSignedError(lab, response, 10, NtStatus.ObjectNameNotFound);
    }

    /// <summary>
    /// A successful response was always signed — this pins that the fix did not regress the success path
    /// (e.g. by double-signing, which would corrupt the signature over an already-signed buffer).
    /// </summary>
    [Fact]
    public void SuccessResponse_ToSignedRequest_IsStillSigned()
    {
        using var lab = new SignedSessionLab(concurrentMetadata: false);

        byte[] response = lab.Dispatcher.ProcessMessage(lab.Connection, lab.SignedCreate(10, "present.txt"));

        AssertSignedError(lab, response, 10, NtStatus.Success);
    }

    /// <summary>
    /// The converse rule: a response is signed because the <i>request</i> was, not unconditionally. An unsigned
    /// request on a session that does not require signing must still get an unsigned response — signing one
    /// would be just as unverifiable to the client as not signing a signed one.
    /// </summary>
    [Fact]
    public void UnsignedRequest_OnUnsignedSession_GetsUnsignedErrorResponse()
    {
        using var lab = new SignedSessionLab(concurrentMetadata: false, requireSigning: false);

        byte[] response = lab.Dispatcher.ProcessMessage(lab.Connection, lab.UnsignedCreate(10, "missing.txt"));

        Smb2Header header = Smb2Header.Read(response);
        Assert.Equal(NtStatus.ObjectNameNotFound, header.Status);
        Assert.False(header.Flags.HasFlag(Smb2HeaderFlags.Signed),
            "an unsigned request must not draw a signed response.");
    }

    private static void AssertSignedError(SignedSessionLab lab, byte[] response, ulong messageId, NtStatus expected)
    {
        Smb2Header header = Smb2Header.Read(response);
        Assert.Equal(expected, header.Status);
        Assert.True(header.Flags.HasFlag(Smb2HeaderFlags.Signed),
            $"the {expected} response carries no SMB2_FLAGS_SIGNED — a Windows client discards it and the " +
            "operation hangs until its timeout.");
        Assert.True(
            Smb2Signer.Verify(Alg, lab.SigningKey, response, messageId, isServer: true, isCancel: false),
            $"the {expected} response is flagged signed but its signature does not verify — the client " +
            "discards it just the same.");
    }

    /// <summary>An authenticated, signing-required session over a real backing directory with one file in it.</summary>
    private sealed class SignedSessionLab : IDisposable
    {
        public Smb2Dispatcher Dispatcher { get; }
        public SmbConnection Connection { get; }
        public byte[] SigningKey { get; }
        private readonly ulong _sessionId;
        private readonly uint _treeId;
        private readonly string _dir;

        public SignedSessionLab(bool concurrentMetadata, bool requireSigning = true)
        {
            _dir = Path.Combine(Path.GetTempPath(), "smb-signerr-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_dir);
            File.WriteAllText(Path.Combine(_dir, "present.txt"), "hello");

            var backend = new InMemoryIdentityBackend().AddUser("DOM", "alice", "pw");
            var options = new SmbServerOptions
            {
                ServerGuid = new byte[16],
                SpnegoNegotiator = new NtlmSpnegoNegotiator(backend, new NtlmServerOptions { NetbiosDomainName = "DOM" }),
                RequireMessageSigning = requireSigning,
                ConcurrentMetadataOps = concurrentMetadata,
            };
            options.Shares.Add(new Share
            {
                Name = "Files",
                Type = ShareType.Disk,
                FileStore = new LocalFileStore(_dir, readOnly: false),
            });

            var state = new SmbServerState(options);
            Dispatcher = new Smb2Dispatcher(state);
            Connection = new SmbConnection();

            Dispatcher.ProcessMessage(Connection, TestHelpers.BuildNegotiateRequest(
                [SmbDialect.Smb311], SmbSecurityMode.SigningEnabled, signingAlgs: [Alg]));

            var client = new NtlmClient("DOM", "alice", "pw");
            byte[] r1 = Dispatcher.ProcessMessage(Connection, TestHelpers.BuildSessionSetupRequest(1, 0, client.BuildNegotiate()));
            _sessionId = Smb2Header.Read(r1).SessionId;
            Dispatcher.ProcessMessage(Connection, TestHelpers.BuildSessionSetupRequest(
                2, _sessionId, client.BuildAuthenticate(ExtractSecurityBuffer(r1))));

            SmbSession session = state.SessionGlobalList[_sessionId];
            SigningKey = session.SigningKey;
            Assert.Equal(requireSigning, session.SigningRequired); // the premise of every case here

            _treeId = Smb2Header.Read(Dispatcher.ProcessMessage(Connection,
                TestHelpers.BuildTreeConnectRequest(3, _sessionId, @"\\s\Files", SigningKey, Alg))).TreeId;
        }

        public byte[] SignedCreate(ulong messageId, string name) => BuildCreate(messageId, name, SigningKey);
        public byte[] UnsignedCreate(ulong messageId, string name) => BuildCreate(messageId, name, null);

        private byte[] BuildCreate(ulong messageId, string name, byte[]? signingKey)
            => TestHelpers.BuildCreateRequest(messageId, _sessionId, _treeId, name, FileReadData,
                (uint)CreateDisposition.Open, (uint)CreateOptions.NonDirectoryFile, signingKey, Alg);

        private static byte[] ExtractSecurityBuffer(byte[] response)
        {
            const int body = Smb2Header.Size;
            int off = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 4, 2));
            int len = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(body + 6, 2));
            return len == 0 ? [] : response.AsSpan(off, len).ToArray();
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, recursive: true); } catch { /* best-effort */ }
        }
    }
}
