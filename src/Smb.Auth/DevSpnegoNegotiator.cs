using Smb.Auth.Oids;

namespace Smb.Auth;

/// <summary>
/// <b>For development/testing only.</b> An SPNEGO negotiator that accepts every authentication
/// anonymously in a single step and returns a deterministic session key. This lets the complete
/// SMB path (negotiate → session setup → key derivation → signing) be exercised without real
/// NTLM/Kerberos. In production, replace it with a real <see cref="ISpnegoNegotiator"/>
/// (NTLM/Kerberos) — guest/anonymous is rejected by default (Context §8.4, §20).
/// </summary>
public sealed class DevSpnegoNegotiator : ISpnegoNegotiator
{
    private readonly byte[] _sessionKey;
    private readonly SecurityIdentity _identity;

    public DevSpnegoNegotiator(byte[]? sessionKey = null, SecurityIdentity? identity = null)
    {
        _sessionKey = sessionKey ?? CreateDeterministicKey();
        _identity = identity ?? new SecurityIdentity
        {
            DomainName = "WORKGROUP",
            UserName = "dev",
            IsAnonymous = true,
        };
    }

    public byte[] CreateInitialServerToken()
        => SpnegoTokens.CreateNegTokenInit2([GssOids.Ntlm]);

    public ISpnegoServerContext CreateServerContext() => new Context(_sessionKey, _identity);

    private static byte[] CreateDeterministicKey()
    {
        var key = new byte[16];
        for (int i = 0; i < key.Length; i++) key[i] = (byte)(i + 1);
        return key;
    }

    private sealed class Context : ISpnegoServerContext
    {
        private readonly byte[] _key;
        private readonly SecurityIdentity _identity;

        public Context(byte[] key, SecurityIdentity identity)
        {
            _key = key;
            _identity = identity;
        }

        public GssResult Accept(ReadOnlySpan<byte> spnegoToken)
            => GssResult.Succeeded((byte[])_key.Clone(), _identity);
    }
}
