namespace Smb.Server.State;

/// <summary>
/// A single connection bound to an <see cref="SmbSession"/> for SMB 3.x multichannel
/// (Context §8.1 <c>Session.ChannelList</c>, §3.3.5.5.2). The <i>primary</i> channel is the
/// connection the session authenticated on; further channels are added via a
/// <c>SESSION_SETUP</c> carrying <c>SMB2_SESSION_FLAG_BINDING</c>.
/// </summary>
/// <remarks>
/// Each channel carries its own signing key: for 3.1.1 it is derived from the session key and the
/// channel's <b>own</b> preauth integrity hash (so it differs per channel, §3.3.5.5.3); for
/// 3.0/3.0.2 it equals the session signing key (the KDF has no preauth input there).
/// </remarks>
public sealed class SmbChannel
{
    public required SmbConnection Connection { get; init; }

    /// <summary>Per-channel signing key used for inbound verification and outbound signing on this connection.</summary>
    public required byte[] SigningKey { get; set; }
}
