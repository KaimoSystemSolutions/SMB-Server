namespace Smb.Server.Rpc;

/// <summary>A DCERPC endpoint (e.g. srvsvc) that processes a PDU and returns a response PDU.</summary>
public interface IRpcEndpoint
{
    byte[] HandlePdu(ReadOnlySpan<byte> pdu);
}

/// <summary>
/// State of an open RPC named pipe (e.g. <c>\PIPE\srvsvc</c> on IPC$). Buffers the
/// response PDU for the Write→Read pattern; for FSCTL_PIPE_TRANSCEIVE the response is
/// returned directly.
/// </summary>
public sealed class RpcPipe
{
    private readonly IRpcEndpoint _endpoint;
    private byte[] _output = [];

    public RpcPipe(IRpcEndpoint endpoint) => _endpoint = endpoint;

    /// <summary>Processes an incoming PDU and returns the response PDU (also buffered for READ).</summary>
    public byte[] Transceive(ReadOnlySpan<byte> requestPdu)
    {
        _output = _endpoint.HandlePdu(requestPdu);
        return _output;
    }

    /// <summary>Returns the last buffered response (for the WRITE→READ pattern) and clears the buffer.</summary>
    public byte[] TakeOutput()
    {
        byte[] o = _output;
        _output = [];
        return o;
    }
}
