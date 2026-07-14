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
    private readonly object _gate = new();
    private byte[] _output = [];

    public RpcPipe(IRpcEndpoint endpoint) => _endpoint = endpoint;

    /// <summary>The bound endpoint (e.g. to detect a witness pipe for the long-pending AsyncNotify path).</summary>
    public IRpcEndpoint Endpoint => _endpoint;

    /// <summary>Processes an incoming PDU and returns the response PDU (also buffered for READ).</summary>
    public byte[] Transceive(ReadOnlySpan<byte> requestPdu)
    {
        // Locked because READ/WRITE frames (including on pipe opens) may be processed concurrently
        // (docs/ASYNC_IO_ROADMAP.md, A4). The endpoint itself is stateless per PDU.
        byte[] output = _endpoint.HandlePdu(requestPdu);
        lock (_gate) _output = output;
        return output;
    }

    /// <summary>Returns the last buffered response (for the WRITE→READ pattern) and clears the buffer.</summary>
    public byte[] TakeOutput()
    {
        lock (_gate)
        {
            byte[] o = _output;
            _output = [];
            return o;
        }
    }
}
