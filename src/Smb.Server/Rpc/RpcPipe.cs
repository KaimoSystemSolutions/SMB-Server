namespace Smb.Server.Rpc;

/// <summary>Ein DCERPC-Endpoint (z.B. srvsvc), der eine PDU verarbeitet und eine Antwort-PDU liefert.</summary>
public interface IRpcEndpoint
{
    byte[] HandlePdu(ReadOnlySpan<byte> pdu);
}

/// <summary>
/// Zustand einer offenen RPC-Named-Pipe (z.B. <c>\PIPE\srvsvc</c> auf IPC$). Puffert die
/// Antwort-PDU für das Write→Read-Muster; bei FSCTL_PIPE_TRANSCEIVE wird direkt geantwortet.
/// </summary>
public sealed class RpcPipe
{
    private readonly IRpcEndpoint _endpoint;
    private byte[] _output = [];

    public RpcPipe(IRpcEndpoint endpoint) => _endpoint = endpoint;

    /// <summary>Verarbeitet eine eingehende PDU und gibt die Antwort-PDU zurück (auch gepuffert für READ).</summary>
    public byte[] Transceive(ReadOnlySpan<byte> requestPdu)
    {
        _output = _endpoint.HandlePdu(requestPdu);
        return _output;
    }

    /// <summary>Liefert die zuletzt gepufferte Antwort (für das WRITE→READ-Muster) und leert den Puffer.</summary>
    public byte[] TakeOutput()
    {
        byte[] o = _output;
        _output = [];
        return o;
    }
}
