using Smb.Protocol.Compression;
using Smb.Protocol.Messages;
using Smb.Protocol.Messages.Fscc;
using Smb.Protocol.Security;
using Smb.Protocol.Wire;
using Smb.Server.Rpc;
using Smb.Server.Witness;

namespace Smb.Fuzz;

/// <summary>Invokes a single wire parser over an arbitrary input buffer (ref-struct safe).</summary>
public delegate void ParseTarget(ReadOnlySpan<byte> input);

/// <summary>
/// Registry of every fuzzed <see cref="Smb.Protocol"/> wire reader (plus the server NDR/witness stub
/// parsers), and the shared oracle that runs one input through a target and classifies the outcome.
/// </summary>
/// <remarks>
/// The parse contract every target must honour: given <b>any</b> byte sequence it must either succeed or
/// throw <see cref="SmbWireFormatException"/> — and always terminate. A leaked
/// <see cref="IndexOutOfRangeException"/>/<see cref="ArgumentException"/>/<see cref="OutOfMemoryException"/>
/// etc. is a hardening defect (the dispatcher maps only <see cref="SmbWireFormatException"/> to a clean
/// <c>STATUS_INVALID_PARAMETER</c>; anything else falls through the generic safety net or, for OOM, is a
/// genuine DoS). The fuzz tests assert that contract; this class is the shared machinery.
/// </remarks>
public static class WireParserFuzzHarness
{
    /// <summary>The outcome of running one input through one target.</summary>
    public enum Outcome
    {
        /// <summary>Parsed without throwing (a plausibly-valid or leniently-accepted frame).</summary>
        Parsed,
        /// <summary>Rejected cleanly with <see cref="SmbWireFormatException"/> — the expected malformed-input path.</summary>
        WireFormatRejected,
        /// <summary>Threw something other than <see cref="SmbWireFormatException"/> — a contract violation.</summary>
        UnexpectedThrow,
    }

    public static readonly IReadOnlyList<(string Name, ParseTarget Fn)> Targets = BuildTargets();

    /// <summary>Runs <paramref name="input"/> through <paramref name="target"/> and classifies the result.</summary>
    public static Outcome Run(ParseTarget target, ReadOnlySpan<byte> input, out Exception? unexpected)
    {
        unexpected = null;
        try
        {
            target(input);
            return Outcome.Parsed;
        }
        catch (SmbWireFormatException)
        {
            return Outcome.WireFormatRejected;
        }
        catch (Exception ex)
        {
            unexpected = ex;
            return Outcome.UnexpectedThrow;
        }
    }

    private static List<(string, ParseTarget)> BuildTargets() =>
    [
        ("Smb2Header.Read", b => Smb2Header.Read(b)),
        ("NegotiateRequest.Parse", b => NegotiateRequest.Parse(b, 0)),
        ("SessionSetupRequest.Parse", b => SessionSetupRequest.Parse(b, 0)),
        ("TreeConnectRequest.Parse", b => TreeConnectRequest.Parse(b, 0)),
        ("CreateRequest.Parse", b => CreateRequest.Parse(b, 0)),
        ("CreateContextList.Parse", b => CreateContextList.Parse(b, 0, b.Length)),
        ("CloseMessage.ParseRequest", b => CloseMessage.ParseRequest(b, 0)),
        ("ReadMessage.ParseRequest", b => ReadMessage.ParseRequest(b, 0)),
        ("WriteMessage.ParseRequest", b => WriteMessage.ParseRequest(b, 0)),
        ("QueryDirectoryMessage.ParseRequest", b => QueryDirectoryMessage.ParseRequest(b, 0)),
        ("QueryInfoMessage.ParseRequest", b => QueryInfoMessage.ParseRequest(b, 0)),
        ("SetInfoMessage.ParseRequest", b => SetInfoMessage.ParseRequest(b, 0)),
        ("SetInfoMessage.ParseRename", b => SetInfoMessage.ParseRename(b)),
        ("CancelMessage.ParseRequest", b => CancelMessage.ParseRequest(b, 0)),
        ("LockMessage.ParseRequest", b => LockMessage.ParseRequest(b, 0)),
        ("ChangeNotifyMessage.ParseRequest", b => ChangeNotifyMessage.ParseRequest(b, 0)),
        ("IoctlMessage.ParseRequest", b => IoctlMessage.ParseRequest(b, 0)),
        ("IoctlMessage.ParseValidateNegotiate", b => IoctlMessage.ParseValidateNegotiate(b)),
        ("DfsReferralMessage.ParseRequest", b => DfsReferralMessage.ParseRequest(b)),
        ("DfsReferralMessage.ParseRequestEx", b => DfsReferralMessage.ParseRequestEx(b)),
        ("FullEaInformation.Parse", b => FullEaInformation.Parse(b)),
        ("TransformHeader.Read", b => TransformHeader.Read(b)),
        ("CompressionTransformHeader.ReadUnchained", b => CompressionTransformHeader.ReadUnchained(b)),
        ("CompressionPayloadHeader.Read", b => CompressionPayloadHeader.Read(b)),
        ("Sid.Parse", b => Sid.Parse(b)),
        ("Ace.Parse", b => Ace.Parse(b, out _)),
        ("Acl.Parse", b => Acl.Parse(b, out _)),
        ("SecurityDescriptor.Parse", b => SecurityDescriptor.Parse(b)),
        ("SymlinkErrorResponse.Parse", b => SymlinkErrorResponse.Parse(b)),
        // Server-side stub readers (NDR is a wire reader too, and the witness Register stubs sit on IPC$).
        ("NdrReader.WideStringNullTerminated", b => DrainNdr(b)),
        ("WitnessWire.ParseRegister", b => WitnessWire.ParseRegister(b.ToArray())),
        ("WitnessWire.ParseRegisterEx", b => WitnessWire.ParseRegisterEx(b.ToArray())),
    ];

    // Exercises the NDR reader's alignment + conformant-varying string path (the shapes the witness
    // Register stub decodes). ReadOnlyMemory can't wrap a span, so copy the fuzz slice into an array.
    private static void DrainNdr(ReadOnlySpan<byte> b)
    {
        var reader = new NdrReader(b.ToArray());
        reader.UInt32();
        reader.WideStringNullTerminated();
    }
}
