using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Smb.Protocol.Discovery;

/// <summary>
/// WS-Discovery constants (WS-Discovery 2005/04 profile, the version Windows uses for network browsing:
/// the "Function Discovery" provider in Explorer's Network view). SOAP 1.2 envelopes over UDP, multicast
/// group 239.255.255.250 (IPv4) / FF02::C (IPv6) on port 3702.
/// </summary>
public static class WsDiscoveryConstants
{
    public const string SoapNs = "http://www.w3.org/2003/05/soap-envelope";
    public const string WsaNs = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
    public const string WsdNs = "http://schemas.xmlsoap.org/ws/2005/04/discovery";

    public const string MulticastAddressV4 = "239.255.255.250";
    public const string MulticastAddressV6 = "FF02::C";
    public const int Port = 3702;

    public const string DiscoveryTo = "urn:schemas-xmlsoap-org:ws:2005:04:discovery";
    public const string AnonymousTo = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";

    public const string ProbeAction = WsdNs + "/Probe";
    public const string ProbeMatchesAction = WsdNs + "/ProbeMatches";
    public const string ResolveAction = WsdNs + "/Resolve";
    public const string ResolveMatchesAction = WsdNs + "/ResolveMatches";
    public const string HelloAction = WsdNs + "/Hello";
    public const string ByeAction = WsdNs + "/Bye";
}

/// <summary>
/// A WS-Discovery type in Clark/QName form (namespace + local name + preferred prefix). Types identify the
/// kind of device a Probe is looking for and that a ProbeMatch advertises.
/// </summary>
public readonly record struct WsDiscoveryQName(string Namespace, string LocalName, string Prefix)
{
    /// <summary>Clark notation "{namespace}localName" — the namespace-resolved identity used for matching.</summary>
    public string Clark => "{" + Namespace + "}" + LocalName;

    /// <summary><c>pub:Computer</c> — a Windows computer as shown in Explorer's network view.</summary>
    public static readonly WsDiscoveryQName Computer =
        new("http://schemas.microsoft.com/windows/pub/2005/07", "Computer", "pub");

    /// <summary><c>wsdp:Device</c> — a generic WS-Discovery device.</summary>
    public static readonly WsDiscoveryQName Device =
        new("http://schemas.xmlsoap.org/ws/2006/02/devprof", "Device", "wsdp");
}

/// <summary>A parsed WS-Discovery Probe: the request MessageID (for RelatesTo) and the requested types (Clark form).</summary>
public readonly record struct WsDiscoveryProbe(string MessageId, IReadOnlyList<string> Types);

/// <summary>
/// Pure WS-Discovery message parsing/building (no sockets). Parses inbound Probe envelopes and builds the
/// ProbeMatches / Hello / Bye responses. Keeps the discovery wire format in <c>Smb.Protocol</c> so it is
/// fully unit-testable; the UDP multicast plumbing lives in the host layer.
/// </summary>
public static class WsDiscoveryMessage
{
    private static readonly XNamespace Soap = WsDiscoveryConstants.SoapNs;
    private static readonly XNamespace Wsa = WsDiscoveryConstants.WsaNs;
    private static readonly XNamespace Wsd = WsDiscoveryConstants.WsdNs;

    /// <summary>Returns the wsa:Action of a WS-Discovery envelope, or null if it cannot be read.</summary>
    public static string? TryGetAction(ReadOnlySpan<byte> datagram)
    {
        XElement? header = TryParse(datagram)?.Root?.Element(Soap + "Header");
        return header?.Element(Wsa + "Action")?.Value.Trim();
    }

    /// <summary>
    /// Parses a datagram as a WS-Discovery Probe. Returns true only when the envelope is well-formed and its
    /// action is the Probe action; anything else (Hello, ProbeMatches, garbage) yields false with no throw,
    /// so a receiver has fully defined behavior for every datagram it sees.
    /// </summary>
    public static bool TryParseProbe(ReadOnlySpan<byte> datagram, out WsDiscoveryProbe probe)
    {
        probe = default;
        XDocument? doc = TryParse(datagram);
        XElement? root = doc?.Root;
        XElement? header = root?.Element(Soap + "Header");
        if (header is null)
            return false;
        if (header.Element(Wsa + "Action")?.Value.Trim() != WsDiscoveryConstants.ProbeAction)
            return false;

        string messageId = header.Element(Wsa + "MessageID")?.Value.Trim() ?? string.Empty;
        XElement? probeEl = root!.Element(Soap + "Body")?.Element(Wsd + "Probe");
        IReadOnlyList<string> types = ParseTypes(probeEl?.Element(Wsd + "Types"));
        probe = new WsDiscoveryProbe(messageId, types);
        return true;
    }

    /// <summary>Builds a ProbeMatches response for one advertised endpoint (§ WS-Discovery ProbeMatch).</summary>
    public static byte[] BuildProbeMatches(
        string relatesToMessageId, Guid endpointId, IReadOnlyList<WsDiscoveryQName> types,
        IReadOnlyList<string> xAddrs, ulong instanceId, ulong messageNumber, uint metadataVersion = 1)
    {
        XElement body = new(Soap + "Body",
            new XElement(Wsd + "ProbeMatches",
                new XElement(Wsd + "ProbeMatch",
                    new XElement(Wsa + "EndpointReference",
                        new XElement(Wsa + "Address", EndpointUri(endpointId))),
                    TypesElement(types),
                    new XElement(Wsd + "XAddrs", string.Join(' ', xAddrs)),
                    new XElement(Wsd + "MetadataVersion", metadataVersion))));

        return Serialize(Envelope(
            to: WsDiscoveryConstants.AnonymousTo,
            action: WsDiscoveryConstants.ProbeMatchesAction,
            relatesTo: relatesToMessageId,
            instanceId: instanceId,
            messageNumber: messageNumber,
            body: body));
    }

    /// <summary>Builds a Hello announcement (server appearing on the network).</summary>
    public static byte[] BuildHello(
        Guid endpointId, IReadOnlyList<WsDiscoveryQName> types, IReadOnlyList<string> xAddrs,
        ulong instanceId, ulong messageNumber, uint metadataVersion = 1)
        => BuildPresence(WsDiscoveryConstants.HelloAction, endpointId, types, xAddrs, instanceId, messageNumber, metadataVersion);

    /// <summary>Builds a Bye announcement (server leaving the network).</summary>
    public static byte[] BuildBye(
        Guid endpointId, IReadOnlyList<WsDiscoveryQName> types, IReadOnlyList<string> xAddrs,
        ulong instanceId, ulong messageNumber, uint metadataVersion = 1)
        => BuildPresence(WsDiscoveryConstants.ByeAction, endpointId, types, xAddrs, instanceId, messageNumber, metadataVersion);

    private static byte[] BuildPresence(
        string action, Guid endpointId, IReadOnlyList<WsDiscoveryQName> types, IReadOnlyList<string> xAddrs,
        ulong instanceId, ulong messageNumber, uint metadataVersion)
    {
        string element = action == WsDiscoveryConstants.HelloAction ? "Hello" : "Bye";
        XElement body = new(Soap + "Body",
            new XElement(Wsd + element,
                new XElement(Wsa + "EndpointReference",
                    new XElement(Wsa + "Address", EndpointUri(endpointId))),
                TypesElement(types),
                new XElement(Wsd + "XAddrs", string.Join(' ', xAddrs)),
                new XElement(Wsd + "MetadataVersion", metadataVersion)));

        return Serialize(Envelope(
            to: WsDiscoveryConstants.DiscoveryTo,
            action: action,
            relatesTo: null,
            instanceId: instanceId,
            messageNumber: messageNumber,
            body: body));
    }

    private static XElement Envelope(
        string to, string action, string? relatesTo, ulong instanceId, ulong messageNumber, XElement body)
    {
        var header = new XElement(Soap + "Header",
            new XElement(Wsa + "To", to),
            new XElement(Wsa + "Action", action),
            new XElement(Wsa + "MessageID", EndpointUri(Guid.NewGuid())));
        if (relatesTo is not null)
            header.Add(new XElement(Wsa + "RelatesTo", relatesTo));
        // AppSequence gives the receiver a total order for a server instance's messages (WS-Discovery
        // §Appendix I) — a stable InstanceId plus a monotonic MessageNumber, so ordering is never ambiguous.
        header.Add(new XElement(Wsd + "AppSequence",
            new XAttribute("InstanceId", instanceId),
            new XAttribute("MessageNumber", messageNumber)));

        return new XElement(Soap + "Envelope",
            new XAttribute(XNamespace.Xmlns + "soap", WsDiscoveryConstants.SoapNs),
            new XAttribute(XNamespace.Xmlns + "wsa", WsDiscoveryConstants.WsaNs),
            new XAttribute(XNamespace.Xmlns + "wsd", WsDiscoveryConstants.WsdNs),
            header,
            body);
    }

    private static XElement TypesElement(IReadOnlyList<WsDiscoveryQName> types)
    {
        var el = new XElement(Wsd + "Types");
        // Declare each type's prefix on the element and write the QNames as text (e.g. "pub:Computer").
        foreach (WsDiscoveryQName t in types)
        {
            if (el.GetPrefixOfNamespace(t.Namespace) is null)
                el.Add(new XAttribute(XNamespace.Xmlns + t.Prefix, t.Namespace));
        }
        el.Value = string.Join(' ', types.Select(t => (el.GetPrefixOfNamespace(t.Namespace) ?? t.Prefix) + ":" + t.LocalName));
        return el;
    }

    private static IReadOnlyList<string> ParseTypes(XElement? typesEl)
    {
        if (typesEl is null || string.IsNullOrWhiteSpace(typesEl.Value))
            return [];

        var result = new List<string>();
        foreach (string token in typesEl.Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            int colon = token.IndexOf(':');
            if (colon < 0)
            {
                // Unqualified name → default namespace in scope (may be empty).
                XNamespace def = typesEl.GetDefaultNamespace();
                result.Add("{" + def.NamespaceName + "}" + token);
                continue;
            }
            string prefix = token[..colon];
            string local = token[(colon + 1)..];
            XNamespace? ns = typesEl.GetNamespaceOfPrefix(prefix);
            // An unresolved prefix keeps the literal so it simply never matches — defined, not a throw.
            result.Add("{" + (ns?.NamespaceName ?? prefix) + "}" + local);
        }
        return result;
    }

    private static string EndpointUri(Guid id) => "urn:uuid:" + id.ToString("D");

    private static XDocument? TryParse(ReadOnlySpan<byte> datagram)
    {
        try
        {
            string xml = Encoding.UTF8.GetString(datagram);
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            using var reader = XmlReader.Create(new System.IO.StringReader(xml), settings);
            return XDocument.Load(reader);
        }
        catch (XmlException) { return null; }
        catch (ArgumentException) { return null; }
    }

    private static byte[] Serialize(XElement envelope)
    {
        var doc = new XDocument(new XDeclaration("1.0", "utf-8", null), envelope);
        using var ms = new System.IO.MemoryStream();
        var settings = new XmlWriterSettings { Encoding = new UTF8Encoding(false), OmitXmlDeclaration = false };
        using (var xw = XmlWriter.Create(ms, settings))
            doc.Save(xw);
        return ms.ToArray();
    }
}
