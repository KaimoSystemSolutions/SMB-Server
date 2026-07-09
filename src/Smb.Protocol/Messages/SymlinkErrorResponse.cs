using System.Buffers.Binary;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

/// <summary>
/// SMB2 SYMLINK_ERROR_RESPONSE (MS-SMB2 §2.2.2.2.1). The ErrorData of an ERROR response whose status
/// is <c>STATUS_STOPPED_ON_SYMLINK</c>: it tells the client that a component of the requested path is a
/// symbolic link, carrying the link's substitute/print target so the client can re-target the path and
/// retry (§3.3.5.9). The layout mirrors the MS-FSCC §2.1.2.4 symlink reparse data buffer wrapped in the
/// SMB2 symlink error framing.
/// </summary>
public static class SymlinkErrorResponse
{
    /// <summary>SymLinkErrorTag — MUST be 0x4C4D5953 ("SYML").</summary>
    public const uint SymLinkErrorTag = 0x4C4D5953;

    /// <summary>ReparseTag — IO_REPARSE_TAG_SYMLINK (MS-FSCC §2.1.2.4).</summary>
    public const uint IoReparseTagSymlink = 0xA000000C;

    /// <summary>SYMLINK_FLAG_RELATIVE: the substitute name is relative to the link's directory.</summary>
    public const uint SymlinkFlagRelative = 0x00000001;

    /// <summary>The parsed content of a SYMLINK_ERROR_RESPONSE.</summary>
    public readonly record struct Parsed(string SubstituteName, string PrintName, int UnparsedPathLength, bool IsRelative);

    /// <summary>
    /// Builds the SYMLINK_ERROR_RESPONSE ErrorData. <paramref name="unparsedPathLength"/> is the number of
    /// bytes (UTF-16) of the requested path that follow the symlink component and were not consumed;
    /// <paramref name="relative"/> maps to SYMLINK_FLAG_RELATIVE. The PathBuffer stores the substitute name
    /// first, then the print name (both UTF-16LE, no terminator).
    /// </summary>
    public static byte[] Build(string substituteName, string printName, int unparsedPathLength, bool relative)
    {
        ArgumentNullException.ThrowIfNull(substituteName);
        ArgumentNullException.ThrowIfNull(printName);

        int subLen = Encoding.Unicode.GetByteCount(substituteName);
        int printLen = Encoding.Unicode.GetByteCount(printName);
        int pathBuffer = subLen + printLen;

        // Symlink reparse data content (§2.1.2.4): the 12 fixed bytes (offsets/lengths + Flags) + PathBuffer.
        int reparseDataLength = 12 + pathBuffer;
        // SymLinkLength spans everything after the SymLinkLength field: 20 fixed bytes + reparseDataLength.
        // (SymLinkErrorTag 4 + ReparseTag 4 + ReparseDataLength 2 + UnparsedPathLength 2 = 12, then the 12+PathBuffer.)
        int symLinkLength = 12 + reparseDataLength;

        var body = new byte[4 + symLinkLength];
        var w = new SpanWriter(body);
        w.WriteUInt32((uint)symLinkLength);      // SymLinkLength
        w.WriteUInt32(SymLinkErrorTag);          // SymLinkErrorTag
        w.WriteUInt32(IoReparseTagSymlink);      // ReparseTag
        w.WriteUInt16((ushort)reparseDataLength); // ReparseDataLength
        w.WriteUInt16((ushort)unparsedPathLength); // UnparsedPathLength
        w.WriteUInt16(0);                         // SubstituteNameOffset (relative to PathBuffer)
        w.WriteUInt16((ushort)subLen);            // SubstituteNameLength
        w.WriteUInt16((ushort)subLen);            // PrintNameOffset
        w.WriteUInt16((ushort)printLen);          // PrintNameLength
        w.WriteUInt32(relative ? SymlinkFlagRelative : 0); // Flags
        w.WriteUtf16(substituteName);
        w.WriteUtf16(printName);
        return body;
    }

    /// <summary>Parses a SYMLINK_ERROR_RESPONSE ErrorData buffer (§2.2.2.2.1).</summary>
    public static Parsed Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 28)
            throw new SmbWireFormatException($"SYMLINK_ERROR_RESPONSE too short: {data.Length} bytes.");

        uint tag = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
        if (tag != SymLinkErrorTag)
            throw new SmbWireFormatException($"Unexpected SymLinkErrorTag 0x{tag:X8}.");

        int unparsed = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(14, 2));
        int subOffset = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(16, 2));
        int subLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(18, 2));
        int printOffset = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(20, 2));
        int printLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(22, 2));
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(24, 4));

        // Offsets are relative to the PathBuffer, which begins right after the 28-byte fixed header.
        ReadOnlySpan<byte> pathBuffer = data.Slice(28);
        string sub = Encoding.Unicode.GetString(pathBuffer.Slice(subOffset, subLength));
        string print = Encoding.Unicode.GetString(pathBuffer.Slice(printOffset, printLength));
        return new Parsed(sub, print, unparsed, (flags & SymlinkFlagRelative) != 0);
    }
}
