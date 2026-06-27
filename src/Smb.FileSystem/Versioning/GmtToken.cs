using System.Globalization;

namespace Smb.FileSystem.Versioning;

/// <summary>
/// Helpers for the Windows "Previous Versions" snapshot tokens
/// <c>@GMT-YYYY.MM.DD-HH.MM.SS</c> (MS-SMB2 §2.2.32.2, GMT token syntax). Such a token can appear
/// as a leading path segment (e.g. <c>@GMT-2026.06.24-10.30.00\file.txt</c>) and addresses the
/// version of a file at a snapshot point in time (UTC).
/// </summary>
public static class GmtToken
{
    /// <summary>Strict parse/format mask; @ G M T are escaped because G/M would be format specifiers.</summary>
    private const string Pattern = @"\@\G\M\T-yyyy.MM.dd-HH.mm.ss";

    /// <summary>Formats a UTC point in time as a <c>@GMT-…</c> token (second precision).</summary>
    public static string Format(DateTime utc)
    {
        DateTime u = utc.Kind == DateTimeKind.Utc ? utc : utc.ToUniversalTime();
        return u.ToString(Pattern, CultureInfo.InvariantCulture);
    }

    /// <summary>Parses a single <c>@GMT-…</c> token to UTC. False on differing syntax.</summary>
    public static bool TryParse(string? token, out DateTime utc)
    {
        utc = default;
        if (token is null || !token.StartsWith("@GMT-", StringComparison.Ordinal))
            return false;
        return DateTime.TryParseExact(
            token, Pattern, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out utc);
    }

    /// <summary>
    /// Splits a path into (snapshot time, remaining path) if the first segment is a
    /// <c>@GMT-…</c> token. <paramref name="remainder"/> is then the share-relative path without
    /// the token (backslash-separated). Returns false if there is no snapshot path.
    /// </summary>
    public static bool TrySplitSnapshotPath(string? path, out DateTime snapshotUtc, out string remainder)
    {
        snapshotUtc = default;
        remainder = path ?? string.Empty;
        if (string.IsNullOrEmpty(path))
            return false;

        string p = path.Replace('/', '\\').TrimStart('\\');
        int slash = p.IndexOf('\\');
        string first = slash < 0 ? p : p[..slash];
        if (!TryParse(first, out snapshotUtc))
            return false;

        remainder = slash < 0 ? string.Empty : p[(slash + 1)..];
        return true;
    }
}
