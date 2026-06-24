using System.Globalization;

namespace Smb.FileSystem.Versioning;

/// <summary>
/// Hilfsfunktionen für die Windows-„Vorherige Versionen"-Snapshot-Token
/// <c>@GMT-YYYY.MM.DD-HH.MM.SS</c> (MS-SMB2 §2.2.32.2, GMT-Token-Syntax). Ein solches Token
/// kann als führendes Pfadsegment auftreten (z.B. <c>@GMT-2026.06.24-10.30.00\datei.txt</c>)
/// und adressiert die Version einer Datei zu einem Snapshot-Zeitpunkt (UTC).
/// </summary>
public static class GmtToken
{
    /// <summary>Strikte Parse-/Format-Maske; @ G M T sind escaped, da G/M Format-Spezifizierer wären.</summary>
    private const string Pattern = @"\@\G\M\T-yyyy.MM.dd-HH.mm.ss";

    /// <summary>Formatiert einen UTC-Zeitpunkt als <c>@GMT-…</c>-Token (Sekundengenauigkeit).</summary>
    public static string Format(DateTime utc)
    {
        DateTime u = utc.Kind == DateTimeKind.Utc ? utc : utc.ToUniversalTime();
        return u.ToString(Pattern, CultureInfo.InvariantCulture);
    }

    /// <summary>Parst ein einzelnes <c>@GMT-…</c>-Token zu UTC. False bei abweichender Syntax.</summary>
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
    /// Zerlegt einen Pfad in (Snapshot-Zeit, Rest-Pfad), falls das erste Segment ein
    /// <c>@GMT-…</c>-Token ist. <paramref name="remainder"/> ist dann der share-relative Pfad
    /// ohne das Token (Backslash-getrennt). Liefert false, wenn kein Snapshot-Pfad vorliegt.
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
