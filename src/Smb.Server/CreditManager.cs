using Smb.Protocol.Enums;

namespace Smb.Server;

/// <summary>
/// Credit-/Flusskontroll-Logik (Context §7, MS-SMB2 §3.3.1.2). Berechnet CreditCharge
/// für Multi-Credit-Operationen und entscheidet, wie viele Credits zu gewähren sind.
/// </summary>
public static class CreditManager
{
    private const int CreditUnit = 65536; // 64 KiB pro Credit.

    /// <summary>
    /// CreditCharge = ceil(max(SendPayload, ExpectedReceivePayload) / 65536), mind. 1.
    /// Bei 2.0.2 immer 0 (ein implizites Credit je Request, Context §7).
    /// </summary>
    public static ushort ComputeCreditCharge(SmbDialect dialect, int sendPayload, int expectedReceivePayload)
    {
        if (dialect == SmbDialect.Smb202) return 0;
        int max = Math.Max(sendPayload, expectedReceivePayload);
        if (max <= 0) return 1;
        int charge = (max + CreditUnit - 1) / CreditUnit;
        return (ushort)Math.Max(1, charge);
    }

    /// <summary>
    /// Bestimmt die zu gewährenden Credits: mindestens so viele wie angefordert (damit der
    /// Client Fortschritt macht), aber gedeckelt (Context §7: "großzügig, aber gedeckelt").
    /// Mindestens 1.
    /// </summary>
    public static ushort ComputeCreditGrant(ushort requested, ushort cap)
    {
        // Großzügig gewähren, damit der Client schnell ein Credit-Polster aufbaut und auch
        // Multi-Credit-Operationen (große READ/WRITE/IOCTL, je ~CreditCharge Credits) absenden
        // kann. Sparsame Vergabe führt sonst zum Deadlock (Context §7). Mindestfloor, gedeckelt.
        const ushort floor = 256;
        int grant = Math.Max(requested, floor);
        if (grant > cap) grant = cap;
        if (grant < 1) grant = 1;
        return (ushort)grant;
    }

    /// <summary>
    /// Prüft, ob eine MessageId im gültigen Sequenzfenster liegt (Context §7, §19.1 Schritt 3).
    /// </summary>
    public static bool IsWithinWindow(ulong messageId, ulong windowStart, ulong windowSize)
        => messageId >= windowStart && messageId < windowStart + windowSize;
}
