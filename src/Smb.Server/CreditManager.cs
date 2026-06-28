using Smb.Protocol.Enums;

namespace Smb.Server;

/// <summary>
/// Credit/flow-control logic (Context §7, MS-SMB2 §3.3.1.2). Calculates CreditCharge
/// for multi-credit operations and decides how many credits to grant.
/// </summary>
public static class CreditManager
{
    private const int CreditUnit = 65536; // 64 KiB pro Credit.

    /// <summary>
    /// CreditCharge = ceil(max(SendPayload, ExpectedReceivePayload) / 65536), minimum 1.
    /// For 2.0.2 always 0 (one implicit credit per request, Context §7).
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
    /// Determines the credits to grant: at least as many as requested (so the client makes
    /// progress), but capped (Context §7: "generous, but capped").
    /// Minimum 1.
    /// </summary>
    public static ushort ComputeCreditGrant(ushort requested, ushort cap)
    {
        // Grant generously so the client quickly builds up a credit buffer and can also send
        // multi-credit operations (large READ/WRITE/IOCTL, each ~CreditCharge credits).
        // Stingy granting otherwise leads to deadlock (Context §7). Minimum floor, capped.
        const ushort floor = 256;
        int grant = Math.Max(requested, floor);
        if (grant > cap) grant = cap;
        if (grant < 1) grant = 1;
        return (ushort)grant;
    }

    /// <summary>
    /// Checks whether a MessageId is within the valid sequence window (Context §7, §19.1 step 3).
    /// </summary>
    public static bool IsWithinWindow(ulong messageId, ulong windowStart, ulong windowSize)
        => messageId >= windowStart && messageId < windowStart + windowSize;
}
