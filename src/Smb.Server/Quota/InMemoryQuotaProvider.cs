using System.Collections.Concurrent;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Security;

namespace Smb.Server.Quota;

/// <summary>
/// [M11.1] Process-local, in-memory quota provider (portable + testable). Tracks per-owner-SID used
/// bytes against a threshold/limit for each share; a real deployment maps this seam onto NTFS/ZFS
/// quotas instead. Thread-safe.
/// </summary>
public sealed class InMemoryQuotaProvider : IQuotaProvider
{
    private sealed class Record
    {
        public long Used;
        public long Threshold = FileQuotaInformation.Unlimited;
        public long Limit = FileQuotaInformation.Unlimited;
        public long ChangeTime;
    }

    // Key = share name + '\0' + hex(owner SID bytes).
    private readonly ConcurrentDictionary<string, Record> _records = new(StringComparer.Ordinal);

    public bool IsSupported => true;

    /// <summary>Seeds/updates an owner's limit (and optional threshold) on a share — for tests/config.</summary>
    public void SetLimit(string shareName, Sid owner, long limit, long threshold = FileQuotaInformation.Unlimited)
    {
        Record rec = _records.GetOrAdd(Key(shareName, owner), _ => new Record());
        lock (rec)
        {
            rec.Limit = limit;
            rec.Threshold = threshold;
        }
    }

    public IReadOnlyList<FileQuotaInformation> Query(IShare share, IReadOnlyList<Sid> sidFilter)
    {
        var result = new List<FileQuotaInformation>();

        if (sidFilter.Count > 0)
        {
            foreach (Sid sid in sidFilter)
                if (_records.TryGetValue(Key(share.Name, sid), out Record? rec))
                    result.Add(Snapshot(sid, rec));
            return result;
        }

        string prefix = share.Name + "\0";
        foreach (KeyValuePair<string, Record> kv in _records)
        {
            if (!kv.Key.StartsWith(prefix, StringComparison.Ordinal)) continue;
            Sid sid = Sid.Parse(Convert.FromHexString(kv.Key[prefix.Length..]));
            result.Add(Snapshot(sid, kv.Value));
        }
        return result;
    }

    public NtStatus Set(IShare share, IReadOnlyList<FileQuotaInformation> entries)
    {
        foreach (FileQuotaInformation e in entries)
        {
            Record rec = _records.GetOrAdd(Key(share.Name, e.Sid), _ => new Record());
            lock (rec)
            {
                rec.Threshold = e.QuotaThreshold;
                rec.Limit = e.QuotaLimit;
                rec.ChangeTime = e.ChangeTime;
                if (e.QuotaUsed >= 0) rec.Used = e.QuotaUsed; // allow seeding usage
            }
        }
        return NtStatus.Success;
    }

    public bool TryReserve(IShare share, Sid owner, long additionalBytes)
    {
        if (additionalBytes <= 0) return true;
        Record rec = _records.GetOrAdd(Key(share.Name, owner), _ => new Record());
        lock (rec)
        {
            if (rec.Limit != FileQuotaInformation.Unlimited && rec.Used + additionalBytes > rec.Limit)
                return false;
            rec.Used += additionalBytes;
            return true;
        }
    }

    public void Release(IShare share, Sid owner, long bytes)
    {
        if (bytes <= 0) return;
        if (_records.TryGetValue(Key(share.Name, owner), out Record? rec))
            lock (rec) rec.Used = Math.Max(0, rec.Used - bytes);
    }

    private static FileQuotaInformation Snapshot(Sid sid, Record rec)
    {
        lock (rec)
            return new FileQuotaInformation(sid, rec.ChangeTime, rec.Used, rec.Threshold, rec.Limit);
    }

    private static string Key(string shareName, Sid owner) => shareName + "\0" + Convert.ToHexString(owner.ToBytes());
}
