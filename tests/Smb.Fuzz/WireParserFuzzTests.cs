using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace Smb.Fuzz;

/// <summary>
/// [D3] Wire-parser fuzz suite (docs/ENTERPRISE_HARDENING_ROADMAP.md). Seeded and reproducible: every
/// generated input is derived from a fixed base seed, so a failure prints the exact seed to reproduce it.
/// The asserted invariant for every target is the parse contract in <see cref="WireParserFuzzHarness"/>:
/// arbitrary bytes → either a successful parse or <c>SmbWireFormatException</c>, never an unexpected throw,
/// and always terminating (a hung parser fails the per-input xUnit timeout rather than the process).
/// </summary>
public sealed class WireParserFuzzTests
{
    private const int BaseSeed = 0x5B2F0FF; // stable across runs; bump to explore a fresh corpus.
    private readonly ITestOutputHelper _out;

    public WireParserFuzzTests(ITestOutputHelper output) => _out = output;

    public static IEnumerable<object[]> AllTargets()
    {
        foreach ((string name, _) in WireParserFuzzHarness.Targets)
            yield return [name];
    }

    /// <summary>
    /// Random-bytes fuzzing: 20k buffers of length 0..1024 per target. Purely random input mostly exercises
    /// the structure-size / offset validation guards at the top of each parser.
    /// </summary>
    [Theory]
    [MemberData(nameof(AllTargets))]
    public void RandomBytes_NeverCrashesOrLeaksUnexpectedException(string targetName)
    {
        ParseTarget target = ResolveTarget(targetName);
        var rng = new Random(BaseSeed ^ targetName.GetHashCode());
        var buffer = new byte[1024];

        for (int i = 0; i < 20_000; i++)
        {
            int len = rng.Next(0, buffer.Length + 1);
            rng.NextBytes(buffer.AsSpan(0, len));
            AssertContract(target, buffer.AsSpan(0, len), targetName, seed: i);
        }
    }

    /// <summary>
    /// Structure-primed fuzzing: the first 2 bytes hold a plausible small StructureSize and a valid SMB2
    /// header prefix is prepended, so the input gets <i>past</i> the top-level guards and drives the deeper
    /// offset/length arithmetic (where the interesting parser bugs live).
    /// </summary>
    [Theory]
    [MemberData(nameof(AllTargets))]
    public void StructurePrimed_NeverCrashesOrLeaksUnexpectedException(string targetName)
    {
        ParseTarget target = ResolveTarget(targetName);
        var rng = new Random(unchecked(BaseSeed + 1) ^ targetName.GetHashCode());
        var buffer = new byte[512];

        for (int i = 0; i < 20_000; i++)
        {
            int len = rng.Next(2, buffer.Length + 1);
            rng.NextBytes(buffer.AsSpan(0, len));
            // Bias the leading structure-size field toward realistic values (2..64) so parsers that check
            // it accept the frame and continue into the body.
            ushort structureSize = (ushort)rng.Next(2, 65);
            buffer[0] = (byte)structureSize;
            buffer[1] = (byte)(structureSize >> 8);
            AssertContract(target, buffer.AsSpan(0, len), targetName, seed: i);
        }
    }

    /// <summary>
    /// Truncation fuzzing: build a random ~256-byte frame, then feed <b>every</b> prefix length 0..N. This
    /// deterministically hits every "read past end" boundary — the classic source of index-out-of-range
    /// leaks — for each parser.
    /// </summary>
    [Theory]
    [MemberData(nameof(AllTargets))]
    public void EveryTruncation_NeverCrashesOrLeaksUnexpectedException(string targetName)
    {
        ParseTarget target = ResolveTarget(targetName);
        var rng = new Random(unchecked(BaseSeed + 2) ^ targetName.GetHashCode());
        var full = new byte[256];

        for (int trial = 0; trial < 64; trial++)
        {
            rng.NextBytes(full);
            for (int len = 0; len <= full.Length; len++)
                AssertContract(target, full.AsSpan(0, len), targetName, seed: trial * 1000 + len);
        }
    }

    /// <summary>
    /// Bit-flip mutation: start from an all-zero (minimally-structured) buffer and flip a handful of random
    /// bits each iteration, exploring the neighbourhood of the "empty" frame that many parsers special-case.
    /// </summary>
    [Theory]
    [MemberData(nameof(AllTargets))]
    public void BitFlipMutation_NeverCrashesOrLeaksUnexpectedException(string targetName)
    {
        ParseTarget target = ResolveTarget(targetName);
        var rng = new Random(unchecked(BaseSeed + 3) ^ targetName.GetHashCode());

        for (int trial = 0; trial < 5_000; trial++)
        {
            int len = rng.Next(0, 129);
            var buf = new byte[len];
            int flips = rng.Next(0, 24);
            for (int f = 0; f < flips && len > 0; f++)
                buf[rng.Next(len)] ^= (byte)(1 << rng.Next(8));
            AssertContract(target, buf, targetName, seed: trial);
        }
    }

    private void AssertContract(ParseTarget target, ReadOnlySpan<byte> input, string targetName, int seed)
    {
        WireParserFuzzHarness.Outcome outcome = WireParserFuzzHarness.Run(target, input, out Exception? ex);
        if (outcome == WireParserFuzzHarness.Outcome.UnexpectedThrow)
        {
            string hex = Convert.ToHexString(input);
            _out.WriteLine($"Target '{targetName}' leaked {ex!.GetType().FullName} on input (seed {seed}): {hex}");
            Assert.Fail(
                $"Parser '{targetName}' violated the wire contract: threw {ex.GetType().Name} " +
                $"('{ex.Message}') instead of SmbWireFormatException on {input.Length}-byte input. " +
                $"Reproduce with the hex above.");
        }
    }

    private static ParseTarget ResolveTarget(string name)
    {
        foreach ((string n, ParseTarget fn) in WireParserFuzzHarness.Targets)
            if (n == name)
                return fn;
        throw new InvalidOperationException($"Unknown fuzz target '{name}'.");
    }
}
