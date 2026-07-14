# Fuzzing & conformance (Enterprise Hardening Roadmap D3)

This project is the CI-runnable half of D3: a **seeded, reproducible generative fuzzer** for the
`Smb.Protocol` wire readers (plus the server-side NDR / witness stub parsers). It runs under
`dotnet test` like the rest of the suite — no external fuzzing toolchain required.

## What it asserts

For **every** registered parser (`WireParserFuzzHarness.Targets`), on **any** input byte sequence:

1. **It terminates** — no infinite loop (a hang trips the test runner rather than wedging the process).
2. **It never leaks an unexpected exception** — the only throw allowed is `SmbWireFormatException`.
   Anything else (`IndexOutOfRangeException`, `ArgumentException`, `OverflowException`,
   `OutOfMemoryException`, …) is a hardening defect: the dispatcher maps only `SmbWireFormatException`
   to a clean `STATUS_INVALID_PARAMETER`; other types fall through the generic safety net (wrong status)
   or, for OOM, are a genuine DoS.

Four input strategies drive that contract (see `WireParserFuzzTests`):

| Strategy          | Coverage focus |
|-------------------|----------------|
| Random bytes      | top-level StructureSize / ProtocolId guards |
| Structure-primed  | plausible leading StructureSize → drives the *body* offset/length arithmetic |
| Every truncation  | deterministic hit on every "read past end" boundary |
| Bit-flip mutation | the neighbourhood of the minimal/empty frame parsers special-case |

Every input is derived from a fixed base seed, so a failure prints the exact hex to reproduce.

### Bugs found & fixed by this harness

- **`FILE_FULL_EA_INFORMATION` chain (`FullEaInformation.Parse`)** — a wire-controlled `NextEntryOffset`
  cast to a negative `int` (huge `uint`) crashed with `ArgumentOutOfRangeException`, and an overlapping
  offset was never rejected. Fixed to validate the offset advances strictly past the entry and stays in
  bounds (→ `SmbWireFormatException`).
- **`SpanReader.Seek` / `SpanReader.Slice`** — an out-of-range wire offset threw
  `ArgumentOutOfRangeException` (mapped to the wrong NT status). Unified to `SmbWireFormatException` so
  every wire-format fault maps to `STATUS_INVALID_PARAMETER`.

## Coverage-guided fuzzing (follow-up, not in CI)

The generative fuzzer above is broad but not coverage-guided. To go deeper, run a libFuzzer-style,
coverage-instrumented campaign with [SharpFuzz](https://github.com/Metalnem/sharpfuzz):

1. Instrument `Smb.Protocol.dll`: `sharpfuzz Smb.Protocol.dll`.
2. Write a thin `Main` that pipes `stdin` bytes into one target (e.g. `CreateRequest.Parse(data, 0)`).
3. Drive with `afl-fuzz` / libFuzzer, seeded from a corpus of real captured frames.

Keep it out of `dotnet test` (needs the native fuzzer + instrumented build); run it in a nightly/manual
job. The generative suite here is the regression guard that the campaign's findings get folded back into.

## Conformance (real-client interop)

Automated wire fuzzing cannot replace testing against genuine clients. The conformance path:

- **Windows** — mount from Windows 10/11 (`net use`), run Explorer + robocopy + `icacls`, and exercise
  the CA/witness path against a failover-cluster client. This is the manual-verify step called out for
  Phase B (Kerberos) and Phase C (Witness/persistent handles) in `ENTERPRISE_HARDENING_ROADMAP.md`.
- **Samba** — `smbtorture` (`smb2.*`, and `smb2.witness` for the Phase C witness endpoint) is the closest
  automatable conformance oracle; the `python` smbprotocol/pysmb scripts in the repo root cover the
  everyday operations.
