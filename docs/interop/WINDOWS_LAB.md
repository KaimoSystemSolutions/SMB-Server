# Windows interop lab — without a VM

> **In short:** no virtual machine is needed. The real Windows SMB client is a kernel driver (`mrxsmb.sys`)
> that already runs on the development machine. Once the server listens on `127.0.0.1:445`, **every UNC
> access** — including from ordinary .NET code — travels through exactly that client, the same code path
> Explorer, `robocopy` and Office use. Real Windows interop therefore runs as a plain `dotnet test`.

## Two labs, one battery

The operations under test live in one reusable base class, `tests/Smb.Tests/WindowsInteropBattery.cs`,
and run against **two** server configurations:

| Lab | Fixture | Server | Configuration |
|---|---|---|---|
| Minimal | `WindowsSmbLab` | in-process | bare defaults + `ConcurrentMetadataOps`; includes the gated backend for the freeze case |
| Example | `SampleServerLab` | **the shipped example binary** (`examples/Smb.Sample.Server`) as an external process | every knob on: compression, quota, multichannel, DFS, versioned shares, custom lock manager, … |

`WindowsClientInteropTests` runs the battery against the minimal lab, `SampleServerInteropTests` against
the example — plus example-only cases (negotiated compression both directions via `robocopy /compress`,
versioned shares, the DFS root). A case that passes minimal but fails example isolates a bug to the
feature surface; the LZ77 wire-format regression (Explorer: "unexpected network error" on any folder with
enough entries) was found exactly this way. The two labs serialise on `127.0.0.1:445` via `Port445Gate` —
xUnit runs the collections one after the other.

Complementary and much cheaper than the wire tests: `WindowsCodecCrossValidationTests` cross-validates
the LZ77/LZNT1 codecs against `ntdll!RtlCompressBuffer`/`RtlDecompressBufferEx` — the exact code the
Windows SMB drivers use — in both directions, with no server, port or admin shell involved.

## One-time preparation

Windows' **own** SMB server occupies port 445 (`srv2.sys`, process ID 4). It has to go before our server can
bind the port:

```powershell
# Admin shell:
Stop-Service LanmanServer -Force

# Verify — must be empty:
Get-NetTCPConnection -LocalPort 445 -State Listen
```

If a kernel listener survives anyway, disable the driver and reboot:
```powershell
sc.exe config srv2 start= disabled
# Reboot
```

**To undo** (re-enable Windows file sharing):
```powershell
sc.exe config srv2 start= demand
Start-Service LanmanServer
```

### What this costs
While `LanmanServer` is stopped, **this machine** shares no files or printers and the admin shares (`C$`) are
gone. On a developer machine that is usually irrelevant and reversible at any time. The SMB **client**
(`LanmanWorkstation`) is untouched — access to *other* servers keeps working.

### What it does *not* need
- **No elevation for the port bind.** Windows has no privileged-port concept (< 1024) like Linux — binding 445
  succeeds from a normal process. Only stopping the service needs admin rights.
- **No firewall rule.** Loopback traffic is not filtered.
- **No domain, no domain controller.** This deployment uses NTLM against its own `IIdentityBackend`.

## Running the tests

```bash
cd SmbServer
# both labs (minimal + example server) and the ntdll codec cross-validation:
dotnet test tests/Smb.Tests/Smb.Tests.csproj \
  --filter "FullyQualifiedName~WindowsClientInteropTests|FullyQualifiedName~SampleServerInteropTests|FullyQualifiedName~WindowsCodecCrossValidationTests"
```

Each lab starts one server on `127.0.0.1:445` for its whole test collection, logs in over `net use` with
NTLM test credentials, and the battery then exercises the operations Explorer actually issues over real UNC
paths: read/write/overwrite/append/set-length/offset I/O, a 4 MiB LARGE_MTU round trip,
rename/delete/directories, enumeration (including 500-entry paging, wildcards, Unicode), timestamps and
attributes, volume free space (interleaved with root enumeration), error statuses, sharing violations,
parallel readers, byte-range locks, flush, copy, robocopy trees, `File.Replace` save flows, alternate data
streams (Zone.Identifier), security-descriptor queries, read-only delete semantics, case-insensitive
lookups, share-root operations, CHANGE_NOTIFY — plus the freeze case (a stuck metadata op must not block an
unrelated read).

**Every case is time-boxed** (`Timed`, 25 s). A freeze is the symptom under investigation, so it has to fail as
a freeze rather than hang the test run.

**If port 445 is occupied, or the test is not running on Windows, it reports as `Skipped`** — never as
"passed". That is deliberate (via `Xunit.SkippableFact`): *a test that silently does nothing while reporting
green is worse than no test.* A skipped run looks like this:

```
Skipped Smb.Tests.WindowsClientInteropTests.Read_File_ReturnsServerContent
Skipped!: failed: 0, succeeded: 0, skipped: 32, total: 32
```
with the reason in the detailed output:
```
port 445 not bindable (AccessDenied) — Windows' own SMB server holds it exclusively.
Run `Stop-Service LanmanServer -Force` in an admin shell, ...
```

**Only the environment may skip.** Once the server is up, every failure is a real result — a failed NTLM login
turns the test **red**, it is not skipped away.

> **Note:** `succeeded: 32` at ~150 ms runtime would mean nothing ran at all — real SMB interop takes
> considerably longer. Runtime is your sanity check.

### Why everything runs on `127.0.0.1` (and not one address per test)

The obvious idea is to give each test its own loopback address to dodge the client's connection cache. **That
does not work** (measured, 2026-07-15): with `LanmanServer` stopped, **every** 127.x address is bindable *and*
reachable from user-mode TCP (`127.0.0.77:445` connects cleanly) — but the SMB client is a **kernel driver**
and only routes to addresses actually **assigned** to the loopback interface. That is `127.0.0.1` alone;
anything else fails the connect with `ERROR_NETWORK_UNREACHABLE` (1231). Hence: **one** server as a collection
fixture (`WindowsSmbLab`) on `127.0.0.1:445` for all tests, several shares on it, and test directories carrying
a per-run suffix to defeat the client's directory cache.

### The one expected hiccup: `System error 67`

If a *new* server starts on `127.0.0.1:445` shortly after a previous one, the client can still be holding its
connection to the **previous** run's server and rejects the first `net use` with `System error 67` ("The
network name cannot be found"). The lab retries exactly that error (only that one) up to 15 times. Usually the
client attaches immediately (~200 ms); one observed episode outlasted five one-second retries and was gone on
the next run. Not a server fault — client cache.

## Diagnosis when something jams

The Windows client event logs say **why** the client stalls or refuses — the information the server side lacks:

```powershell
Get-WinEvent -LogName Microsoft-Windows-SMBClient/Connectivity -MaxEvents 30
Get-WinEvent -LogName Microsoft-Windows-SMBClient/Operational  -MaxEvents 30
```

Inspect the negotiated state of the connection (dialect, signing, encryption, multichannel):
```powershell
Get-SmbConnection
Get-SmbClientConfiguration
```

Clear client caches between manual attempts — Windows caches sessions, credentials, negative lookups and
directory contents aggressively and otherwise falsifies results:
```powershell
net use * /delete /y
Restart-Service LanmanWorkstation -Force
```

Combine this with the server's OpenTelemetry spans (`Smb.Server.OpenTelemetry`, meter/activity source
`"Smb.Server"`) — then you have both sides of the same second.

## Limits of this setup — when a VM is needed after all

Loopback covers client semantics, auth and the file/metadata cases. It does **not** cover:

| Not covered | Why | Roadmap |
|---|---|---|
| Other Windows versions (Win10, Server 2022/2025) | only ever the local host is tested | W5 |
| Real network effects: latency, MTU, packet loss | loopback has none of them | W4 |
| Reconnect after a network drop, durable-handle recovery | no interface to take down | W4.3 |
| Multichannel across several NICs | only one loopback interface | W4 |

None of that is relevant to the acute freeze (backend/auth latency) — latency is simulated more
deterministically by the backend shim (`GatedCreateFileStore`) than by a real link. A VM (Hyper-V + PowerShell
Direct + checkpoints) only pays off for the version matrix in W5.
