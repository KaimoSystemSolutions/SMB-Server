# Windows Compatibility Roadmap: "every case works flawlessly"

> **Purpose of this document:** work plan **and** resumption log, to get the SMB server to the point where a
> real **Windows client (Explorer, Office, robocopy, CLI, backup/AV)** accesses the shares without freezes,
> without data loss, and without "works most of the time" behaviour. The [status journal](#status-journal) at
> the bottom says exactly which milestone is done and what comes next. If interrupted: read the journal,
> continue at the first open item. Leave inline `<!-- NOTE: -->` markers while working.
>
> This roadmap complements `ENTERPRISE_ROADMAP.md` (feature completeness) and
> `ENTERPRISE_HARDENING_ROADMAP.md` (scale/auth/HA/observability). Both are finished; the core is functional.
> **What is open is exactly what those two roadmaps repeatedly deferred as "manual-verify against a real
> Windows client"** — plus the concrete protocol details where Windows differs from a test client
> (smbprotocol/pysmb). That is where the reported freezes come from.

## Baseline (verified against the code, 2026-07-14)

The baseline is strong and configured close to Windows: SMB 3.1.1 preferred, signing required, AES-GMAC/GCM,
pre-auth integrity, multichannel on, leases + classic oplocks + durable/persistent handles + witness present.
The gaps are **not** "feature missing" but **behaviour under real Windows timing**:

| # | Finding (evidenced in code) | File | Freeze relevance |
|---|------|------|------------------|
| 1 | `ConcurrentMetadataOps` **default off** → every CREATE/CLOSE/SET_INFO/QUERY_* is a **connection barrier** that drains all in-flight I/O and runs serially. | `SmbServerOptions.cs:137`, `Smb2Dispatcher.Concurrency.cs` | **Highest suspicion.** On a real backend (TrueNAS/ZFS, network latency) **one** slow metadata op blocks the whole connection. Explorer fires bursts of CREATE+QUERY_INFO+CLOSE when opening a folder → visible freeze. |
| 2 | Oplock/lease **break-before-grant not implemented**: the conflicting access does **not wait** for the acknowledgment, the holder is downgraded immediately. Explicitly marked "deferred to a later pass". | `Smb2Dispatcher.Oplock.cs:18`, `Smb2Dispatcher.Lease.cs:16-20` | No server hang, but **cache-coherency break** and Windows-side retries/stalls (Explorer/Office open the same file several times: thumbnail, preview, Defender, SearchIndexer). |
| 3 | Break notification is **fire-and-forget** (`_ = SendOplockBreakAsync`), **no break timeout**, no retry, no force-downgrade clock. | `Smb2Dispatcher.Oplock.cs:38`, `.Lease.cs:34` | A client that never acks is never cleaned up; no observability into why a file "sticks". |
| 4 | CHANGE_NOTIFY: changes **between** two requests are lost (marked open in the code). | `Smb2Dispatcher.Notification.cs:78-79` | No freeze, but "case does not work flawlessly": the Explorer view goes stale, F5 needed. |
| 5 | Directory watcher default = `FileSystemDirectoryWatcher` (.NET `FileSystemWatcher`). | `SmbServerOptions.cs:186` | On ZFS/network mounts `FileSystemWatcher` may deliver no/late events → CHANGE_NOTIFY "dead" (the comment names inotify/ZFS events as the alternative). |
| 6 | **No** end-to-end test against real Windows exists in the repo (all roadmaps end in "manual-verify"). | — | The actual task: "every case" has never been evidenced against the real client. |
| 7 | `InMemoryOplockManager` XML doc claims "a lease … is not yet implemented" — **outdated**, leases are really implemented in `InMemoryLeaseManager`. | `Oplocks/InMemoryOplockManager.cs:29` | Documentation misdirection only; fix along with the break-before-grant rework (W1). |

**Bottom line (2026-07-14, original hypothesis):** the freeze is most likely **#1** (barrier on a slow backend),
secondarily **#2/#3** (break handshake). Hence a **diagnosis phase (W0)** comes first, to *prove* the freeze
rather than guess — then fix in a targeted way.

> **Addendum 2026-07-15: the hypothesis was wrong — which is exactly why W0 came first.**
> The lab from W0.1 reproduced the freezes and measured their cause. It was **neither #1 nor #2/#3**, but two
> concrete protocol bugs that do not appear in the table above at all. See the next section. The value of the
> diagnosis phase is demonstrated here: all five hypotheses would have fixed past the freeze.

## Freeze causes — measured in the Windows lab (2026-07-15)

Both findings came out of expanding `WindowsClientInteropTests` to full operation coverage. Both are fixed,
and both now have a regression test that runs **without** the lab (dispatcher level) — the interop tests are
the proof against the real client, the dispatcher tests keep it that way in CI.

| # | Cause | Effect on the real client | Fix | Test |
|---|-------|---------------------------|-----|------|
| **F1** | **Error responses were sent unsigned on a signed session.** Every `BuildError` path produced `ResponseSegment.Unsigned(...)` — the handler has no session in hand. | §3.2.5.1.3: a Windows client **discards** a response whose signature does not verify — it does *not* fail the call. So the operation runs into the client's timeout. This affects **every** declining status (file missing, sharing violation, access denied) ⇒ "almost every operation freezes". It surfaced as a misleading `NTE_BAD_SIGNATURE` instead of the real status. | Sign centrally at assembly time: `SignIfRequestWasSigned` in **both** dispatch paths (§3.3.4.1.1: sign the response ⟺ the request was signed). | `SignedErrorResponseTests` (4), `WindowsClientInteropTests.OpenMissingFile_FailsFastWithFileNotFound` |
| **F2** | **Async CANCEL was matched by MessageId instead of AsyncId.** `HandleCancel` only looked in `PendingRequests[header.MessageId]`. | §3.3.5.16: when `SMB2_FLAGS_ASYNC_COMMAND` is set, the CANCEL identifies its target by **AsyncId**; Windows does *not* put the original's MessageId there (measured: `async=True mid=2 asyncId=2` against `pending=[mid14/async2]`). So the lookup **always** missed, the parked CHANGE_NOTIFY was never completed, and the client waited out its own timeout: **64.7 s**. Explorer registers a CHANGE_NOTIFY on **every** open folder window ⇒ closing/navigating away froze for ~65 s. | Look up by AsyncId when `AsyncCommand` is set, otherwise by MessageId as before. | `ChangeNotifyTests.AsyncCancel_ByAsyncId_...`, `WindowsClientInteropTests.ChangeNotify_ReportsCreate_AndDropsWatchPromptly` (measures the teardown: 64,749 ms → 16 ms) |

**Why none of the existing tests found this:** `ChangeNotifyTests.Cancel_AbortsPendingChangeNotify_WithStatusCancelled`
sends a **sync** CANCEL "with the same MessageId" — a shape a real Windows client never sends for an async
operation. The test was written against the implementation, not against the spec, and therefore confirmed
exactly the assumption that constituted the bug. It still passes; the new test beside it models the real client
shape. Same story for F1: all dispatcher tests ran with `RequireMessageSigning = false`, where an unsigned error
response is correct.

**Two further functional gaps** that the same test expansion uncovered (no freezes, but "case does not work
flawlessly"):

| # | Cause | Effect | Fix |
|---|-------|--------|-----|
| **F3** | `SET_INFO/FileBasicInformation` was **acknowledged with `NtStatus.Success` and dropped** (comment: "no hard setting needed for browsing/writing"). | Timestamps and DOS attributes were **not settable** over SMB — while reporting success. Every copy loses the original's timestamps; Explorer's "read-only/hidden" checkboxes did nothing. | New opt-in seam `IBasicInfoStore` (pattern of `ISparseFileStore`), implemented by `LocalFileStore`; backends without the seam keep the old accept-and-drop (otherwise every Windows copy would fail outright). `FILE_WRITE_ATTRIBUTES` is now enforced. |
| **F4** | `LocalFileHandle.Build()` reported `Attributes` **hard-coded as `Normal`** (resp. `Directory`) instead of reading them. | QUERY_INFO on an open handle contradicted a directory listing of the same file: hidden/read-only looked "normal" in the properties dialog. | `LocalFileStore.MapAttributes` is now used by both paths. |
| **F5** (found 2026-07-15 while implementing W1, **not** lab-measured) | **F1 all over again, on the out-of-band path.** `SendAsyncFinalAsync` (CHANGE_NOTIFY, witness) and `SendFinalLockResponseAsync` (blocking LOCK) sent their **error/cancelled finals unsigned** on a signed session — literally `status.IsSuccess() ? MaybeSigned(...) : ResponseSegment.Unsigned(...)`. | Same mechanism as F1 (§3.2.5.1.3: the client *discards* it rather than failing the call), one path over: a client that CANCELs a CHANGE_NOTIFY, or is refused a blocking LOCK, never sees the answer and waits out its own timeout. `SignIfRequestWasSigned` does not cover these — nothing assembles an out-of-band final centrally. | New `SignedLikeRequest` helper applies §3.3.4.1.1 (request signed ⇒ response signed) to every async final. |

> **The generalisable lesson from F1 + F5 — this root cause has now bitten three times.** Every place that
> builds a response **outside** a central choke point re-decides signing, and re-decides it wrong. First the
> sequential `BuildError` paths, then `ExecutePreparedFrameAsync` (the gotcha that cost time twice on
> 2026-07-15), now the two out-of-band finals. The **TOP-GOTCHA is not "there are two dispatch paths"** — it is
> that there are *four* places a response reaches the wire, and only two of them pass through
> `SignIfRequestWasSigned`. Anything new that sends a response must state which one it uses. W1's parked CREATE
> deliberately reuses `SendAsyncFinalAsync` for exactly this reason.

---

## Phase W0 — Prove the freeze: repro harness, Windows lab, observability

Goal: make the freeze **reproducible** and **unambiguously attributable to one of hypotheses #1–#5** before
code is changed. Without this step you fix blind.

### W0.1 — Real Windows test lab ✅ DONE (no VM — loopback)
- **Deployment decided (2026-07-14):** the server is consumed as a **library** that **overrides** shares /
  user auth / permission checks through the extension points — **no Kerberos, no domain**. So the auth path is
  **NTLMv2 against the consumer's own `IIdentityBackend`** (or an own `ISpnegoNegotiator`), and permissions go
  through `IShareAccessPolicy` + the CREATE-time DACL check. The Kerberos/`Smb.Auth.Sspi` track (roadmap phase
  B1) is **out of scope** for this deployment.
- **Correction of the original VM assumption (2026-07-14):** a VM is **not needed**. The real Windows SMB
  client is a kernel driver (`mrxsmb.sys`) already running on the dev host — it does not need to be simulated,
  only pointed at the server. Once the server listens on `127.0.0.1:445`, **every UNC access from ordinary
  .NET code** goes through exactly that client (the same MUP/RDBSS/mrxsmb path as Explorer/robocopy/Office)
  ⇒ real interop as a plain `dotnet test` run, no VM overhead.
  - **Only prerequisite:** Windows' own SMB server occupies 445 → `Stop-Service LanmanServer -Force` (system
    change, one-off, reversible). **Verified:** the port bind itself needs **no elevation** — Windows has no
    privileged ports (<1024) like Linux (probe bind on 987 from a non-elevated process succeeded).
- **Deliverable:** `docs/interop/WINDOWS_LAB.md` ✅ — preparation (free 445 + undo), test run, diagnosis
  (SMBClient event logs, `Get-SmbConnection`, cache reset) and the documented limits of loopback.
- **When a VM is needed after all:** only for the version matrix (Win10/Server), real network effects
  (latency/MTU/loss), reconnect-after-drop and multichannel across several NICs → W4/W5, not for the freeze.

### W0.2 — Client-side freeze repro scripts
- Three PowerShell/`robocopy` loads that provoke the hypotheses:
  1. **Metadata burst** (hyp. #1): `robocopy` of a tree with 50k small files + `Remove-Item -Recurse`; open an
     Explorer folder with 10k entries. Raise latency artificially (backend delay shim, see W0.3).
  2. **Multiple opens of the same file** (hyp. #2/#3): keep a file open in Word, concurrently
     read/rename/delete from PowerShell; preview pane + SearchIndexer active.
  3. **Live folder** (hyp. #4/#5): Explorer window open, create/delete files from a second session; check
     whether the view refreshes without F5.
- **Deliverable:** `docs/interop/repro/*.ps1` + expected vs. observed behaviour per script.

### W0.3 — Server-side freeze observability
- **Latency shim backend:** an `IFileStore` decorator that injects a configurable delay per metadata op
  (simulates ZFS/network latency), so the barrier effect (#1) is reproducible locally without TrueNAS.
  Analogous to the existing benchmark backend from `A5`.
- **Barrier/break instrumentation:** measure via the existing OTel bridge (`Smb.Server.OpenTelemetry`): wait
  time at the metadata barrier (time between "frame classified" and "dispatch starts"), number of open breaks
  without ack, `PendingRequests` depth. A span hanging > *N* ms at the barrier marks the freeze **in the
  trace**.
- **Deliverable:** `tests/Smb.Tests/…LatencyShim`, OTel attributes `smb.dispatch.barrier_wait_ms`,
  `smb.oplock.pending_breaks`. **Test:** shim + burst shows measurably growing `barrier_wait_ms` with
  `ConcurrentMetadataOps=false` and a flat curve with `true` (proof for hyp. #1).

> **Gate:** only once W0.3 attributes the freeze to a hypothesis is the corresponding phase (W1/W2/W3)
> prioritised. Most likely outcome: **W2 first**.

---

## Phase W1 — Break-before-grant: coherent oplock/lease semantics

**Status: W1.1–W1.4 DONE (2026-07-15). W1.5 (lab verification) open.** Once F1/F2 removed the two hard
freezes, this was the most plausible remaining candidate for "the file sticks". The conflicting access now
**waits** for the break ack (or a timeout) before it proceeds — the Windows-conformant behaviour
(§3.3.5.9.8), closing cache-coherency gap #2 and the missing break clock #3.

### ⚠️ The design constraint below was analysed correctly and concluded wrongly — read this first

The section that used to stand here declared **W1.0 (take the break ack off the barrier) a hard prerequisite**,
because *"a CREATE parked waiting for a break ack deadlocks with the ack that would release it"*. Every
individual fact in that analysis is true. The conclusion is not, and **W1.0 was not implemented — it is not
needed.** Why:

- The deadlock only exists if the parked CREATE's **frame** stays in `_inflight` while it waits, i.e. if the
  handler `await`s the ack inline. That was an unstated assumption.
- **W1.1 itself prescribed the opposite** ("STATUS_PENDING interim **exactly as CHANGE_NOTIFY does**").
  CHANGE_NOTIFY does not park its frame: it registers the wait, answers with an interim, and the frame
  completes. The two halves of the plan contradicted each other, and the half that was written down as the
  blocker won the reader's attention.
- **Park the response, not the frame** and the deadlock dissolves: the CREATE frame returns as soon as the
  interim and the notification are out, so it has already left `_inflight` when the ack arrives — the barrier
  drains an empty-of-this-CREATE list and the ack gets through. The concurrency classifier is untouched.

**The inline-await design would in fact have had a *second*, worse deadlock that the analysis did not
cover:** with `ConcurrentMetadataOps=false` — **still the default** (W2.1) — CREATE is a *barrier*, so the
read loop sits inside `await ProcessMessageAsync(create)` (`SmbConnectionHandler.cs:171-172`) and never reads
the ack frame **at all**, off-barrier classification or not. W1.0 would have bought a deadlock fix that only
worked with a flag that is off by default. The chosen design works with the flag on **and** off.

**Lesson, and it is the same one F1/F2 taught:** the prose that names itself the blocker gets believed. This
one survived a full planning pass because it was specific, code-referenced and confidently worded — all of
which it was, while resting on an assumption nobody stated. Re-derive the constraint from the design you are
actually about to write, not from the design the plan assumed.

### W1.0 — Take the break ack off the barrier ⬜ NOT NEEDED (see above)
Not implemented, deliberately, and there is no reason to revisit it: `OPLOCK_BREAK` stays a barrier frame.
Keep it that way — the ack mutates manager state and making it concurrent buys nothing now that no frame
parks.

### W1.1 — Blocking break in the CREATE path ✅ DONE
- A CREATE that triggers an ack-required break parks: **interim → notification → wait → final out-of-band**
  (`ParkCreateBehindBreakAsync` / `CompleteParkedCreateAsync` in `Smb2Dispatcher.FileCommands.cs`).
- **Deviation from the CHANGE_NOTIFY pattern, forced by W1.1's own ordering rule:** the interim is written
  *inside* the handler (awaited `SendOutOfBandAsync`) and the frame answers with **nothing** (`null`), instead
  of returning the interim for the caller to write. Returning it would leave "interim before notification" to
  a race between two tasks — the handler returns, and only then does the caller assemble and write, while the
  break send is already in flight. `HandleCreateAsync` therefore returns `ResponseSegment?`.
- **The response body is built after the wait, not before.** That is the whole point: the file the holder
  flushes into is the file whose size/timestamps the response reports. `BuildCreateBodyAsync` is a local
  function so both paths share it.
- **Not every break waits** (as planned): lease → ack required iff Write or Handle caching is lost; classic
  oplock → iff the holder's level *was* Exclusive/Batch (a LEVEL_II holder never acks a LEVEL_II→None break,
  §3.3.4.6 — waiting for that ack would stall until the timeout for nothing). The oplock from-level is read
  from `open.OplockLevel` **before** the mirror is overwritten: the mirror is what the *client* was granted,
  which is what decides whether the client will ack at all.
- **Single source of truth:** `LeaseAckRequired` now feeds **both** the wire flag in `SendLeaseBreakAsync`
  **and** the wait decision, so "we told the client to ack" and "we are waiting for an ack" cannot drift apart.
- **New carve-out — a compound CREATE does not park.** A compound chain assembles one response; an element
  answering out-of-band later would let its followers (QUERY_INFO/CLOSE) reply ahead of it. Windows sends
  CREATE+QUERY_INFO+CLOSE for metadata probes, and those opens do not cache, so no coherency is lost. Needed a
  `standalone` flag threaded through `DispatchOneAsync`; it is *exact*, not a heuristic
  (`offset == 0 && NextCommand == 0 && !RelatedOperations`).
- **A parked CREATE is deliberately not cancellable.** §3.3.5.16 lets the server ignore a cancel it cannot
  service, and here cancelling would be actively harmful: the open already exists, so a client that never
  learns its FileId could never close it. The timeout bounds the wait instead.
- **Files:** `Smb2Dispatcher.FileCommands.cs`, `.Oplock.cs`, `.Lease.cs`, `.cs` (standalone flag + signing),
  `.Concurrency.cs` (passes `standalone: true` — the concurrent path is single-frame by construction).

### W1.2 — Break timeout + force downgrade ✅ DONE (the "force downgrade" half turned out to be a no-op)
- New `SmbServerOptions.OplockBreakTimeout`, default **35 s** (the Windows value). One `ITimer` per break off
  the server's `TimeProvider`, in the new `BreakWaitTracker` (`src/Smb.Server/Oplocks/BreakWaitTracker.cs`).
- **There is no force-downgrade to do, and no manager leak to avoid** — the plan assumed a lazier manager than
  this codebase has. `InMemoryOplockManager.RequestOplock` / `InMemoryLeaseManager.RequestLease` downgrade
  their state **eagerly**, when the break is *decided*. The wait is purely about the holder's client-side dirty
  data, so a timeout has nothing left to force: it just releases the waiter. The manager stays the single
  authority over caching state; a second downgrade here would be a competing one.
- A late ack is a clean no-op (the tracker entry is gone) **and is still answered normally** — the ack is a
  valid frame regardless of whether anyone was waiting for it.
- **⬜ Consumer-visible:** `OplockBreakTimeout = TimeSpan.Zero` (or less) disables blocking break-before-grant
  and restores the pre-W1 behaviour. Documented as the escape hatch for a misbehaving client.

### W1.3 — Observability ✅ DONE
- `SmbServerMetrics`: `PendingBreaks` (gauge), `OplockBreaksSent`, `OplockBreakTimeouts` (+ `MetricsSnapshot`).
  OTel bridge: **`smb.oplock.pending_breaks`** (the W0.3 attribute that was never implemented),
  `smb.oplock.breaks_sent`, `smb.oplock.break_timeouts`.
- `OplockBreakTimeouts > 0` is the production signal behind "the file sticks": clients holding caching
  guarantees they no longer honour. It was previously unmeasurable, which is why the phase existed.
- Break *wait time* is not emitted separately — the parked CREATE's own `smb.command.duration` already carries
  it (the span covers the whole parked op), so a second histogram would measure the same thing twice.

### W1.4 — Doc correction ✅ DONE
Baseline finding #7 (`InMemoryOplockManager`'s "a lease … is not yet implemented") and the "deferred to a
later pass" paragraphs in `.Oplock.cs` / `.Lease.cs` / both managers now describe the implemented behaviour,
including the split that matters: **the manager decides breaks, the dispatcher waits for them.**

### W1.5 — Verify against the real client ⬜ OPEN
- Lab case: hold a file open in one process with a lease, open it conflicting from a second — the second open
  must not return before the break is resolved, and must not take ~35 s either (that would mean the ack is not
  arriving/not being matched — the F2 failure mode, one level up).
- **Test:** extend `WindowsClientInteropTests`, time-boxed like every other case there.

---

## Phase W2 — Metadata throughput under Windows (fix the barrier freeze)

Goal: remove hypothesis #1. The machinery already exists (`ConcurrentMetadataOps`) but is **default off**.

### W2.1 — Validate against real Windows, then flip the default
- ✅ **Validated (2026-07-15):** the whole interop suite (32 cases) runs green against the real Windows client
  with `ConcurrentMetadataOps=true`, including delete-on-close ordering, SET_INFO(rename)→CLOSE and
  QUERY_DIRECTORY paging (500 entries) under the concurrent path. `WindowsSmbLab` sets the flag.
- ⬜ **Open — the flip itself:** `SmbServerOptions.ConcurrentMetadataOps` is still `false` by default
  (`SmbServerOptions.cs:137`, comment "Default off while this rolls out"). The rollout gate that comment names
  is now met. **Consumer-visible decision — see the recommendation in the journal entry of 2026-07-15.**
- **Files:** `SmbServerOptions.cs` (default), host preset. **Tests:** the A2b/A5 suite stays green; the
  interop suite is the real-client evidence.

### W2.2 — Latency out of the metadata hot path (backend **and** own hooks)
- **Scenario-specific (library with overrides):** it is not only the `IFileStore` backend that creates latency —
  the **overridden auth/permission check** sits in the same barrier path. `IShareAccessPolicy.AuthorizeConnect`
  (TREE_CONNECT) and the **CREATE-time DACL check** run synchronously inside the op; if they do a DB/network/LDAP
  lookup per access they aggravate freeze #1 **directly**. Check: do these hooks cache? Do they block
  synchronously? A 20 ms lookup per CREATE on an Explorer folder open (hundreds of CREATEs) is precisely the
  freeze. (Phase W6 solved the connect-time half of this.)
- Reduce backend latency: audit `IFileStore` calls (unnecessary `stat`/`GetInfo` round trips in the CREATE/QUERY
  path?), the delete-on-close path, the bounded enumeration path (`QueryDirectoryAsync(maxEntries)`).
- **Deliverable:** measurement of metadata latency per op type **including the consumer's own auth/policy
  hooks**; document hotspots. (W2.1 with `ConcurrentMetadataOps=true` prevents a single such lookup from
  freezing the whole connection — it does not remove the latency itself.)

---

## Phase W3 — CHANGE_NOTIFY & Explorer behaviour ("case works flawlessly")

**Status: OPEN.** No freeze, but the Explorer view goes stale and needs F5 — and there is a resource leak
(below). The mechanism itself works against the real client since F2 was fixed
(`ChangeNotify_ReportsCreate_AndDropsWatchPromptly` is green).

### The shape of the problem

`HandleChangeNotify` is **one-shot per request**: it sets up a watcher, parks the request, and disposes the
subscription the moment it completes (`NotifyOnce.Attach`). Nothing watches the directory between the
completion of one CHANGE_NOTIFY and the arrival of the next. Explorer re-registers **after every
notification** — so every change that happens inside that window is lost, permanently. The code says as much
(`Smb2Dispatcher.Notification.cs:77-79`: "Correct buffering of changes between two requests remains an open
issue").

### W3.1 — Close the change-buffering gap (#4)
- Move the watch's lifetime from **the request** to **the directory open**: establish it on the first
  CHANGE_NOTIFY for that `SmbOpen`, tear it down at CLOSE. Add a bounded FIFO of pending `FileNotifyEvent`s per
  open.
  - Request arrives, buffer non-empty → complete **immediately** from the buffer (drain it).
  - Request arrives, buffer empty → park as today.
  - Watcher fires, request parked → complete it. Watcher fires, none parked → append to the buffer.
- **Overflow is a defined protocol state, not a failure:** when the buffer exceeds its cap, drop the contents
  and latch an overflow flag; the next request answers `STATUS_NOTIFY_ENUM_DIR` with an empty body, which tells
  the client to re-enumerate the directory itself. `NtStatus.NotifyEnumDir` already exists (used today for the
  too-small-output-buffer case). This bounds memory: a rename storm cannot grow the buffer without limit.
- **Filter/scope changes:** the CompletionFilter and WatchTree are per **request**, but the watch would now
  live on the open. Key the established watch by (filter, watchTree) and restart it if a request arrives with
  a different pair — Explorer re-registers with the same pair, so this is the rare path, but silently serving
  the wrong filter would be a correctness bug.
- **Files:** `Smb2Dispatcher.Notification.cs`, `SmbOpen` (watch + buffer + overflow flag), `IDirectoryWatcher`
  (unchanged — the seam already delivers events, only the lifetime changes).
- **Tests:** change in the window between two notifies → delivered immediately on re-register; buffer overflow
  → `STATUS_NOTIFY_ENUM_DIR`; a change *before* the first register is not delivered (nobody was watching —
  guards against over-buffering); different filter → watch restarted.

### W3.2 — Complete a parked CHANGE_NOTIFY at CLOSE (§3.3.5.10)
Found on 2026-07-15 while writing this plan: `PendingAsyncRequest.Owner` is documented as "the open that the
operation belongs to (**for cancellation at CLOSE**)" — but **no CLOSE path uses it**. Only connection teardown
(`CancelNonSurvivingPending`) and CANCEL complete a parked request. Closing a directory handle with a
CHANGE_NOTIFY parked on it therefore leaves the request and its watcher subscription hanging until the
connection dies.
- §3.3.5.10 requires outstanding CHANGE_NOTIFYs on a closing handle to be completed with
  `STATUS_NOTIFY_CLEANUP`. Today they are completed with nothing.
- Not currently visible against Windows (its watcher sends CANCEL before CLOSE — which is why the interop test
  is green), but it is a real leak against a client that just closes: `PendingRequests` and the watcher
  subscription both survive, bounded only by `MaxOutstandingRequests` per connection.
- **Files:** `Smb2Dispatcher.FileCommands.cs` (`HandleCloseAsync`), `PendingAsyncRequest`.
- **Tests:** park a CHANGE_NOTIFY → CLOSE the directory handle → final response is `STATUS_NOTIFY_CLEANUP` and
  `PendingRequests` is empty afterwards. `NtStatus.NotifyCleanup` (0x0000010C) needs adding.

### W3.3 — ZFS-capable watcher (#5)
- For the TrueNAS deployment, provide an `IDirectoryWatcher` based on inotify/ZFS events (instead of .NET
  `FileSystemWatcher`) and verify against Explorer (create/delete/rename appear without F5). **Measure before
  building:** .NET's `FileSystemWatcher` already uses inotify on Linux, so the question is specifically whether
  it is reliable on the ZFS mount in question — hypothesis #5 was never verified, and the two freeze causes we
  did measure were both something else entirely. If events turn out unreliable: documented fallback =
  `NullDirectoryWatcher` (Explorer then polls itself — slower but correct).
- **Files:** new watcher in `Smb.FileSystem` or the host. **Tests:** watcher delivers create/delete/rename;
  Explorer live refresh in the lab (manual-verify).

---

## Phase W4 — Flow control, large MTU, encryption against Windows

Baseline looks correct (credits with floor 256/cap 512, `MaxRead/Write 8 MiB`, GMAC/GCM) — but never evidenced
against Windows timing. (Partly covered since 2026-07-15: a 4 MiB LARGE_MTU round trip is green in the interop
suite.)

### W4.1 — Credit/sequence window under Windows load
- Drive large copies (several GB, many parallel multi-credit READ/WRITE) and check that the sequence window
  never closes (Windows stalls on credit starvation). Cross-check `CreditRequestResponse` on all paths
  (including interim/async finals).
- **Tests:** throughput run without a stall; OTel shows credits > 0 throughout.

### W4.2 — Encryption + signing end-to-end
- Check `RequireEncryption` + per-share encryption against Windows (AES-128-GCM default, AES-256 enforced);
  signing requirement with GMAC against 24H2. Reconnect/durable handle after a network blip (timeout 60 s vs.
  Windows ~16 min — W4.3).
- **Tests:** encrypted session read/write ok; incorrectly signed frame → AccessDenied.

### W4.3 — Durable/persistent reconnect after a real network blip
- Force a WLAN drop/NIC switch on the Windows VM; check that open handles (a Word document) survive and
  continue without data loss. Adjust `DurableHandleTimeout` (currently 60 s) to the Windows expectation if
  needed.

---

## Phase W5 — The "every case" interop catalogue (acceptance matrix)

Goal: tick off **every** relevant Windows operation explicitly against the real client once. That is the actual
"flawless" promise. Each row = one manual/semi-automatic test case in `docs/interop/MATRIX.md` with status
green/red/note.

> **2026-07-15:** `WindowsClientInteropTests` (32 cases) now automates a large part of the file/metadata rows
> below. What remains genuinely manual is the application-level behaviour (Explorer dialogs, Office) and
> anything needing a VM.

- **Explorer:** open folder (small/large), live refresh, copy/move (drag&drop + `Ctrl+C/V`), rename, delete
  (single/recursive/recycle bin), properties/timestamps, thumbnails/preview pane, "search in folder".
- **File semantics:** delete-on-close, rename over an open handle, ADS/Zone.Identifier (downloads from the
  network), attributes (ReadOnly/Hidden/System), timestamp preservation on copy, sparse/large files.
- **Office/applications:** open+save in Word/Excel (lock files `~$…`, byte-range locks), concurrent opening,
  correct "file in use" dialog.
- **CLI/tools:** `robocopy /MIR`, `xcopy`, `Get-ChildItem -Recurse`, `icacls` (ACL read), backup tools (VSS
  semantics out of scope, but evidence read-all).
- **Auth & own overrides (the core of this deployment):** NTLMv2 login from Windows against the **own
  `IIdentityBackend`**; the overridden `IShareAccessPolicy` filters share visibility + TREE_CONNECT correctly;
  a **permission deny** arrives as a clean `STATUS_ACCESS_DENIED` → Explorer shows the right dialog (no freeze,
  no generic error). Guest/anonymous correctly refused. (Kerberos/domain: n/a.)
- **Error paths:** sharing-violation dialog, access-denied on DACL deny, disk-full (quota →
  `STATUS_DISK_FULL`), path-too-long.

**Deliverable:** a fully green `docs/interop/MATRIX.md`. Every red case links back to a concrete milestone in
W1–W4.

---

## Phase W6 — Async authorization: I/O-bound auth without a connection freeze

Motivation: the W2.2 test proves that a slow **synchronous** `IShareAccessPolicy.AuthorizeConnect` freezes the
connection and that `ConcurrentMetadataOps` does **not** cover it. For this deployment (library with overridden
auth/permission check) an I/O-bound policy (DB/LDAP) is the normal case. Goal: support it cleanly without (a)
blocking a thread-pool thread sync-over-async and (b) without freezing independent I/O on other trees.

> **Verified clarification (checked at the read loop, 2026-07-14):** making the policy async is **not enough**.
> The host read loop runs a barrier op with `await ProcessMessageAsync(...)` **before** it reads the next frame
> (`SmbConnectionHandler.cs:171-172`). An async `AuthorizeConnect` does release the thread (no sync-over-async),
> but the read loop only reads the next frame once the TREE_CONNECT is done → the independent READ stays frozen.
> **The actual freeze fix is to take TREE_CONNECT out of the read-loop barrier** (W6.3, analogous to "CREATE
> runs free" from `ENTERPRISE_HARDENING_ROADMAP.md` A2b: the client cannot send an op on a TreeId it has not
> been given yet). The async seam (W6.1/W6.2) is the **precondition** for that — otherwise an off-loop
> TREE_CONNECT would just block the task thread synchronously.

### W6.1 — Async seam on `IShareAccessPolicy` (additive) ✅ DONE
- `IsVisibleAsync`/`AuthorizeConnectAsync` as **default interface methods** delegating to the synchronous ones.
  No breaking change; existing sync policies (`AllowAllSharePolicy`, `DelegateSharePolicy`, custom) run
  unchanged.
- **Files:** `src/Smb.Server/Authorization/ShareAccess.cs`.
- **Tests:** an async-only policy is called correctly; a sync policy delegates identically by default.

### W6.2 — Dispatcher consumes the async seam ✅ DONE (TREE_CONNECT; enumeration deferred)
- `HandleTreeConnect` → `HandleTreeConnectAsync` (`async ValueTask<ResponseSegment>`, param `ReadOnlyMemory`
  instead of `ReadOnlySpan`, span parsing before the `await`); the dispatch switch awaits it.
  `AuthorizeConnectAsync` is awaited → no more sync-over-async thread block. The default policy delegates to
  sync → behaviour unchanged. (Connection freeze **not** yet fixed — that is W6.3.)
- **Followed up in W6.2b ✅ (see below):** share enumeration is async now too.
- **Files:** `src/Smb.Server/Smb2Dispatcher.cs` (HandleTreeConnectAsync + dispatch arm).
- **Tests:** `AsyncSeam_IsUsedAtTreeConnect_AsyncDenyRejects` (WindowsFreezeReproTests) — policy grants sync,
  denies async → TREE_CONNECT gets `ACCESS_DENIED` ⇒ proves the async seam decides.

### W6.3 — Take TREE_CONNECT out of the read-loop barrier (the actual freeze fix) ✅ DONE
- TREE_CONNECT classified concurrent-eligible (**runs free** like CREATE, gated on `ConcurrentMetadataOps`):
  creation-like, no following op references the not-yet-issued TreeId (`AllocateTreeId` via `Interlocked`),
  `session.TreeConnects` is a `ConcurrentDictionary`. **Teardown** lifecycle
  (LOGOFF/TREE_DISCONNECT/SESSION_SETUP/NEGOTIATE/CANCEL) stays a barrier and drains in-flight TREE_CONNECTs
  first; ordering holds because SESSION_SETUP (barrier) completes in arrival order before a following
  TREE_CONNECT.
- **Verified nuance (documented in the classifier + test):** off-barrier fixes the freeze **only with a truly
  asynchronous policy**. A sync-blocking policy stalls the read-loop thread already in the synchronous prefix
  of the concurrent frame (before the `await` suspends) — so it still freezes (evidenced by the unchanged W2.2
  test with sync policy + flag on). The fix needs **both** parts: async seam (W6.1/W6.2) **and** off-barrier
  (W6.3).
- **Files:** `src/Smb.Server/Smb2Dispatcher.Concurrency.cs` (classifier `case TreeConnect` + class doc).
- **Tests (pair, isolating off-barrier as the fix — same async policy, only the flag differs):**
  `SlowAsyncAuthorizeConnect_DefaultBarrier_StillFreezesOtherShareIo` (flag off → READ freezes) and
  `SlowAsyncAuthorizeConnect_ConcurrentMetadataOps_DoesNotFreezeOtherShareIo` (flag on → READ gets through
  despite a hanging async connect).

### W6.4 — Builder ergonomics ✅ DONE
- New `AsyncDelegateSharePolicy` (`Authorization/ShareAccess.cs`): async
  `AuthorizeConnectAsync`/`IsVisibleAsync` from lambdas; sync interface members as a fallback (they block on
  the delegate — only for external callers of the sync API). Builder overload
  `SmbServerBuilder.UseShareAuthorizationAsync(authorizeConnect, isVisible?)` mirroring the sync variant.
  `DelegateSharePolicy` (sync) unchanged.
- **Tests:** `ShareAccessPolicyAsyncTests` +2 (async path runs the delegate; sync fallback yields the same
  decision / default visibility true).

### W6.2b — Share enumeration async ✅ DONE
Less invasive than feared: the policy is consulted at **pipe open** (`OpenRpcEndpoint`), not in RPC request
handling — the share list is determined once and baked into the `SrvsvcEndpoint`. The DCERPC/NDR stack never
touches the policy and stays synchronous.
- `SmbServerState.GetVisibleSharesAsync` (new, uses `IsVisibleAsync`); the **synchronous** `GetVisibleShares`
  remains unchanged (public API + existing test) → no breaking change.
- `OpenRpcEndpoint` → `OpenRpcEndpointAsync`; `HandlePipeCreate` → `HandlePipeCreateAsync` (`ReadOnlyMemory`
  instead of `ReadOnlySpan`, parsing before the `await`; `CreateRequest` is a `class`), the caller in the
  already-async `HandleCreateAsync` awaits it.
- **Behaviour-neutral:** for every sync policy `IsVisibleAsync` delegates to `IsVisible`, shares are checked in
  `Shares` order ⇒ identical list as before.
- **Tests:** `RpcShareEnumTests.ShareEnumeration_AppliesPolicy_ThroughAsyncPath` (theory) — sync policy filters
  exactly as before (neutrality proof) **and** async policy filters (new capability); the existing E2E test
  `EndToEnd_ShareEnumeration_OverIpcPipe_ListsShares` runs unchanged through the new path.

### W6.5 — Doc/rule updated ✅ DONE
- **Final design rule:** I/O-bound auth belongs in the **async** policy members (`AuthorizeConnectAsync` /
  `IsVisibleAsync`; lambda via `UseShareAuthorizationAsync` or a custom policy) and should **await instead of
  blocking synchronously**; with `ConcurrentMetadataOps=true` it then no longer freezes independent I/O (W6.3).
  Caching stays sensible but is no longer a freeze necessity. **Per-file** permissions stay in
  `IFileStore.CreateAsync` (covered by the same flag). **Both** policy paths of the server (TREE_CONNECT +
  enumeration) are async now — the sync members remain only for external callers of the sync API.

---

## Status Journal

- **2026-07-14** — Roadmap created. Baseline verified against the code (table above): baseline close to
  Windows, the real gaps are behaviour-under-Windows-timing, not missing features. Freeze primarily hypothesis
  #1 (metadata barrier, `ConcurrentMetadataOps` default off) on a latency-bearing backend, secondarily #2/#3
  (break handshake without waiting/timeout). **Order:** W0 (prove the freeze) → then the phase the trace
  confirms, expected **W2** first, W1 if coherency/#2 is confirmed, then W3/W4, W5 continuously.
  **Open decision:** target deployment workgroup (NTLM) or domain (Kerberos) first? → determines W0.1/W5 auth.
  Next action: **W0.1** (set up the Windows VM lab) + **W0.3** (latency shim + `barrier_wait_ms` span), to
  reproduce the freeze and attribute it to a hypothesis.
- **2026-07-14** — **W0.3 freeze PROVEN (repro test green).** The freeze mechanism is unambiguously located in
  the code: with `ConcurrentMetadataOps=false` (default) the host read loop executes a metadata op as a
  **barrier** with `await ProcessMessageAsync(...)` **directly in the read loop** (`SmbConnectionHandler.cs:172`)
  — it reads **no further frame** until the op is done. A CREATE hanging in the backend therefore freezes the
  **whole connection**, including independent READs on already-open files. New test
  `tests/Smb.Tests/WindowsFreezeReproTests.cs` (2 tests) proves this **deterministically** over the real TCP
  host loop: backend `SlowCreateGatedStore` blocks only `slow.txt` (no timing → not flaky). (1)
  `DefaultBarrier_SlowMetadataOp_FreezesUnrelatedRead`: pipelined CREATE(slow)+READ(fast-open) → **no answer
  within 2 s** (freeze); after gate release both flow. (2)
  `ConcurrentMetadataOps_SlowMetadataOp_UnrelatedReadCompletes`: same setup, flag on → **READ (mid 6) answers
  immediately** while CREATE (mid 5) still hangs. Same backend, only the flag differs → isolates the barrier as
  the cause **and** evidences the fix. **Hypothesis #1 confirmed.** Test gotcha (fixed):
  `Task.WaitAsync(timeout)` only aborts the wait, not the socket read → the hanging read then swallowed the
  answer (desync); now the read itself is aborted via `CancellationTokenSource` (0 bytes read during the
  freeze → clean). **Suite Smb.Tests 545 → 547 green.** Next action: **W2.1** — validate
  `ConcurrentMetadataOps=true` against real Windows (W0.1 lab) and flip the default/TrueNAS preset; optionally
  in parallel the OTel `barrier_wait_ms` instrumentation (rest of W0.3) as a permanent regression guard.
  **Open decision remains:** workgroup (NTLM) or domain (Kerberos) first.
- **2026-07-14** — **Deployment decision resolved: no Kerberos/no domain.** The server is used as a **library**
  that overrides shares / user auth / permission checks through the extension points (own
  `IIdentityBackend`/`ISpnegoNegotiator`, `IShareAccessPolicy`, CREATE DACL check). → auth path = **NTLMv2
  against own backend**; roadmap phase B1 (SSPI Kerberos) **out of scope** for this deployment. W0.1 reduced to
  workgroup-only; the W5 auth row focused on the override hooks (deny → clean `STATUS_ACCESS_DENIED`). **New
  scenario-specific freeze factor in W2.2:** the overridden auth/policy check sits in the same barrier hot path
  as the backend — a DB/network lookup per CREATE/TREE_CONNECT aggravates #1 directly;
  `ConcurrentMetadataOps=true` prevents the whole connection from freezing, not the latency itself. Next action
  unchanged **W2.1** (validate the flag against real Windows + set it in our own builder).
- **2026-07-14** — **W2.2 auth latency edge case tested + recorded.** New test
  `SlowAuthorizeConnect_FreezesOtherShareIo_EvenWithConcurrentMetadataFlag` in `WindowsFreezeReproTests.cs`.
  Result (green): a slow **synchronous** `IShareAccessPolicy.AuthorizeConnect` freezes — **even with
  `ConcurrentMetadataOps=true`** — an independent READ on an already-connected, working share, because
  TREE_CONNECT is a lifecycle op and therefore **always** a barrier outside the flag. **The design rule derived
  for the library consumer:** (1) per-file permission checks belong in the consumer's own
  `IFileStore.CreateAsync` — there the flag covers the latency (mechanically identical to the proven backend
  CREATE freeze). (2) The connect-time policy (`AuthorizeConnect`) is **synchronous without an async variant**
  → **cache** the decision, do not do I/O per connect. **Suite Smb.Tests 547 → 548 green.** That covers the
  freeze from both angles relevant to this deployment (backend/per-file latency **and** connect auth). Next
  action still **W2.1** (set the flag in our own builder + validate against real Windows); noted improvement:
  consider an **async `IShareAccessPolicy` variant** (so I/O-bound auth does not block the barrier thread
  synchronously) — candidate for a later W phase.
- **2026-07-14** — **Phase W6 documented + W6.1 DONE.** Correction of a previously too-optimistic statement:
  verified at the read loop that an **async** policy does **not** fix the connection freeze on its own — the
  read loop `await`s the barrier op before the next frame read (`SmbConnectionHandler.cs:171-172`); the actual
  fix is TREE_CONNECT off-barrier (**W6.3**). Phase W6 created with this clarification + milestones W6.1–W6.5.
  **W6.1 implemented:** `IShareAccessPolicy` extended with default interface methods
  `IsVisibleAsync`/`AuthorizeConnectAsync` (delegating to the synchronous ones) — purely additive, no breaking
  change, all existing policies unchanged. Tests `ShareAccessPolicyAsyncTests` (3, green): sync default
  delegation, deny pass-through, pure async override path. **Suite Smb.Tests 548 → 551 green.** Not wired up
  yet (that is W6.2). Next action: **W6.2** — make `HandleTreeConnect` async and await `AuthorizeConnectAsync`
  (+ enumeration `IsVisibleAsync`), so I/O auth no longer blocks a thread sync-over-async; then **W6.3** (the
  freeze fix).
- **2026-07-14** — **W6.2 DONE (TREE_CONNECT auth path).** `HandleTreeConnect` → `HandleTreeConnectAsync`
  (async, `ReadOnlyMemory` instead of `ReadOnlySpan`, all span parsing before the `await`; `TreeConnectRequest`
  is a `class` and survives the await fine); the dispatch switch arm awaits. `AuthorizeConnectAsync` is now
  awaited — I/O-bound auth no longer blocks a thread sync-over-async. The default policy delegates to sync ⇒
  **behaviour-neutral** (551 existing tests unchanged green). Behavioural evidence:
  `AsyncSeam_IsUsedAtTreeConnect_AsyncDenyRejects` (sync grant / async deny → `ACCESS_DENIED`). **Suite
  551 → 552 green.** **Enumeration (`IsVisible`) deliberately deferred** (synchronous srvsvc RPC path, separate
  rework, rarer browsing scenario — W6.2b if needed). Connection freeze still open → next action **W6.3**:
  classify TREE_CONNECT concurrent-eligible ("runs free" like CREATE) so a slow (async) policy no longer
  freezes independent I/O — the actual fix; plus the inversion of the W2.2 edge-case test.
- **2026-07-14** — **W6.3 DONE → connect freeze fixed.** TREE_CONNECT classified concurrent-eligible
  (`Smb2Dispatcher.Concurrency.cs`, `case TreeConnect: return metadataConcurrency;`), "runs free" like CREATE;
  invariants verified against the code (`AllocateTreeId` Interlocked, `TreeConnects` ConcurrentDictionary,
  ordering via the SESSION_SETUP barrier). Class doc: TREE_CONNECT moved from "lifecycle barrier" to
  "creation-like runs free"; only teardown lifecycle stays a barrier. **Important verified nuance:**
  off-barrier only helps a truly asynchronous policy — a sync-blocking policy stalls the read loop already in
  the synchronous prefix of the concurrent frame (the W2.2 test with sync policy + flag on therefore still
  freezes, unchanged green). Fix = async seam (W6.1/W6.2) **and** off-barrier (W6.3) together. Test pair
  `SlowAsyncAuthorizeConnect_*` (flag off freezes / flag on fixed, same async policy → isolates off-barrier as
  the fix). **Suite Smb.Tests 552 → 554 green, no regressions.** Next action: **W6.4** (builder ergonomics:
  `UseShareAuthorizationAsync` + async `DelegateSharePolicy`).
- **2026-07-14** — **W6.4 + W6.5 DONE → phase W6 rounded off (except W6.2b).** `AsyncDelegateSharePolicy` +
  `UseShareAuthorizationAsync(...)` builder overload (async auth by lambda; sync fallback for the
  still-synchronous enumeration path). Tests `ShareAccessPolicyAsyncTests` +2. **Suite Smb.Tests 554 → 556
  green.** Brief stumble: `<paramref>` in a type `<summary>` → CS1734 (paramref is only valid for
  method/ctor params), changed to `<c>isVisible</c>`. **Phase W6 summary:** async authorization seam (W6.1),
  dispatcher awaits it (W6.2), TREE_CONNECT off-barrier (W6.3 = connect freeze fix), builder ergonomics (W6.4),
  rule/doc (W6.5). **W6.2b remains open** (enumeration `IsVisible` async — synchronous srvsvc RPC path, rarer
  browsing scenario, deliberately deferred). Overall freeze status for this deployment: backend/per-file
  latency (W2, `ConcurrentMetadataOps`) **and** I/O-bound connect auth (W6) are covered by one flag + an async
  policy.
- **2026-07-14** — **W6.2b DONE → PHASE W6 COMPLETE.** Enumeration made async, the condition "must work exactly
  the same" honoured and **evidenced**. Finding on entry: the rework was far less invasive than planned — the
  policy is consulted at **pipe open** (`OpenRpcEndpoint`), not in RPC handling; the list is baked into the
  `SrvsvcEndpoint`, the DCERPC/NDR stack stays untouched and synchronous. Implemented:
  `GetVisibleSharesAsync` (new; sync `GetVisibleShares` stays → no breaking change, existing test green),
  `OpenRpcEndpointAsync`, `HandlePipeCreateAsync` (ReadOnlyMemory, parse before await), the caller in the async
  `HandleCreateAsync` awaits. **Neutrality proof:** new theory test
  `ShareEnumeration_AppliesPolicy_ThroughAsyncPath` — sync policy filters identically to before, async policy
  filters too; the existing E2E enum test runs unchanged through the new path. Outdated doc spots
  ("enumeration is still synchronous") in `AsyncDelegateSharePolicy` + `UseShareAuthorizationAsync` corrected.
  Gotcha: `<see cref>` to a type from a non-imported namespace → CS1574, used `<c>`. **Suite Smb.Tests
  556 → 558 green.** **Phase W6 complete (W6.1–W6.5 + W6.2b):** both policy paths of the server (TREE_CONNECT +
  enumeration) are async, TREE_CONNECT runs off-barrier, lambda ergonomics in place. Next sensible action:
  **W2.1** (validate flag + async policy against real Windows, W0.1 lab) or **W1** (blocking break-before-grant)
  — user's call.
- **2026-07-14** — **W0.1 DONE — and the VM assumption was wrong.** Re-evaluated on the question "does this
  have to be a VM? it gets bloated otherwise": **no**. The real Windows SMB client is a kernel driver already
  running locally; a server on `127.0.0.1:445` is served by exactly that client for normal UNC access from .NET
  code ⇒ **real interop in `dotnet test`, without a VM**. Verified: a low-port bind needs **no elevation** on
  Windows (probe on 987 from a non-elevated process ok) — the only blocker is the occupied port 445
  (`srv2.sys`, PID 4; `Stop-Service LanmanServer -Force`, a system change by the user). New:
  `tests/Smb.Tests/WindowsClientInteropTests.cs` (2 tests) — (1) file cases over real UNC paths
  (read/write/enumerate/rename/delete/subdirectory) after a `net use` NTLM login against our own
  `InMemoryIdentityBackend`; (2) the freeze case against the real client (`GatedCreateFileStore` holds a CREATE
  → an independent read must not stall). **Gated:** no Windows / 445 occupied → early return with an actionable
  message (pattern of the QUIC tests; `Assert.Skip` does not exist in xUnit 2.9.2). The skip fires cleanly here
  (`AccessDenied`, because the kernel driver holds the port exclusively). `docs/interop/WINDOWS_LAB.md` written
  (preparation + reversal, diagnosis via SMBClient event logs/`Get-SmbConnection`/cache reset, documented
  loopback limits). **Suite Smb.Tests 558 → 560 green.**
  **Honestly open:** the loopback flow is **not verified end-to-end** here — 445 is occupied on this machine and
  freeing it is a system change by the user. The tests compile and skip cleanly; whether the Windows client
  actually gets through (NTLM login, signing against 24H2 defaults, file cases) will show on the first run with
  `LanmanServer` stopped. **That is the next step (W2.1).**
- **2026-07-14** — **Defect fixed: the interop tests reported false green.** Found by the user on the first run
  ("implementation still not runnable"): the early return in the gate made the skipped tests appear as
  **"succeeded: 2"** — the giveaway was the ~160 ms runtime (real SMB interop takes a multiple of that). **A
  test that silently does nothing and reports green is worse than no test.** Fix: added `Xunit.SkippableFact`
  (1.5.61), moved the tests to `[SkippableFact]` + `Skip.IfNot`/`Skip.If` → the report now says `skipped: 2`
  instead of `succeeded: 2`. **Additionally tightened:** a failed `net use` NTLM login is **no longer** skipped
  away but turns the test **red** (`Connect()` with an assert) — only the *environment* (no Windows / 445
  occupied) may skip, every result after that is real. API gotcha: `Skip.Always` does not exist, only
  `Skip.If`/`Skip.IfNot`.
  **Empirically evidenced (instead of assumed):** port 445 is held **exclusively** by `srv2.sys` (PID 4) —
  probe binds on `127.0.0.1`, `127.0.0.2` and `127.0.0.55` **all** return `AccessDenied`. So there is **no**
  workaround via an alternative loopback address; `Stop-Service LanmanServer -Force` (admin shell) is
  mandatory. **Suite: 558 green + 2 skipped = 560.**
  **Still open (unchanged):** the loopback flow has **never run end-to-end** — that is the next step (W2.1) and
  needs the user's system intervention.
- **2026-07-15** — **W0.1 lab ran end-to-end for the first time (user stopped `LanmanServer`) → the freezes are
  found, measured and fixed. The initial hypothesis was wrong.** See
  [Freeze causes](#freeze-causes--measured-in-the-windows-lab-2026-07-15) for the full table. In short:
  - **F1 — unsigned error responses (the actual "almost every operation freezes" cause).** The first real run
    failed with `IOException: Ungültige Signatur` (`hr=0x80090006`, NTE_BAD_SIGNATURE) on write. Cause: every
    `BuildError` path builds `ResponseSegment.Unsigned(...)` because the handler has no session in hand. On a
    signed session the Windows client **discards** such a response (§3.2.5.1.3) instead of failing the call ⇒
    the operation runs into the client timeout. Fix: `SignIfRequestWasSigned` centrally at response assembly,
    in **both** dispatch paths. **Gotcha that cost time twice:** the fix in `ProcessMessageAsync` (sequential)
    alone changes **nothing** for the real client — with `ConcurrentMetadataOps=true`, CREATE/QUERY_INFO/READ
    run through `ExecutePreparedFrameAsync`, which assembles its response **independently**. Anyone changing
    response generation must touch **both** paths.
  - **F2 — async CANCEL by MessageId instead of AsyncId: 64.7 s freeze.** Uncovered by the new CHANGE_NOTIFY
    test. `watcher.Dispose()` (= Explorer closing a folder window) blocked **64,749 ms**; after the fix
    **16 ms**. Measured: `async=True mid=2 asyncId=2` against `pending=[mid14/async2]` — Windows does **not**
    put the original's MessageId in the CANCEL header, and §3.3.5.16 requires the lookup by **AsyncId** when
    `SMB2_FLAGS_ASYNC_COMMAND` is set.
  - **F3/F4 — timestamps + DOS attributes were not settable over SMB** (silent success), and QUERY_INFO on a
    handle reported attributes hard-coded as `Normal`. Both fixed (new seam `IBasicInfoStore`; `MapAttributes`
    now used by both paths).
  - **Hypotheses #1–#5 of the baseline table were involved in none of the four findings.**
    `ConcurrentMetadataOps` (#1) is on in the lab and its test (`SlowMetadataOp_DoesNotStallUnrelatedRead`) is
    green — the barrier fix from W2.1 is correct, it just was not the cause of the reported Explorer freezes.
  - **Test expansion:** `WindowsClientInteropTests` 2 → **32 tests** across the operations Explorer really
    drives (read/write/overwrite/append/set-length/offset I/O, 4 MiB LARGE_MTU round trip, rename/delete/
    directories, enumeration incl. 500-entry paging + wildcard + Unicode, timestamps/attributes, volume free
    space via `GetDiskFreeSpaceEx`, error statuses, sharing violation, parallel readers, byte-range locks,
    flush, copy, CHANGE_NOTIFY, freeze case). **Every case is time-boxed** (`Timed`, 25 s) — a freeze must fail
    as a freeze, not hang the test run.
  - **Server harness reworked:** `WindowsSmbLab` is now a **collection fixture** (one server for all classes —
    xUnit parallelises classes, two labs would fight over 445), shares `Files` (writable), `ReadOnlyFiles`,
    `SlowFiles` (gated).
  - **Lab empirics (complements the 2026-07-14 entry):** with `LanmanServer` stopped, **all** 127.x addresses
    are bindable and reachable from user-mode TCP — but the **client** (kernel driver) routes **only to
    127.0.0.1**; anything else fails with ERROR_NETWORK_UNREACHABLE (1231). So an address per test (to dodge
    the client's connection cache) is **not** an option.
  - **Test gotchas (real, hit repeatedly):** (1) `LocalFileStore(dir)` is **`readOnly: true` by default** — the
    original interop test therefore tested write *failures* instead of writing. (2) The backend check must not
    be `File.ReadAllText`: the server keeps its handle open (FileShare.ReadWrite), `File.ReadAllText` demands
    deny-write ⇒ sharing violation on the **local** path. (3) `task.Wait(t)` wraps failures in
    `AggregateException` and breaks every `ThrowsAny<IOException>` → `Task.WhenAny`. (4) The client caches
    directory contents/negative lookups per path for a few seconds ⇒ test directories carry a per-run suffix.
    (5) Delete over SMB is delete-on-close and the client may defer CLOSE ⇒ backend visibility is polled
    (`AssertEventually`), not asserted instantly.
  - **Suite: Smb.Tests 560 → 595 green, Smb.Fuzz 128 green (723 total).** Interop class green 8 runs in a row.
  **Next action:** W1 (break-before-grant) stays open and is now the most plausible remaining candidate for
  "the file sticks" cases under Explorer/Office/Defender; W3 (CHANGE_NOTIFY gap between two requests) is still
  real and now testable. **Most importantly:** the four findings show that the remaining Windows cases belong
  **measured**, not derived — the interop catalogue (W5) is the basis for that now.
- **2026-07-15** — **W1 + W3 planned in detail; two hard findings recorded before any code was written.**
  (Documents converted to English per the user's instruction — this roadmap and `docs/interop/WINDOWS_LAB.md`
  were the only German ones; everything else already was English.)
  - **W1 blocker found in the code (would have produced a new ~35 s freeze):** a CREATE parked on a break ack
    would sit in the host's `_inflight` list, while `OPLOCK_BREAK` — which carries the ack — is **not**
    concurrent-eligible and therefore runs as a barrier that **first drains `_inflight`**
    (`SmbConnectionHandler.cs:169-171`, `Smb2Dispatcher.Concurrency.cs` `TryClassifyConcurrent` →
    `default: false`). Parked CREATE waits for the ack, the ack waits for the parked CREATE ⇒ deadlock until
    the break timeout. **Therefore W1.0 (take the ack off the barrier) is a hard prerequisite for W1.1** and is
    written into the phase as such, with a documented fallback if the classification proves unsafe.
  - **W3 gap found in the code:** `PendingAsyncRequest.Owner` is documented as "for cancellation at CLOSE", but
    **no CLOSE path uses it** — only connection teardown and CANCEL complete a parked request. Closing a
    directory handle with a CHANGE_NOTIFY parked on it therefore never completes it (§3.3.5.10 wants
    `STATUS_NOTIFY_CLEANUP`) and leaks the request + watcher subscription. Not visible against Windows (its
    watcher cancels before closing — which is why the interop test is green), but real against any client that
    just closes. Became milestone **W3.2**; `NtStatus.NotifyCleanup` needs adding.
  - **W2.1 status corrected:** the "validate against real Windows" half is **done** (32 interop cases green
    with the flag on); what remains is the **flip of the default** in `SmbServerOptions.cs:137`, which is a
    consumer-visible decision. **Recommendation: flip it.** The gate its own comment names ("default off while
    this rolls out") is met, the concurrency correctness is enforced by `KeyedReaderWriterQueue` + the A2b
    suite, and the current default ships the barrier freeze to everyone who does not know to set the flag —
    for an enterprise library the safe default should be the correct one, with an opt-out for the rare case.
    Known trade-off to document when flipping: `MaxOpenHandlesPerSession` becomes a soft bound under the flag
    (already documented on the option).
  - **Nothing implemented for W1/W3 in this entry** — plan only. Next action: **W1.0 + W1.1 together** (W1.0
    alone is not observable), then W1.2.
- **2026-07-15** — **W1.1–W1.4 IMPLEMENTED (break-before-grant). The plan's own blocker, W1.0, turned out to
  be unnecessary — and the design it prescribed instead had a second, worse deadlock.**
  - **The W1.0 correction is the headline.** The analysis ("parked CREATE ∈ `_inflight` → ack barrier drains
    `_inflight` → deadlock") is factually right but rests on an unstated assumption: that the CREATE `await`s
    the ack **inline**, keeping its frame in flight. W1.1 in the same document prescribed the opposite
    ("interim **exactly as CHANGE_NOTIFY does**" — which does *not* park its frame). **Park the response, not
    the frame:** the CREATE returns as soon as interim + notification are out, so it has left `_inflight`
    before the ack arrives; the barrier drains fine; the classifier is untouched. `OPLOCK_BREAK` stays a
    barrier frame. **And the prescribed design was worse than "just more code":** with
    `ConcurrentMetadataOps=false` (**still the default**) CREATE *is* the barrier, so the read loop would sit
    inside `await ProcessMessageAsync(create)` and never read the ack **regardless** of how OPLOCK_BREAK is
    classified — W1.0 would have fixed a deadlock only for the non-default flag setting. The implemented
    design works with the flag on and off; `AcknowledgmentOnTheSameConnection_ReleasesParkedCreate_WithoutDeadlock`
    is the proof. **Meta-lesson (same shape as F1/F2):** the paragraph that declares itself the blocker gets
    believed — it was specific, code-referenced and confidently worded, and still wrong. Re-derive the
    constraint from the design you are about to write.
  - **Deviation from the CHANGE_NOTIFY pattern, forced by W1.1's own ordering rule** ("interim before
    notification", §2.2.24): the interim is written **inside** the handler (awaited `SendOutOfBandAsync`) and
    the frame answers `null`. Returning the interim as the frame's response would leave the ordering to a race
    — the handler returns, *then* the caller assembles and writes, while the break send is already in flight
    and a fast holder could ack, releasing the final before the client has seen the AsyncId it is tagged with.
    `HandleCreateAsync` is now `ValueTask<ResponseSegment?>`.
  - **New carve-out: a compound CREATE never parks.** One assembled response per chain ⇒ an element answering
    out-of-band later would let CREATE+QUERY_INFO+CLOSE reply out of order. Those probe opens do not cache, so
    no coherency is lost. Threaded a `standalone` flag through `DispatchOneAsync`; exact, not heuristic
    (`offset == 0 && NextCommand == 0 && !RelatedOperations`). The concurrent path is standalone by
    construction (`TryBeginConcurrentFrame` rejects compounds).
  - **W1.2's "force downgrade + avoid a manager leak" was a no-op against this codebase** — the plan assumed a
    lazier manager. Both default managers downgrade **eagerly** when they *decide* the break, so a timeout has
    no state left to force and there is no leak: it only releases the waiter. New
    `SmbServerOptions.OplockBreakTimeout` (default 35 s, the Windows value), `BreakWaitTracker` with one
    `ITimer` per break off the server `TimeProvider`. **Consumer-visible:** `TimeSpan.Zero` disables blocking
    break-before-grant (pre-W1 behaviour) — the escape hatch for a misbehaving client.
  - **F5 found while wiring this up — F1's root cause, third instance.** `SendAsyncFinalAsync` /
    `SendFinalLockResponseAsync` sent **error finals unsigned** on a signed session ⇒ a Windows client
    discards a cancelled CHANGE_NOTIFY / refused blocking LOCK and waits out its own timeout. Fixed
    (`SignedLikeRequest`). **The TOP-GOTCHA needs restating:** it is not "there are two dispatch paths" — there
    are **four places a response reaches the wire, and only two pass through `SignIfRequestWasSigned`**. See
    the F5 row in the freeze-cause table.
  - **Ack-required is now single-sourced.** `LeaseAckRequired` feeds both the wire flag and the wait decision
    (they could previously have drifted). Classic oplocks: ack required iff the holder's level *was*
    Exclusive/Batch — read from `open.OplockLevel` **before** the mirror is overwritten, because the mirror is
    what the *client* was granted and that is what decides whether it acks at all (§3.3.4.6: a LEVEL_II holder
    never acks a LEVEL_II→None break). Directory-lease breaks (`BreakParentDirectoryLease`) are deliberately
    **never** waited on: they invalidate a listing of a *different* file than the one being created (§3.3.4.18).
  - **A parked CREATE is deliberately not cancellable** (§3.3.5.16 permits ignoring an unserviceable cancel):
    the open already exists, so a client that never learns its FileId could never close it. The timeout bounds
    the wait.
  - **4 existing tests encoded the pre-W1 behaviour** and were updated (OplockTests ×2, LeaseDispatcherTests
    ×2) — same story the roadmap already recorded for F1/F2: written against the implementation, not the spec.
    They now assert the notification wire shape and let `BreakBeforeGrantTests` own the park/ack round trip.
  - **Test gotcha (real, cost a design decision):** the repo's existing `ManualTimeProvider`
    (DurableHandleTests/TimeoutTests) overrides **only `GetUtcNow`** — it does **not** drive
    `TimeProvider.CreateTimer`, so a break timer armed through it would sit on the *real* clock (a 35 s sleep,
    or a flake). `BreakBeforeGrantTests` carries a fake that drives timers too.
  - **Verification status — honest:** `BreakBeforeGrantTests` (7 new) ran **green in 960 ms** (no real waits).
    **The full suite was NOT re-run after the 4 legacy tests were updated**: a **Visual Studio uninstall
    started on this machine mid-session** (MsiInstaller, 22:05–22:07) and removed .NET 10 *and* emptied the
    .NET 9 runtime folders (`C:\Program Files\dotnet\shared\Microsoft.NETCore.App\9.0.2` and `9.0.8` are now 0
    items; `host\fxr` has no 9.x). Only SDK 8.0.406 is left, which cannot target net9 ⇒ nothing in this repo
    builds until .NET 9 is reinstalled. **Before committing: reinstall the .NET 9 SDK/runtime and re-run
    `dotnet test tests/Smb.Tests`.** Expected 595 + 7 new = **602**, minus nothing (the 4 updated tests keep
    their names except two renames: `SecondOpen_BreaksHolderToLevelII_AndNotifiesTheHolder`,
    `SecondDistinctLeaseKey_BreaksHolderToRead_AndNotifiesTheHolder`).
  - **Next action: W1.5** — verify against the real client in the W0.1 lab (hold a file open with a lease,
    open it conflicting from a second process: the second open must not return before the break resolves, and
    must not take ~35 s either — a 35 s wait means the ack is not arriving/not being matched, the F2 failure
    mode one level up). Then **W3** (CHANGE_NOTIFY buffering gap + W3.2 `STATUS_NOTIFY_CLEANUP` leak) and the
    **W2.1 default flip**, which is now more attractive than before: the W1 design deliberately does not
    depend on it.
- _(append progress here, tick off items in the phases)_
