# Enterprise Hardening Roadmap: scalability, auth, HA, observability

> **Purpose of this document:** Work plan AND resumption protocol for the post-`ENTERPRISE_ROADMAP.md`
> hardening effort. The [Status Journal](#status-journal) at the bottom states exactly which
> milestone is complete, where work is happening, and what comes next. On interruption: read the
> journal, continue at the first unchecked item. Leave inline `<!-- NOTE: -->` comments as work
> proceeds.
>
> This roadmap grew out of an external code review (2026-07-14). The review's six points were
> verified against the source before planning; the verification verdicts are recorded below so we
> do not re-litigate settled facts.

## Verification of the review (2026-07-14)

| # | Review claim | Verdict | Evidence |
|---|--------------|---------|----------|
| 1 | Only READ/WRITE run concurrently; all metadata ops (CREATE/CLOSE/SET_INFO/QUERY_*) are strictly serial per connection | **TRUE — biggest lever** | `Smb2Dispatcher.Concurrency.cs` admits only single non-compound READ/WRITE to the concurrent path; everything else is a per-connection **barrier** that drains all inflight I/O (`SmbConnectionHandler.DrainInflightAsync`). |
| 2 | `IFileHandle` forces sync-over-async in teardown (`Dispose()`, `GetInfo()`) | **Mostly already done** | `IFileHandle` already exposes `GetInfoAsync`/`DisposeAsync` default interface methods (`IFileStore.cs:19-31`) and the server uses the async variants in the CLOSE/hot path. Only **two** sync-`Dispose()` remnants remain: session teardown loop (`Smb2Dispatcher.FileCommands.cs:1503`) and durable-handle expiry (`:1694`). |
| 3 | Only NTLM; no Kerberos/AD | **Misleading** | SPNEGO is fully pluggable (`SpnegoNegotiator.cs`); a real `KerberosServerMechanism` + `KerberosMechanismFactory` exist, plus an LDAP/`System.DirectoryServices` AD backend. **Actually missing:** a *shipped* `IKerberosTicketValidator` (SSPI/GSSAPI binding) — only the interface exists; machine-account/domain-join; and `mechListMIC` is parsed but **not enforced** (SPNEGO downgrade gap). |
| 4 | Persistent Handles + Witness missing | **True (mostly)** | Persistent handles are modeled (`DurableHandle.IsPersistent`, `DurableHandleStore.cs:26`) but the shipped store is **in-memory** (no real persistence); the **Witness protocol is entirely absent**; no CA capability advertised at share level. |
| 5 | OpenTelemetry + hard resource limits missing | **Partly** | No OTel/`ActivitySource`/`Meter` — only custom Interlocked counters + latency histogram (`SmbServerMetrics.cs`, explicitly designed as an OTel bridge). `ConnectionLimiter` (global + per-IP) and quota exist; **missing:** per-session open-handle cap and a memory cap for `QUERY_DIRECTORY` (materializes the whole `IReadOnlyList`). |
| 6 | Security mature; fuzzing/conformance open | **Mature** | `RequireMessageSigning = true`, `RejectUnencryptedAccess = true` defaults (`SmbServerOptions.cs:38-49`); pre-auth integrity (SHA-512) fully implemented (`PreauthIntegrityHash.cs`). **Open:** no fuzz/conformance tests; plus the `mechListMIC` enforcement gap from #3. |

**Takeaways:** #1 is real and the top priority. #2 is nearly closed. #3 is "wired but no batteries" (validator + MIC enforcement), not a missing architecture. #4/#5/#6 are valid gaps on an otherwise high maturity baseline.

---

## Phase A — Throughput: break the per-connection barrier

Goal: metadata ops (CREATE/CLOSE/SET_INFO/QUERY_*) run concurrently with fine-grained locking
instead of the current connection-wide barrier, while preserving SMB2 state-coherence invariants.
This is the fix for the acute delete/metadata-throughput problem. Pure internal refactoring — no
wire-format or public-behavior change.

### A0 — Concurrency invariants + safety net (do first)
- **Write down the invariants** this refactor must preserve, as a doc section here and as xml-doc
  on the new lock type. Non-negotiables:
  - Sequence-window (`MessageId`) validation stays in **arrival order** on the read loop
    (`TryBeginConcurrentFrame` already mutates `SequenceWindowStart` in order — must remain so).
  - Compound/related requests stay sequential (already excluded).
  - Ops touching the **same `Open`** or the **same path** are serialized w.r.t. each other.
  - Session/tree lifecycle (LOGOFF, TREE_DISCONNECT, connection teardown) is a **full barrier**
    — it must still drain all inflight ops before mutating/ tearing down that state.
- **Files:** new `docs` section (this file); no code yet.
- **Tests:** none yet — this milestone is the spec the later tests assert against.

### A1 — Per-key exclusive async lock (utility) ✅ DONE
- `src/Smb.Server/Concurrency/KeyedAsyncLock.cs` — async, non-reentrant, refcount-evicting exclusive
  lock keyed by an opaque token, `ValueTask<Releaser> AcquireAsync(key, ct)`.
- **Note:** this exclusive primitive does **not** preserve arrival order (acquisition races off the
  read loop) and has no shared mode, so it is **not** the dispatch-ordering primitive — it is retained
  for **A3** (guarding per-path state-store mutations, where order is irrelevant). The dispatch path
  uses **A2a** instead. Tests: `tests/Smb.Tests/KeyedAsyncLockTests.cs` (5, green).

### A2a — Ordered keyed reader/writer queue (dispatch-ordering primitive)
Why an RW queue and not the A1 lock: the dispatch path has two hard requirements the A1 lock cannot
meet. (1) **Arrival order per key** — `SET_INFO(delete-on-close)` then `CLOSE` on the same FileId must
not reorder. Order must be fixed on the read loop (arrival order), not at off-loop acquisition. (2)
**Shared vs exclusive** — READ/WRITE run in parallel today (even on the same handle); a concurrent
CLOSE must serialize *after* inflight READ/WRITE of that Open while READs stay parallel among
themselves. That is a reader/writer relation with FIFO fairness (no writer starvation).
- Introduce `src/Smb.Server/Concurrency/KeyedReaderWriterQueue.cs` with a **two-phase** API:
  - `Reservation Reserve(TKey key, LockMode mode)` — called **synchronously on the read loop** in
    arrival order; fixes this frame's FIFO position for `key`.
  - `ValueTask<Releaser> Reservation.AcquireAsync(ct)` — called **off-loop** by the executing task;
    completes when granted per FIFO + RW rules (a run of leading `Shared` reservations is granted as a
    batch; an `Exclusive` reservation is granted alone once it reaches the head).
  - Per-key eviction when the queue drains; cancellation removes a not-yet-granted node and re-pumps.
- **Files:** `src/Smb.Server/Concurrency/KeyedReaderWriterQueue.cs` (new).
- **Tests:** `tests/Smb.Tests/KeyedReaderWriterQueueTests.cs` — leading shared batch runs in parallel;
  exclusive waits for prior shared and runs alone; shared reserved after an exclusive waits for it
  (FIFO, no reordering); writer not starved by a shared stream; cancellation of a queued node unblocks
  the rest; eviction leaves no state.

### A2b — Classify metadata ops as concurrency-eligible & wire the queue ✅ DONE
Gated behind `SmbServerOptions.ConcurrentMetadataOps` (**default off**). Read-loop classifier
(`Smb2Dispatcher.TryClassifyConcurrent`) admits single, non-compound
CREATE/CLOSE/SET_INFO/QUERY_INFO/QUERY_DIRECTORY/FLUSH (plus the existing READ/WRITE) and assigns:
  - READ/WRITE/QUERY_INFO → `Shared`, keyed `OpenScope(fileId)`.
  - CLOSE/SET_INFO/FLUSH/QUERY_DIRECTORY → `Exclusive`, keyed `OpenScope(fileId)`. QUERY_DIRECTORY is
    exclusive because it mutates the open's paging cursor (A3 finding).
  - **CREATE → runs free (no reservation).** *Refinement vs. the original PathScope plan:* a CREATE's
    FileId does not exist yet, so no other frame can reference the Open it produces, and every store it
    touches is atomic (A3) — so serializing CREATEs by path buys nothing. The natural request/response
    dependency (a client can't send an op on a FileId it hasn't been given) means per-Open ops always
    arrive after their CREATE is client-observably complete, so no CREATE↔per-Open ordering is needed.
- **Ordering is fixed on the read loop, not at acquisition.** `TryBeginConcurrentFrame` only classifies +
  consumes the sequence window; the host takes the reservation via `ReserveScope` **after** its `_ioGate`
  (still on the serial read loop, so arrival order holds) — this also means a gate-cancelled frame never
  orphans a reservation. The executing task `AcquireAsync`es before `DispatchOneAsync` and releases via
  `using` (success or error). FileId for the scope key is read on the read loop by `TryReadFileId`
  (reuses validated parsers; no-copy direct read for READ/WRITE/FLUSH). Lifecycle
  (LOGOFF/TREE_DISCONNECT/SESSION_SETUP/NEGOTIATE/CANCEL) and compound stay **barrier** ops.
- **Files:** `src/Smb.Server/Smb2Dispatcher.Concurrency.cs` (rewritten), `src/Smb.Host/SmbConnectionHandler.cs`
  (`ReserveScope` after gate; pass `ct` to `ExecutePreparedFrameAsync`), `src/Smb.Server/SmbServerOptions.cs`.
- **Tests:** `tests/Smb.Tests/ConcurrentMetadataDispatchTests.cs` (6, green) — classifier accepts metadata
  ops with the feature on / rejects with it off / lifecycle stays barrier; **CLOSE waits for an inflight
  WRITE on the same Open**; a metadata op on a different Open is not blocked; a concurrent CLOSE really
  removes the Open (follow-up CLOSE → FILE_CLOSED); end-to-end CREATE→QUERY_INFO→CLOSE over the real host
  loop (TCP) with the feature on. Full suite **489/489 green** (feature off = zero behavior change).

### A3 — Make state stores safe for concurrent metadata ops ✅ DONE (audit + hardening test)
**Audit result — the shared stores were already concurrency-safe:**
- `SmbSession.Opens` / `TreeConnects` / `Channels` are `ConcurrentDictionary` (`SmbSession.cs:61-70`).
- `InMemoryShareModeManager`, `InMemoryLockManager`, `InMemoryLeaseManager`, `InMemoryOplockManager`
  each guard their internal `Dictionary`/`List`/`HashSet` with a single `lock (_gate)` around the whole
  check-then-act — atomic.
- `InMemoryDurableHandleStore` is `ConcurrentDictionary`-based; `TryClaim` = atomic `TryRemove`.
- All server/connection IDs (`Session`/`Persistent`/`Tree`/`File`/`Async`) are allocated via
  `Interlocked.Increment` — no torn IDs under parallel CREATE.
- The CREATE flow rolls the share-mode reservation back on every failure branch (backend error, DACL
  deny, delete-on-close deny), so a losing concurrent CREATE leaves no orphan reservation.

**The one genuinely new concern is per-`SmbOpen` mutable field ownership**, not the shared stores:
`SmbOpen.DirectoryListing`/`DirectoryCursor` (QUERY_DIRECTORY paging) and `ResumeKey` are mutated by
the op holding the open. The A2b keying model protects them: same-Open exclusive ops serialize, and
QUERY_DIRECTORY is therefore classified **Exclusive** (not Shared) — see A2b. READ/WRITE staying
`Shared` is safe because SMB2 READ/WRITE carry explicit offsets (no shared cursor on the open).

**Observation (not fixed — out of scope):** `SmbTreeConnect.OpenCount` is incremented (Interlocked) at
both CREATE sites but never decremented and never read anywhere — dead write-only state, no race.

- **Files:** audit only; no store changes needed.
- **Tests:** `tests/Smb.Tests/ShareModeManagerConcurrencyTests.cs` (2, green) — 8 threads × 20k
  exclusive open attempts never observe two concurrent holders (atomic check-then-insert); compatible
  shares all coexist then drain clean. The full dispatch-level parallel open/close stress test is
  deferred to **A2b** (needs the concurrent path wired).

### A4 — Close the async contract (small, from review #2)
- Convert the two remaining sync `Dispose()` teardown sites to `DisposeAsync()`
  (`Smb2Dispatcher.FileCommands.cs:1503`, `:1694`).
- Mark `IFileHandle.Dispose()` and `IFileHandle.GetInfo()` `[Obsolete]` with a message pointing to
  the async variants (do **not** remove — sync backends via `SyncFileStore` still implement them).
- **Files:** `src/Smb.FileSystem/IFileStore.cs`, `src/Smb.Server/Smb2Dispatcher.FileCommands.cs`.
- **Tests:** existing suite must stay green; add an assertion that session teardown awaits
  `DisposeAsync` on a backend whose `Dispose()` throws (proving the async path is taken).

### A5 — Benchmark / regression guard
- A metadata-heavy micro-benchmark (many CREATE+CLOSE+QUERY on one connection) proving overlap vs.
  the old serial baseline; keep it as a non-gating perf test.
- **Files:** `tests/Smb.Tests/MetadataThroughputBenchmark.cs` (or a `benchmarks/` project).

---

## Phase B — Enterprise auth (Kerberos turnkey + downgrade protection)

### B1 — Shipped Kerberos ticket validator
- Provide a real `IKerberosTicketValidator`: Windows SSPI (`AcceptSecurityContext`) binding in a new
  `Smb.Auth.Sspi` project; optionally a keytab/GSSAPI path for Linux. Wire machine-account/keytab
  config into `SmbServerBuilder`.
- **Files:** `src/Smb.Auth.Sspi/` (new project), `src/Smb.Host/SmbServerBuilder.cs`.
- **Tests:** `tests/Smb.Tests/KerberosSspiTests.cs` (may need to be integration/optional if it
  requires a domain); unit-test the token unwrap/AP-REP path with a faked validator (already partly
  covered in `Phase2AuthTests`).

### B2 — Enforce `mechListMIC` (SPNEGO downgrade protection)
- Verify the SPNEGO `mechListMIC` in `SpnegoNegotiator` once a mechanism completes, per RFC 4178 —
  currently parsed but ignored.
- **Files:** `src/Smb.Auth/SpnegoNegotiator.cs`, `src/Smb.Auth/Oids/SpnegoTokens.cs`.
- **Tests:** `tests/Smb.Tests/SpnegoTests.cs` — a tampered mechList is rejected; valid MIC passes.

---

## Phase C — High availability (market-dependent)

### C1 — SMB Witness protocol (MS-SWN)
- Async failover notifications; witness registration RPC endpoint; CA capability
  (`SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY`) advertised at share level.
- **Files:** `src/Smb.Server/Witness/` (new), `src/Smb.Server/Rpc/*`, share-capability plumbing.
- **Tests:** witness register/notify unit tests; CA capability negotiation test.

### C2 — Durable persistent-handle store
- A real persistent `IDurableHandleStore` (disk/external) so `IsPersistent` handles survive a full
  server restart, replacing the in-memory default.
- **Files:** `src/Smb.Server/Durable/` (new impl), builder wiring.
- **Tests:** persist → simulate restart → reclaim handle.

---

## Phase D — Operations & hardening (continuous)

### D1 — OpenTelemetry bridge
- `ActivitySource` traces per op + `Meter` histograms (latency/op) fed from the existing
  `SmbServerMetrics` hook points. Keep it optional (no hard OTel dependency in core).
- **Files:** new `Smb.Server.OpenTelemetry` project, hook points in `SmbServerMetrics`.

### D2 — Resource limits
- Per-session open-handle cap (reject with `STATUS_INSUFFICIENT_RESOURCES`); streaming/cap for
  `QUERY_DIRECTORY` so a huge directory can't be materialized unbounded.
- **Files:** `src/Smb.Server/SmbServerOptions.cs`, `Smb2Dispatcher.FileCommands.cs`, `IFileStore`.

### D3 — Fuzzing + conformance
- Fuzz the wire parser (`Smb.Protocol` readers) with a coverage-guided harness; a conformance suite
  driven by real Windows clients.
- **Files:** `tests/Smb.Fuzz/` (new), conformance harness.

---

## Status Journal

- **2026-07-14** — Roadmap created. Review verified (table above). Agreed order: **A first**, then
  B, then C/D by target market. Detail level: milestone plan with files/tests.
  Next action: begin **A0** (write invariants) → **A1** (`KeyedAsyncLock`).
- **2026-07-14** — **A0 done** (invariants written in the Phase A section). **A1 done**:
  `src/Smb.Server/Concurrency/KeyedAsyncLock.cs` — async, non-reentrant, refcount-evicting keyed lock;
  `Release` drops the semaphore count before evicting so the entry can't be disposed under a holder;
  cancellation drops the reference without touching the count. Tests
  `tests/Smb.Tests/KeyedAsyncLockTests.cs` (5, all green): same-key serialization, cross-key
  parallelism, eviction after last release, drain-leaves-no-state, cancellation reuse.
  <!-- NOTE: Entry had to be `internal` (not private) — a public Releaser's internal ctor may not
       take a less-accessible param (CS0051). -->
  Next action: **A2** — classify single non-compound CREATE/CLOSE/SET_INFO/QUERY_*/FLUSH as
  concurrency-eligible and guard them with `KeyedAsyncLock` (OpenScope(fileId) / PathScope(treeId,path))
  instead of the barrier. First define the key type + which command maps to which scope.
- **2026-07-14** — **Design refinement while starting A2.** The A1 exclusive `KeyedAsyncLock` is the
  wrong primitive for the dispatch path: (a) its acquisition races off the read loop so it does NOT
  preserve arrival order, and (b) it has no shared mode, so a concurrent CLOSE couldn't let same-Open
  READs stay parallel. Split A2 into **A2a** (ordered RW primitive) + **A2b** (wiring). A1 is retained
  for A3 state-store guarding (order-agnostic per-path mutations).
  **A2a done:** `src/Smb.Server/Concurrency/KeyedReaderWriterQueue.cs` — two-phase (`Reserve` on the
  read loop fixes FIFO position; `Reservation.AcquireAsync` off-loop grants per FIFO+RW rules), leading
  shared batched, exclusive alone, strict FIFO (no writer starvation), cancellation removes a queued
  node + re-pumps, per-key eviction. Tcs uses `RunContinuationsAsynchronously` (grant happens under the
  gate). Tests `tests/Smb.Tests/KeyedReaderWriterQueueTests.cs` (7, green). Full suite **481/481 green**
  (nothing wired yet — primitives only).
  <!-- NOTE A2b is the invasive step and depends on A3: once CLOSE/SET_INFO leave the barrier the state
       stores (SmbSession.Opens etc.) are mutated off the read loop and must be made concurrency-safe
       FIRST, and the metadata-concurrency must ship behind a default-off option for rollback. -->
  Next action: **A3** (make state stores concurrency-safe) — audit `SmbSession.Opens` &
  managers — then **A2b** (read-loop classifier + `Reserve`/`AcquireAsync` wiring, option-gated).
- **2026-07-14** — **A3 done (audit + hardening test).** Finding: the shared stores are already
  concurrency-safe (ConcurrentDictionary open-tables, `lock`-guarded managers, Interlocked IDs, CREATE
  rolls back share-mode on every failure branch) — no store changes required. The real new concern is
  per-`SmbOpen` mutable-field ownership (`DirectoryListing`/`DirectoryCursor`), which drove an **A2b
  classification fix**: QUERY_DIRECTORY is **Exclusive** on `OpenScope` (not Shared), else two scans on
  one directory open corrupt the paging cursor. Added `tests/Smb.Tests/ShareModeManagerConcurrencyTests.cs`
  (2, green) locking in the atomic check-then-insert. Noted dead write-only `SmbTreeConnect.OpenCount`
  (never read/decremented — not a race, left as-is).
  Next action: **A2b** — the invasive wiring. Steps: (1) add default-off option
  `SmbServerOptions.ConcurrentMetadataOps`; (2) read-loop classifier computes `(scope, mode)` per
  eligible frame and calls `Reserve` in arrival order; (3) executing task `AcquireAsync`es before
  `DispatchOneAsync`; (4) lifecycle/compound stay barrier; (5) `ConcurrentMetadataDispatchTests`
  incl. the deferred parallel open/close stress test + SET_INFO→CLOSE ordering + CLOSE-waits-for-WRITE.
- **2026-07-14** — **A2b DONE — the metadata-throughput fix is functional** (behind default-off
  `ConcurrentMetadataOps`). Wiring: `TryBeginConcurrentFrame` classifies + consumes the seq window;
  host takes the per-Open reservation via new `ReserveScope` **after** the `_ioGate` (avoids orphaning a
  reservation on gate-cancel); `ExecutePreparedFrameAsync` acquires (FIFO shared/exclusive) then
  dispatches, releasing via `using`. **Design refinement:** CREATE runs **free** (no PathScope) — its
  FileId doesn't exist yet + atomic stores + request/response FileId dependency make per-Open ordering
  automatic; documented in A2b. FileId scope key read on the read loop by `TryReadFileId` (reuses the
  validated parsers; no-copy for READ/WRITE/FLUSH — offsets cross-checked against `TestHelpers` builders).
  Tests: `ConcurrentMetadataDispatchTests` (6, incl. CLOSE-waits-for-WRITE and an end-to-end TCP run).
  **Suite 489/489 green; feature off = byte-identical behavior** (existing 483 unchanged).
  <!-- NOTE consumers enable it via SmbServerBuilder.Configure(o => o.ConcurrentMetadataOps = true);
       requires MaxConcurrentFileOpsPerConnection > 1 (the concurrent path). -->
  Next action: **A4** (mark `IFileHandle.Dispose()`/`GetInfo()` `[Obsolete]`; the 2 sync teardown
  Dispose() sites were already converted earlier) then **A5** (metadata-throughput micro-benchmark).
- _(append progress entries here as milestones complete; check items off in the phase sections)_
