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

### A1 — Per-key async lock manager
- Introduce `Smb.Server/Concurrency/KeyedAsyncLock.cs` — an async, reentrancy-free, fairness-aware
  lock keyed by an opaque token, with `ValueTask<Releaser> AcquireAsync(key, ct)`. Backed by a
  `ConcurrentDictionary<key, SemaphoreSlim>` with refcounted eviction so idle keys don't leak.
- Keys: `OpenScope(fileId)` for per-open ops; `PathScope(treeId, normalizedPath)` for
  create/rename/delete-on-close that race on a name.
- **Files:** `src/Smb.Server/Concurrency/KeyedAsyncLock.cs` (new).
- **Tests:** `tests/Smb.Tests/KeyedAsyncLockTests.cs` — mutual exclusion per key, parallelism across
  keys, no deadlock under contention, key eviction after last release, cancellation.

### A2 — Classify metadata ops as concurrency-eligible
- Extend `TryBeginConcurrentFrame` (or add a sibling classifier) so single, non-compound
  CREATE/CLOSE/SET_INFO/QUERY_INFO/QUERY_DIRECTORY/FLUSH become eligible for the concurrent path,
  guarded by the appropriate keyed lock instead of the barrier.
- Lifecycle commands (LOGOFF, TREE_DISCONNECT, SESSION_SETUP, NEGOTIATE) and compound requests
  remain barrier ops.
- **Files:** `src/Smb.Server/Smb2Dispatcher.Concurrency.cs`, `src/Smb.Host/SmbConnectionHandler.cs`.
- **Tests:** `tests/Smb.Tests/ConcurrentMetadataDispatchTests.cs` — parallel CREATE/CLOSE on
  distinct paths overlap; two ops on the same FileId serialize; a LOGOFF drains inflight metadata
  ops before tearing down the session.

### A3 — Make state stores safe for concurrent metadata ops
- Audit `SmbSession.Opens`, `SmbTreeConnect`, `DurableHandleStore`, `InMemoryShareModeManager`,
  `InMemoryLockManager`, `InMemoryLeaseManager`, `InMemoryOplockManager` for races once the barrier
  is gone. Convert plain `Dictionary`/`List` open-tables to concurrent/guarded structures where a
  metadata op now mutates them off the read loop.
- **Files:** `src/Smb.Server/State/*.cs`, `src/Smb.Server/Sharing/*`, `src/Smb.Server/Durable/*`.
- **Tests:** stress test in `ConcurrentMetadataDispatchTests` — N parallel opens/closes on one
  session, assert `Opens` count consistency and no lost/duplicate FileIds.

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
- _(append progress entries here as milestones complete; check items off in the phase sections)_
