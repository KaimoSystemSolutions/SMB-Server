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

### A4 — Close the async contract (review #2) ✅ DONE (scoped)
- **Primary teardown path is now async:** the connection-close path releases backend handles via
  `IFileHandle.DisposeAsync` (`Smb2Dispatcher.OnConnectionClosedAsync`, called by the host), so an async
  backend no longer sync-over-async-blocks a pool thread on disconnect. Implemented with a **detach/dispose
  split** (`DetachSessionOpens` returns handles; sync vs async caller chooses disposal) so there is no
  duplicated release logic and **no public-API break / no test churn** (sync `OnConnectionClosed` kept for
  the periodic idle-sweep, LOGOFF and back-compat/tests).
- **`[Obsolete]` deliberately NOT applied** (scope decision): `IFileHandle.Dispose()` comes from
  `IDisposable` (can't be marked); marking `GetInfo()` obsolete would flag the `GetInfoAsync` default-method
  bridge and every sync backend that legitimately implements it (with `TreatWarningsAsErrors`, that breaks
  the build) — and sync backends *must* implement these, so "obsolete" is the wrong signal. The XML-doc
  already states the async-first contract. The durable-scavenger's sync `Dispose` (`ReleaseDurable`) is
  intentionally left sync — a rare, host-driven periodic sweep with a sync public signature.
- **Files:** `src/Smb.Server/Smb2Dispatcher.FileCommands.cs`, `src/Smb.Host/SmbConnectionHandler.cs`.
- **Tests:** `tests/Smb.Tests/AsyncTeardownTests.cs` (2, green) — a recording handle proves the async close
  path calls `DisposeAsync` (not `Dispose`), and the sync path calls `Dispose`.

### A5 — Benchmark / regression guard ✅ DONE
- Metadata-throughput micro-benchmark: against a backend with per-op latency, a batch of `n` independent
  CREATEs overlaps with the feature on but serializes on the barrier with it off. Relative assertion
  (same machine/delay, factor-3 margin) so it is non-flaky across CI hardware.
- **Files:** `tests/Smb.Tests/ConcurrentMetadataDispatchTests.cs` →
  `ConcurrentMetadata_OverlapsLatency_FasterThanSerialBaseline` (`[Trait("Category","Performance")]`).

---

## Phase B — Enterprise auth (Kerberos turnkey + downgrade protection)

### B1 — Shipped Kerberos ticket validator ✅ DONE (Windows SSPI)
- New project `src/Smb.Auth.Sspi/` (references `Smb.Auth` only — no Host coupling). `SspiKerberosTicketValidator`
  acquires an inbound server credential (`AcquireCredentialsHandle`, Kerberos/Negotiate package) once, then per
  AP-REQ: re-wraps the bare AP-REQ into a GSS mech token (`KerberosGssToken.WrapApReq`, since the mechanism strips
  the wrapper), calls `AcceptSecurityContext`, and on success extracts the ticket **session key**
  (`SECPKG_ATTR_SESSION_KEY` — the SMB signing/encryption KDK, which `NegotiateAuthentication` does NOT expose, so
  raw SSPI is required) and the identity (SID + group SIDs + UPN via the context access token / `WindowsIdentity`).
  P/Invoke isolated in `SspiNative.cs`; Windows-guarded (`[SupportedOSPlatform("windows")]` + runtime check);
  credential freed on `Dispose`.
- **Wiring:** plugs into the existing `KerberosMechanismFactory` + `SmbServerBuilder.UseAuthentication(...)`; ergonomic
  `SspiKerberos.CreateNegotiator(validator, ntlmFallback)` composes a Kerberos-preferred SPNEGO negotiator. (No new
  Host API — keeps Host free of the Windows-only dependency.)
- **Known limitation (v1):** mutual-auth `AP-REP` not surfaced (`ApRep = null`, contract-permitted); requires a
  domain-joined host owning the SMB SPN. **The Kerberos happy path (real ticket → session-key/PAC) is NOT CI-testable
  here (no domain) — verify manually against a real client.**
- **Files:** `src/Smb.Auth.Sspi/{SspiKerberosTicketValidator,SspiNative,SspiKerberos}.cs`, `Smb.Server.slnx`,
  `tests/Smb.Tests/Smb.Tests.csproj` (project ref).
- **Tests:** `tests/Smb.Tests/SspiKerberosTests.cs` — composition (Kerberos-first, cross-platform), platform guard
  (non-Windows ctor throws), and the **P/Invoke round-trip on Windows** (bogus/empty AP-REQ → rejected, no crash;
  exercises marshaling + error mapping + handle lifetime). Happy path documented as manual-verify.

### B2 — Enforce `mechListMIC` (SPNEGO downgrade protection) ✅ DONE (NTLM, opt-in)
- `SpnegoNegotiator.RequireMechListMic` (default **off** for compat) verifies the SPNEGO `mechListMIC`
  (RFC 4178 §5) once the selected mechanism succeeds. The parser now captures the `MechTypeList` **as
  received** (`SpnegoParseResult.MechListBytes` — the inner `SEQUENCE OF MechType` TLV, no `[0]` wrapper),
  so the MIC is checked against on-wire bytes and a mechanism **stripped in transit** (the O8 Kerberos→NTLM
  fallback downgrade) produces a byte-level mismatch → `AccessDenied`. Required-but-absent MIC is also
  rejected. Constant-time compare.
- **Scope:** enforced for the **NTLM** mechanism (the O8 case), whose GSS_getMIC this layer can compute
  from the negotiated session key. Implementing that required the NTLMSSP first-message signature
  (MS-NLMP §3.4.4/§3.4.5): `NtlmCryptography.NtlmMechListMic` (+ `NtlmSignKey`/`NtlmSealKey`) — extended
  session security + KEY_EXCH + 128-bit (this stack's fixed NTLMv2 flags), SeqNum 0 only (fresh RC4 handle).
  A Kerberos context's integrity is validated inside its GSS provider (B1/SSPI), not here.
- **Files (wider than the original plan — the MIC needs mechanism crypto, per O8):**
  `src/Smb.Crypto/NtlmCryptography.cs` (GSS_getMIC + sign/seal keys), `src/Smb.Auth/Oids/SpnegoTokens.cs`
  (surface `MechListBytes` + `EncodeMechList`), `src/Smb.Auth/SpnegoNegotiator.cs` (`RequireMechListMic` +
  verify on success).
- **Tests:** `tests/Smb.Tests/SpnegoTests.cs` (+6, green) — valid MIC accepted; stripped mechanism rejected;
  missing MIC rejected when enforced / accepted when not (compat); tampered MIC rejected; parser captures
  `MechListBytes` byte-identical to `EncodeMechList`.

---

## Phase C — High availability (market-dependent)

### C1 — SMB Witness protocol (MS-SWN)
Async failover notifications; witness registration RPC endpoint; CA capability
(`SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY`) advertised at share level. Broken into sub-milestones
(the async-notify delivery, C1.3, is the one hard, risky step — everything else is additive).

**Reusable substrate discovered up front (grounds the plan):** the existing DCERPC pipe stack
(`Rpc/{Dcerpc,NdrWriter,RpcPipe,SrvsvcEndpoint}.cs`, dispatched via `SmbOpen.Pipe` on IPC$) handles
BIND/REQUEST synchronously. The **CHANGE_NOTIFY** handler (`Smb2Dispatcher.Notification.cs`) already
implements the exact deferred-response pattern C1.3 needs: `InterimResponse` (STATUS_PENDING) →
`PendingAsyncRequest` → `SendAsyncFinalAsync`/`SendOutOfBandAsync`, guarded by `NotifyOnce`. C1.3
reuses that template but completes with an IOCTL (FSCTL_PIPE_TRANSCEIVE) async final carrying the
`RESP_ASYNC_NOTIFY` PDU, rather than a native CHANGE_NOTIFY body.

#### C1.0 — CA capability at share level ✅ DONE
- TREE_CONNECT advertises `ShareCapabilities.ContinuousAvailability` when `share.ContinuousAvailability`
  **and** the connection is SMB3+ (`Dialect.IsSmb3OrLater()`) — never claim CA on a dialect that cannot
  honour the persistent-handle/witness contract. `IShare.ContinuousAvailability` + `Share` impl already
  existed; only the advertise path was missing.
- **Files:** `src/Smb.Server/Smb2Dispatcher.cs` (`HandleTreeConnect`).
- **Tests:** `tests/Smb.Tests/DurableHandleTests.cs` →
  `TreeConnect_ContinuousAvailabilityShare_AdvertisesCaCapability` (reuses the existing `CA` share +
  harness): CA share sets the bit, plain `Files` share does not. 10/10 green.

#### C1.1 — NDR reader + witness wire types ✅ DONE
- Add an NDR **reader** (only `NdrWriter` exists today): conformant/varying NUL-terminated wide strings,
  unique-pointer referents, 4-byte scalars, alignment — enough to parse `WitnessrRegister(Ex)` args.
- Witness constants/enums/structs: interface UUID `ccd8c074-d0e5-4a40-92b4-d074faa6ba28` v1.1, opnums
  (0 GetInterfaceList, 1 Register, 2 UnRegister, 3 AsyncNotify, 4 RegisterEx), notification/version/state
  enums, `WITNESS_INTERFACE_LIST`, `RESP_ASYNC_NOTIFY`, `RESOURCE_CHANGE`/move payloads.
- **Files:** `src/Smb.Server/Rpc/NdrReader.cs` (new), `src/Smb.Server/Witness/WitnessWire.cs` (new).
- **Tests:** NDR round-trip (writer→reader) for strings/scalars/referents; struct encode goldens.

#### C1.2 — Witness RPC endpoint (synchronous ops) ✅ DONE
- `WitnessEndpoint : IRpcEndpoint` bound at `\PIPE\witness`; accept the witness interface UUID in BIND;
  wire `\PIPE\witness` into `HandlePipeCreate`. Implement `WitnessrGetInterfaceList`,
  `WitnessrRegister`/`WitnessrRegisterEx` (allocate a 20-byte RPC context handle), `WitnessrUnRegister`.
- `WitnessRegistrationStore` (context-handle → registration; per-connection lifetime).
- **Files:** `src/Smb.Server/Witness/{WitnessEndpoint,WitnessRegistrationStore}.cs`,
  `src/Smb.Server/Smb2Dispatcher.FileCommands.cs` (pipe-name dispatch), `Rpc/Dcerpc.cs` if BIND needs the UUID.
- **Tests:** GetInterfaceList decodes; Register→handle→UnRegister; bad handle → error.

#### C1.3 — Async notification delivery (WitnessrAsyncNotify) — the hard step ✅ DONE
- Async-capable endpoint contract (endpoint may say "defer"); IOCTL handler returns `InterimResponse`
  and registers a `PendingAsyncRequest`; on a queued notification (or timeout/unregister) completes via
  `SendAsyncFinalAsync` with an IOCTL response carrying the `RESP_ASYNC_NOTIFY` stub. Per-registration
  async notification channel; `NotifyOnce`-style one-shot.
- **Files:** `Rpc/RpcPipe.cs` (async contract), `Smb2Dispatcher.FileCommands.cs` (IOCTL defer),
  `src/Smb.Server/Witness/WitnessNotificationChannel.cs` (new).
- **Tests:** AsyncNotify pends; a pushed notification completes it out-of-band; unregister/teardown cancels.

#### C1.4 — Server-side trigger + public API ✅ DONE
- `IWitnessService` hook so the host signals RESOURCE_CHANGE / CLIENT_MOVE; builder wiring; lifecycle
  cleanup (drop registrations on connection/session teardown).
- **Files:** `src/Smb.Server/Witness/IWitnessService.cs`, `Smb.Host/SmbServerBuilder.cs`, teardown paths.
- **Tests:** trigger → registered client's pending AsyncNotify fires with the right MessageType.

#### C1.5 — End-to-end + journal ✅ DONE (folded into C1.3/C1.4)
- The full register → async-notify → **public trigger** → out-of-band final flow is exercised end-to-end by
  `WitnessAsyncNotifyTests` (which drives the real dispatcher IOCTL path and completes via
  `WitnessRegistrationStore.NotifyResourceChange`); CA negotiation is covered by C1.0. Journal updated below.

### C2 — Durable persistent-handle store ✅ DONE
- `FileDurableHandleStore : IDurableHandleStore, IPersistentHandleStore` persists **persistent (CA) handle
  metadata** (`PersistentHandleRecord`: FileId, owner key, create GUID, share, path, granted+share access) as
  one atomic JSON file per FileId under a directory; warm (in-process) durable behavior is identical to the
  in-memory store. On startup the directory is scanned into a **cold** table.
- **Rehydration on reconnect (the hard part):** the record is written at CREATE (survives even a crash before a
  graceful disconnect). `TryClaimForReconnect` became **async** and tries the warm table first, then — for a
  persistent handle after a restart — claims the cold record, validates owner/create-GUID against the record
  metadata, and `RehydrateColdRecordAsync` rebuilds a **live `SmbOpen`**: re-opens the backend
  (`IFileStore.CreateAsync`, Open disposition) on the reconnect share and re-reserves the share mode. The
  dispatcher then resumes I/O on it via the existing `RestoreDurableOpenAsync`.
- **Lifecycle:** record removed on CLOSE (`RemovePersisted`); `TakeAll` (shutdown) leaves records on disk;
  cold record is **retained** on claim so it survives a *subsequent* restart; `SmbServerState` seeds the
  persistent-id counter from `HighestPersistentId` so a fresh allocation can't collide with a rehydrated id.
  New `SmbOpen.ShareAccess` field (so the share mode can be re-reserved).
- **Scope (v1, documented):** only reconnectable metadata is persisted — byte-range locks/oplocks/leases are
  **not** reconstructed (a rehydrated handle resumes READ/WRITE but holds no lock/lease until re-acquired).
- **Files:** `src/Smb.Server/Durable/{PersistentHandleStore,FileDurableHandleStore}.cs` (new),
  `Smb2Dispatcher.FileCommands.cs` (persist@CREATE, remove@CLOSE, async claim + rehydrate),
  `State/{SmbOpen,SmbServerState}.cs`, `Smb.Host/SmbServerBuilder.cs`
  (`UseDurableHandleStore` / `UsePersistentDurableHandles(dir)`).
- **Tests:** `tests/Smb.Tests/PersistentHandleRestartTests.cs` (4) — end-to-end persistent open → **restart**
  (fresh store+dispatcher, same dir+backend) → reconnect → **read returns content**; wrong create-GUID rejected
  + record kept; store persist/reload/claim-retains-on-disk/remove; corrupt record skipped on load.

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
- **2026-07-14** — **A4 + A5 DONE → PHASE A COMPLETE.** Correction to the prior note: the sync teardown
  `Dispose()` sites were NOT already converted. A4 done scoped: connection-close path made async
  (`OnConnectionClosedAsync` via a detach/dispose split — no public-API break, no test churn); `[Obsolete]`
  deliberately skipped (infeasible on `IDisposable.Dispose`; wrong signal for `GetInfo()` which sync
  backends must implement + would break the `GetInfoAsync` DIM bridge under `TreatWarningsAsErrors`);
  durable-scavenger sync `Dispose` left as-is (rare periodic sweep). `AsyncTeardownTests` (2) prove the
  async path uses `DisposeAsync`. A5: `ConcurrentMetadata_OverlapsLatency_FasterThanSerialBaseline`
  benchmark (factor-3 relative margin). **Full suite 492/492 green.**
  **Phase A (A0–A5) is complete.** Headline result: metadata/delete throughput bottleneck fixed
  (`ConcurrentMetadataOps`, default off) + async teardown; all inert/off by default = zero behavior change
  until opted in.
  Next action: **Phase B** — B1 shipped Kerberos `IKerberosTicketValidator` (SSPI/GSSAPI), B2 enforce
  SPNEGO `mechListMIC`. (Or C/D per target market — user's call.)
- **2026-07-14** — **B1 DONE (Windows SSPI Kerberos).** New optional project `Smb.Auth.Sspi`
  (`SspiKerberosTicketValidator` + `SspiNative` P/Invoke + `SspiKerberos.CreateNegotiator`). Plugs into the
  existing `KerberosMechanismFactory`/`UseAuthentication`; no Host coupling. Extracts the ticket session key
  via `SECPKG_ATTR_SESSION_KEY` (required for SMB signing — `NegotiateAuthentication` can't expose it) + identity
  from the access token. AP-REP mutual-auth deliberately `null` in v1 (contract-permitted, avoids an untestable
  strip path). Builds 0/0 on Windows. Tests `SspiKerberosTests` (composition + platform guard cross-platform;
  Windows P/Invoke round-trip rejecting a bogus AP-REQ). **Happy path (real ticket→session-key/PAC) needs a
  domain — NOT CI-testable here; manual-verify.**
  <!-- NOTE the classifier/model outage during this session blocked the final test RUN from being confirmed by
       me; the SSPI project itself built clean (0/0). Re-run `dotnet test --filter SspiKerberosTests` to confirm. -->
  Next action: **B2** — enforce SPNEGO `mechListMIC` in `SpnegoNegotiator` (downgrade protection; currently
  parsed but ignored). Then B (done) → C/D per target market.
- **2026-07-14** — **B1 test run CONFIRMED + B2 DONE.** Resumed per the prior note that B1's final test
  run was never confirmed (classifier outage). Ran `SspiKerberosTests` → **4/4 green** (composition,
  platform guard, Windows P/Invoke round-trip); B1's real-ticket happy path remains manual-verify (no
  domain). **B2 implemented** behind opt-in `SpnegoNegotiator.RequireMechListMic` (default off): parser
  captures the on-wire `MechTypeList` (`MechListBytes`), and on mechanism success the NTLM `mechListMIC`
  is recomputed (NTLMSSP GSS_getMIC, MS-NLMP §3.4.4/§3.4.5 — new `NtlmCryptography.NtlmMechListMic`) over
  the received list and compared constant-time; strip/absent/tamper → `AccessDenied`. **Deviation from the
  plan's file list:** the O8 finding requires the NTLMSSP per-message signature, so `Smb.Crypto` (the MIC
  primitive) was also touched — unavoidable, documented in the B2 section. Kerberos MIC left to the SSPI
  GSS layer (out of this layer's scope). Tests: `SpnegoTests` +6 green. **Full suite 502/502 green**
  (492 baseline + 4 B1 + 6 B2); feature off = unchanged behavior.
  <!-- NOTE NtlmMechListMic supports SeqNum 0 only (fresh RC4 handle) — correct for mechListMIC, which is
       always the first GSS_getMIC on the context. Do not reuse it for multi-message signing. -->
  Next action: **Phase B complete.** Proceed to **C** (Witness / durable store) or **D** (OTel / resource
  limits / fuzzing) per target market — user's call. Manual-verify B1 + B2 against a real Windows client
  when a domain-joined host is available.
- **2026-07-14** — **Phase B confirmed complete; started C1 (Witness) per user's call.** Broke C1 into
  sub-milestones C1.0–C1.5 (see the C1 section) after reading the RPC substrate: the DCERPC pipe stack
  (`Rpc/*`, `SmbOpen.Pipe`) is synchronous, and CHANGE_NOTIFY (`Smb2Dispatcher.Notification.cs`) already
  provides the deferred-async-response template C1.3 will reuse. **C1.0 DONE:** TREE_CONNECT now advertises
  `SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY` for `ContinuousAvailability` shares on SMB3+ connections
  (`HandleTreeConnect`). Test `TreeConnect_ContinuousAvailabilityShare_AdvertisesCaCapability` added to
  `DurableHandleTests` (reuses the existing `CA` share) — CA share sets the bit, plain share doesn't;
  DurableHandleTests 10/10 green. (Pre-existing unrelated `SspiKerberosTests` CA1416 warning noted, not new.)
  Next action: **C1.1** — new `Rpc/NdrReader.cs` + `Witness/WitnessWire.cs` (witness UUID/opnums/structs).
- **2026-07-14** — **C1.1 DONE.** `Rpc/NdrReader.cs` (LE NDR decoder: scalars, referents, conformant+varying
  wide strings, fixed WCHAR arrays, raw bytes; truncation → `SmbWireFormatException`) + `NdrWriter` extended
  with `UInt16`/`Bytes`/`FixedWideString`. `Witness/WitnessWire.cs`: opnums, versions (V1 0x00010001 /
  V2 0x00020000), node states, interface/notify/resource-change enums, interface UUID in DCE wire order, and
  encode (`EncodeInterfaceList`, `EncodeAsyncNotifyResponse`, `EncodeResourceChange`) + parse
  (`ParseRegister`, `ParseRegisterEx` — top-level unique-string pointers: referent immediately followed by its
  string). Tests `WitnessWireTests` (7, green): NDR round-trip, truncation throw, register/registerEx parse,
  null-pointer arg, interface-list field-by-field decode, async-notify+resource-change round-trip.
  Next action: **C1.2** — `WitnessEndpoint : IRpcEndpoint` at `\PIPE\witness` (BIND UUID, opnum dispatch,
  GetInterfaceList/Register/UnRegister, context handles) + `WitnessRegistrationStore`; wire `\PIPE\witness`
  into `HandlePipeCreate`.
- **2026-07-14** — **C1.2 DONE.** `Witness/WitnessEndpoint.cs` (IRpcEndpoint at `\PIPE\witness`: BIND ack,
  opnum dispatch for GetInterfaceList/Register/RegisterEx/UnRegister; version + NetName validation returning
  Win32 codes; 20-byte context handle = attrs(4)+UUID(16)) + `Witness/WitnessRegistrationStore.cs`
  (context-handle-keyed, connection-scoped, `Snapshot`/`RemoveAllForConnection` for the C1.4 trigger/teardown).
  Store hung on `SmbServerState.WitnessRegistrations` (server-global). `HandlePipeCreate` refactored to a
  pipe-name→endpoint resolver (`OpenRpcEndpoint`) that now also serves `witness`; srvsvc behavior byte-identical.
  **AsyncNotify (opnum 3) faults for now** — C1.3 serves it out-of-band. Tests `WitnessEndpointTests` (6, green):
  BIND ack; GetInterfaceList decodes self-interface; Register→handle→store→UnRegister→drop; bad version →
  REVISION_MISMATCH + null handle; unknown UnRegister handle → INVALID_PARAMETER; sync AsyncNotify faults.
  **Full suite 516/516 green** (502 + 1 C1.0 + 7 C1.1 + 6 C1.2) — pipe refactor caused zero regressions.
  Next action: **C1.3** — the invasive async-notify step (design in the C1.3 section; reuses the CHANGE_NOTIFY
  deferred-response mechanism at the IOCTL layer). Present design before wiring.
- **2026-07-14** — **C1.3 DONE (design approved, then implemented).** AsyncNotify is now served out-of-band:
  the FSCTL_PIPE_TRANSCEIVE branch detects a witness pipe (`RpcPipe.Endpoint`) and, via
  `WitnessEndpoint.TryBeginAsyncNotify` (parses opnum 3 + context handle, scoped to the owning connection),
  hands off to `BeginWitnessAsyncNotify` (new, in `Smb2Dispatcher.Notification.cs` next to CHANGE_NOTIFY,
  reusing `InterimResponse`/`PendingAsyncRequest`/`SendAsyncFinalAsync`/`NotifyOnce`). Notification rendezvous
  is `WitnessNotificationChannel` (one-shot waiter + bounded buffer; a buffered notify is delivered on a
  pooled thread, never inline, so the STATUS_PENDING interim always precedes the out-of-band final). The final
  is an IOCTL response carrying the RESP_ASYNC_NOTIFY DCERPC PDU (callId echoed). CANCEL/teardown →
  STATUS_CANCELLED. Tests `WitnessAsyncNotifyTests` (2, green): pend→push→out-of-band ResourceChange (asserts
  AsyncId match + decoded MessageType) and CANCEL→STATUS_CANCELLED. **Full suite 518/518 green** — IOCTL
  hot-path change caused zero regressions. Gotcha found while testing: each SMB2 request needs a distinct
  increasing MessageId (reusing one trips the sequence-window check); CANCEL must reuse the async op's MID.
  Next action: **C1.4** — public failover-trigger API (`WitnessRegistrationStore.NotifyResourceChange` +
  builder exposure) + drop registrations on connection teardown.
- **2026-07-14** — **C1.4 + C1.5 DONE → C1 (Witness) COMPLETE.** C1.4: public failover trigger
  `WitnessRegistrationStore.NotifyResourceChange(netName, change, resourceName)` (case-insensitive net-name
  match, null=all; delivers to a waiting AsyncNotify or buffers) surfaced ergonomically as
  `SmbServer.NotifyWitnessResourceChange(...)` (the host already exposed `SmbServer.State`, so no builder
  plumbing needed). Registrations are dropped on connection teardown — `RemoveAllForConnection` wired into
  both `OnConnectionClosedAsync` and `OnConnectionClosed` (a pending AsyncNotify is already cancelled →
  STATUS_CANCELLED by the existing `CancelNonSurvivingPending`). C1.5 folded in: the e2e notify test now
  triggers via the public API. Tests: `WitnessEndpointTests` +2 (net-name filter incl. non-match=0; teardown
  drops only that connection's regs), e2e trigger test updated. **Full suite 520/520 green.**
  **Phase C1 (C1.0–C1.5) complete:** CA capability advertised (SMB3), full `\PIPE\witness` MS-SWN endpoint
  (GetInterfaceList/Register/RegisterEx/UnRegister/AsyncNotify), async out-of-band failover notifications, and
  a public server-side trigger. **Manual-verify against a real Windows failover cluster client when available**
  (the CI tests drive the wire/dispatch paths but not a genuine SMB witness client). Deferred niceties (not
  blocking): real per-NIC interface list in GetInterfaceList (currently a single self-interface, IPv4=0);
  ClientMove/ShareMove/IpChange notify types are encodable but no trigger API yet (only ResourceChange shipped).
  _(Update 2026-07-14: both deferred items are now DONE — the three move/IP notify types have encoders + trigger APIs (C1.6) and GetInterfaceList reports the real per-NIC list (C1.7); see the entries below. C1 has no remaining deferred niceties; the only open item is interop against a real Windows witness client.)_
  Next action (C-phase): **C2** — durable persistent-handle store (survives restart), or **D** (OTel / resource
  limits / fuzzing) per target market — user's call.
- **2026-07-14** — **C2 DONE → Phase C (HA) COMPLETE.** Restart-surviving persistent handles shipped:
  `FileDurableHandleStore` persists CA-handle metadata (`PersistentHandleRecord`, atomic JSON-per-FileId) and
  reloads it as cold records on startup; the reconnect path is now async and, on a warm miss, rehydrates a live
  `SmbOpen` from the cold record (re-open backend + re-reserve share mode) so I/O resumes. Record written at
  CREATE (crash-safe), removed at CLOSE; persistent-id counter seeded from the store so allocations can't
  collide with rehydrated ids; new `SmbOpen.ShareAccess`. Builder: `UsePersistentDurableHandles(dir)`. **v1
  scope:** locks/oplocks/leases not reconstructed (documented in the C2 section + `IPersistentHandleStore`).
  Tests `PersistentHandleRestartTests` (4, incl. full open→restart→reconnect→read). **Full suite 524/524 green**
  — the async reconnect refactor + persist wiring caused zero regressions in the durable-handle tests.
  Phase C (C1 Witness + C2 persistent store) is complete. Remaining in this roadmap: **Phase D** (D1 OTel,
  D2 resource limits, D3 fuzzing/conformance) — Ops hardening, independently startable, user's call.
- **2026-07-14** — **C1.6 — Move/IP notify types shipped (closes most of the C1 deferred caveat).** Added the
  three remaining MS-SWN async-notify message types alongside the existing ResourceChange: `WITNESS_IPADDR_INFO_LIST`
  wire body (`WitnessIpAddr` + `WitnessIpAddrFlags` + `WitnessWire.EncodeIpAddrInfoList`, §2.2.2.4 — shared by
  CLIENT_MOVE/SHARE_MOVE/IP_CHANGE, only the `MessageType` differs) and public trigger APIs
  `WitnessRegistrationStore.NotifyClientMove/NotifyShareMove/NotifyIpChange` (the per-type `NotifyResourceChange`
  logic refactored into a shared private `Notify(netName, type, buffer)`). Tests: `WitnessWireTests` +4 (IPADDR
  list layout golden + AsyncNotify-wraps-type theory ×3) and `WitnessAsyncNotifyTests` +3 (e2e theory driving each
  move type through the real IOCTL/dispatcher path → asserts `MessageType` in the out-of-band RESP_ASYNC_NOTIFY).
  **Full suite 531/531 green.** Still deferred (not blocking): real per-NIC interface list in `GetInterfaceList`
  (still a single self-interface, IPv4=0). The only true interop gap remaining is a real Windows witness client;
  next-best automatable closers discussed: golden byte-vectors from the MS-SWN spec + Samba `smbtorture smb2.witness`.
- **2026-07-14** — **C1.7 — real per-NIC GetInterfaceList (closes the last C1 deferred item).** `WitnessrGetInterfaceList`
  no longer returns a single self-interface with IPv4=0. New mapper `WitnessEndpoint.FromNetworkInterfaces(serverName, nics)`
  reuses the existing multichannel `INetworkInterfaceProvider` (`SmbServerOptions.NetworkInterfaceProvider`,
  default `SystemNetworkInterfaceProvider`) — one available, witness-serving `WITNESS_INTERFACE_INFO` per IPv4
  address (IPV4 = address bytes read LE so a LE wire write reproduces network order; flags IPv4Valid|InterfaceWitness).
  IPv6-only addresses skipped (the WITNESS_INTERFACE_INFO IPv4/IPv6 split advertises IPv4; IPv6 payload is a
  documented follow-up). Falls back to `SelfInterfaces` when no IPv4 NIC is enumerable → the call never returns
  empty. Wired in `OpenRpcEndpoint` (snapshots live NICs per call). Tests: `WitnessEndpointTests` +2 (maps IPv4 /
  skips IPv6 with correct IPV4 uint + flags; IPv6-only → self-interface fallback). **Full suite 531 → 533 green.**
  **C1 has no remaining deferred niceties** — the only open item is genuine interop against a real Windows witness
  client (automatable closers still noted: MS-SWN golden byte-vectors + Samba `smbtorture smb2.witness`).
- _(append progress entries here as milestones complete; check items off in the phase sections)_
