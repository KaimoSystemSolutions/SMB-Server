# Enterprise Roadmap: Windows Server parity and beyond

> **Purpose of this document:** Structured gap analysis and implementation plan for
> reaching enterprise-grade feature parity with Windows Server 2025 SMB. Each phase
> is broken into discrete, testable milestones. Progress is tracked in the
> [Status Journal](#status-journal) at the bottom.
>
> **Baseline:** The library implements SMB 2.0.2–3.1.1 with NTLM authentication,
> AES encryption/signing, byte-range locking, oplocks (classic), CHANGE_NOTIFY,
> share-mode enforcement, concurrent I/O, compound requests, and a pluggable
> `IFileStore` backend. See `docs/SECURITY_AUDIT.md` and `docs/ASYNC_IO_ROADMAP.md`
> for completed hardening work.

---

## Phase 1 — Lease infrastructure (replaces classic oplocks)

Windows clients (since SMB 2.1) negotiate **leases** instead of classic oplocks.
Without leases, clients fall back to no caching or Level II only — a significant
performance penalty for every file open. This is the single highest-impact gap.

### M1.1 — Lease state model ✅

- [x] Define `LeaseState` flags (`Read`, `Write`, `Handle`) and `LeaseKey` (16-byte
      client-assigned GUID) in `Smb.Protocol`.
      (`Enums/LeaseEnums.cs`, `Messages/LeaseKey.cs`)
- [x] Add `SMB2_CREATE_REQUEST_LEASE` / `SMB2_CREATE_REQUEST_LEASE_V2` create context
      parsing and serialization (`Messages/CreateContexts.cs`, `Messages/LeaseRequest.cs`).
      Includes a generic CREATE-context chain parser/serializer reusable by Phase 4.
- [x] Extend `SmbOpen` with `LeaseKey`, `LeaseState`, `LeaseEpoch`, `ParentLeaseKey`.
- [x] Add `ILeaseManager` interface (`Smb.Server/Leases/`) with:
  - `LeaseGrant RequestLease(SmbOpen open, LeaseRequest request)`
  - `LeaseState Acknowledge(LeaseKey key, LeaseState newState)`
  - `void ReleaseOwner(SmbOpen open)`
- [x] Implement `InMemoryLeaseManager` (process-local, per-file-key table).
- [x] Wire `ILeaseManager` into `SmbServerOptions` (default `InMemoryLeaseManager`).
- [x] Add `NullLeaseManager` (always grants `LeaseState.None`).
- [x] Unit tests: solo lease grant (R, RW, RWH), multi-open downgrade, release
      (`tests/Smb.Tests/LeaseModelTests.cs`, 18 tests).

> **Note:** M1.1 is deliberately non-behavioral at the dispatcher level — the lease
> manager and context types exist and are unit-tested, but CREATE does not yet parse
> the lease context or grant leases on the wire. That wiring is M1.2.

### M1.2 — Lease break pipeline ✅ (break-before-grant deferred)

- [x] Implement lease break notification (§2.2.23.2): build and send
      `SMB2_LEASE_BREAK_NOTIFICATION` via `connection.SendRawAsync`
      (`Messages/LeaseBreakMessages.cs`, `Smb2Dispatcher.Lease.cs`).
- [x] Handle `SMB2_LEASE_BREAK_ACKNOWLEDGMENT` (§2.2.24.2, StructureSize 36) — routed
      from `HandleOplockBreak` by StructureSize to `HandleLeaseBreakAck`, answered with
      a `SMB2_LEASE_BREAK` response (§2.2.25.2).
- [x] Wire lease breaks into `HandleCreateAsync` alongside oplock grants: CREATE parses
      the "RqLs" context, grants via `ILeaseManager`, echoes the granted state in a
      response context, and releases the lease at CLOSE / connection teardown.
- [x] Integration tests: solo grant + echoed context, second distinct key triggers a
      LEASE_BREAK notification and Read downgrade, acknowledgment answered, CLOSE releases
      (`tests/Smb.Tests/LeaseDispatcherTests.cs`, 5 tests).
- [ ] **Deferred:** blocking break-before-grant. The conflicting CREATE does not wait for
      the holder's acknowledgment (with timeout → break to None); the holder is downgraded
      immediately in the manager. This is the *same* intentional simplification the classic
      oplock path already makes (see `InMemoryOplockManager`); implementing the blocking
      wait + timeout is its own focused pass and touches both managers symmetrically.

> **Note:** M1.2 delivers the complete grant → notify → acknowledge → release pipeline on
> the wire. What remains (the blocking wait) is a correctness refinement for concurrent
> conflicting opens, not a gap in the message flow.

### M1.3 — Directory leases ✅

- [x] Extend `ILeaseManager` to track directory lease keys (`LeaseHolder.IsDirectory`, set at grant
      from `open.LocalOpen.IsDirectory`; `NullLeaseManager` returns no breaks).
- [x] Grant directory leases on directory CREATE when requested via V2 context — the existing lease
      grant path is backend-path-keyed and already covers directories (solo dir open → full RH).
- [x] Break directory leases on child add/remove/rename within the leased directory via new
      `ILeaseManager.BreakDirectoryLease(directoryFileKey)` + dispatcher helper
      `BreakParentDirectoryLease(childPhysicalPath)` (`Smb2Dispatcher.Lease.cs`). Hooks:
      CREATE with `CreateOutcome.Created` (add), CLOSE of a `DeleteOnClose` open (remove),
      SET_INFO `FileRenameInformation` (rename, both source and target parent). The break drops
      Handle caching, keeping at most shared Read; the epoch is bumped and a LEASE_BREAK
      notification is delivered out-of-band to the holder.
- [x] `SmbOpen.DeleteOnClose` is now kept in sync (CREATE `DeleteOnClose` option + SET_INFO
      `FileDispositionInformation`) so CLOSE knows an entry will be removed — previously a dead field.
- [x] Tests: directory lease grant + echoed context, child-create/-delete/-rename each trigger a
      LEASE_BREAK to Read, acknowledgment answered (`tests/Smb.Tests/DirectoryLeaseTests.cs`, 5 tests).

> **Note:** For directories the RH→R downgrade plus the epoch bump/notification is the staleness
> signal; the client re-enumerates on the break. Same break-before-grant simplification as M1.2 /
> the classic oplock path (the conflicting change is not blocked on the holder's ack).

**Estimated scope:** ~1,200 LOC production + ~600 LOC tests. *(Actual: ~90 LOC production + ~250 LOC
tests — most of the lease infrastructure was already in place from M1.1/M1.2.)*

---

## Phase 2 — Kerberos authentication & AD integration

NTLM alone is insufficient for enterprise environments. Active Directory domains
require Kerberos. The `IGssMechanism` / `IIdentityBackend` seam is already
designed for this.

### M2.1 — Kerberos GSS mechanism ✅ (platform ticket-crypto binding is the user's seam)

Designed for **full modularity**: the library user composes the SPNEGO stack from mechanism factories
and plugs in their own Kerberos ticket crypto — the framework owns only the SPNEGO/GSS framing and the
SMB integration.

- [x] Composable **`SpnegoNegotiator`** (`src/Smb.Auth/SpnegoNegotiator.cs`): built from an ordered
      list of `IGssMechanismFactory` (server preference). Advertises all mech OIDs in NegTokenInit2,
      selects the client's mechanism (SPNEGO optimistic model + resend on mismatch), wraps/unwraps the
      envelope, and still routes raw NTLMSSP unwrapped. `NtlmSpnegoNegotiator` is now a thin wrapper
      over it (single NTLM factory) — proven back-compatible by the whole existing suite.
- [x] **`KerberosServerMechanism : IGssMechanism`** (`src/Smb.Auth/Kerberos/`): one-leg AP-REQ →
      (optional) AP-REP. Owns **no** Kerberos crypto — it strips the GSS-API wrapper
      (`KerberosGssToken`, RFC 1964/4121 framing) and delegates ticket decryption / authenticator
      verification / PAC extraction to the injected **`IKerberosTicketValidator`** seam. `SecurityIdentity`
      already carries UPN/SID/group SIDs for the validator to fill.
- [x] Factories `KerberosMechanismFactory` + `NtlmMechanismFactory` (both `IGssMechanismFactory`);
      `DelegatingKerberosTicketValidator` for lambda/closure wiring. Register Kerberos before NTLM to
      make it preferred with NTLM fallback.
- [x] Tests (`tests/Smb.Tests/Phase2AuthTests.cs`, 11): advertising order, Kerberos one-leg success +
      identity, mutual-auth AP-REP wrapping, validation failure → reject, unsupported-first-mech
      fallback + resend, no-common-mech reject, full NTLM-over-SPNEGO handshake, raw NTLMSSP, GSS token
      round-trip, delegating validator.

> **User-supplied binding:** the actual platform Kerberos (Windows SSPI `AcceptSecurityContext` +
> `SECPKG_ATTR_SESSION_KEY`, or MIT/Heimdal `gss_accept_sec_context` with a keytab) is an
> `IKerberosTicketValidator` implementation the library user provides — it is intentionally out of the
> core so there is no platform lock-in and the seam stays fully testable with a fake validator.

### M2.2 — LDAP/AD identity backend ✅

**Design for modularity + dependency isolation:** the identity-resolution logic (LDAP attribute →
`SecurityIdentity` mapping, caching, SID conversion) lives in the dependency-free core `Smb.Auth`
behind a tiny **`ILdapSearcher`** seam, so it is fully unit-testable with a fake directory and free of
any platform LDAP dependency. The concrete `System.DirectoryServices.Protocols` searcher (the actual
network binding to a DC) goes in a **separate opt-in project** so the LDAP dependency is never forced
on consumers who do not need it (the single-package embed stays clean).

Incremental plan (each step self-contained + tested):

- [x] **A** — `SidConverter` (`src/Smb.Auth/Ldap/`): binary ↔ string SID (MS-DTYP §2.4.2.2) and the
      `\HH`-escaped form for LDAP `objectSid` filters. Pure, no dependency. *(done)*
- [x] **B** — `ILdapSearcher` + `LdapEntry` (multi-valued, binary-safe, case-insensitive attrs) +
      `LdapIdentityBackendOptions` (base DN, filter/attribute names, cache TTL). Connection/bind config
      is intentionally left to the concrete searcher. *(done)*
- [x] **C** — `LdapIdentityBackend : IIdentityBackend`: `Resolve` maps `objectSid` + transitive group
      SIDs (`tokenGroups`, with a `memberOf`-DN fallback) + UPN to `SecurityIdentity` (new
      `SecurityIdentity.UserPrincipalName`); RFC 4515 filter escaping (`LdapFilter.Escape`);
      `TryGetNtHash` returns false (AD does not expose NT hashes over LDAP — NTLM needs Kerberos or a
      Netlogon secure channel). 5 tests. *(done)*
- [x] **D** — `TtlCache` (via `TimeProvider` for deterministic expiry) for identity + SID↔name lookups;
      `ISidResolver` seam (`TryGetAccountName` / `TryGetSid`) implemented by the backend for ACL display
      (Phase 3); `ClearCache()`. AD correctness fix: `tokenGroups` is read with a **Base-scope** lookup
      on the user DN (it is empty on a subtree search). 4 tests. *(done)*
- [x] **E** — `DirectoryServicesLdapSearcher` + `LdapConnectionOptions` in the separate opt-in project
      **`Smb.Auth.DirectoryServices`** (assembly `Smb.Auth.DirectoryServices`, namespace `Smb.Auth.Ldap`)
      wrapping `System.DirectoryServices.Protocols` (LDAP/LDAPS, Negotiate/Basic bind, connection reuse,
      raw-byte attribute extraction). The external dependency lives only here, never in core `Smb.Auth`.
      4 wiring/validation tests; the live round-trip is an integration test against a real DC. *(done)*

**Modularity summary:** core `Smb.Auth` gains LDAP identity resolution with **zero** external
dependency (behind `ILdapSearcher`); consumers who want the real network binding opt into the
`Smb.Auth.DirectoryServices` assembly, or implement `ILdapSearcher` themselves.

> **Packaging follow-up:** `Smb.Auth.DirectoryServices` is intentionally *not* embedded in the
> single `SMB-Server` package (that would force `System.DirectoryServices.Protocols` on everyone). To
> ship it to external consumers it needs its own NuGet package (or the consumer references the source).

### M2.3 — NTLM hardening (deferred audit items) ✅

- [x] **O1** — NTLM MIC verification (downgrade protection, MS-NLMP §3.2.5.1.2): `NtlmServerMechanism`
      keeps the raw NEGOTIATE/CHALLENGE and recomputes the MIC over NEGOTIATE ‖ CHALLENGE ‖
      AUTHENTICATE-with-zero-MIC under the ExportedSessionKey, comparing it in constant time. Verified
      whenever the client announces a MIC via `MsvAvFlags` (bit 0x2), or unconditionally when the new
      `NtlmServerOptions.RequireMessageIntegrity` is set. `NtlmClient` gained optional MIC generation
      for the tests. *(done)*
- [x] **O3** — validate `PreauthIntegrityCapabilities` presence in 3.1.1 negotiate: a client offering
      SMB 3.1.1 without a preauth context (SHA-512) is rejected with `STATUS_INVALID_PARAMETER`
      (`Smb2Dispatcher.HandleNegotiate` + `HasSupportedPreauthContext`). *(done)*
- [x] **O4** — reject `SESSION_SETUP` before `NEGOTIATE` completes: guarded on `connection.NegotiateDone`
      in `HandleSessionSetup`. *(done)*
- [x] Tests: `NtlmMicTests` (6 — valid/tampered MIC, tampered negotiate flags detected, strict mode
      accept/reject, compat without MIC) + `AuthHardeningTests` (5 — O3/O4). All three audit items now
      marked fixed in `docs/SECURITY_AUDIT.md`.

**Estimated scope:** ~1,500 LOC production + ~500 LOC tests.

---

## Phase 3 — NTFS security descriptors & per-file ACLs

Without per-file ACLs, authorization is limited to share-level policies. Enterprise
file servers enforce granular read/write/delete permissions per folder and file.

### M3.1 — Security descriptor model ✅

Built in small tested increments in `src/Smb.Protocol/Security/` (the wire/data layer):

- [x] **A** — `Sid` value type (MS-DTYP §2.4.2): binary ↔ string, `Write`/`ToBytes`/`Parse(out consumed)`,
      value equality for use as a dictionary/set key; `Sid.Create(authority, subs…)`. 15 tests.
- [x] **B** — ACE enums (`AceType`, `AceFlags`, `SecurityDescriptorControl`); `Ace` — basic ACEs
      (ACCESS_ALLOWED/DENIED, SYSTEM_AUDIT/ALARM) parse/serialize with `Allow`/`Deny`/`Audit` factories,
      unknown/object ACE types preserved verbatim in `RawData`. 5 tests.
- [x] **C** — `Acl` (revision + ACE list) parse/serialize (AclSize authoritative on parse). Tested via SD.
- [x] **D** — `SecurityDescriptor` self-relative parse/serialize (MS-DTYP §2.4.6, `Create` factory sets
      DACL/SACL-present bits, control flags preserved so no-DACL / NULL-DACL / present-DACL all round-trip)
      + `WellKnownSids`. 5 tests (incl. NULL-vs-no DACL, SACL, Windows-shaped blob).
- [x] Tests: 25 total (`SidTests`, `AceTests`, `SecurityDescriptorTests`), full suite 264 green.

> **Note:** `Smb.Protocol.Security.Sid` and the older `Smb.Auth.Ldap.SidConverter` (M2.2) now both parse
> SIDs; a later cleanup can have `SidConverter` delegate to `Sid` (Auth depends on Protocol). Left as-is
> for now to avoid churn in the tested M2.2 code.

### M3.2 — QUERY_SECURITY_INFO / SET_SECURITY_INFO ✅

- [x] `IFileStore.GetSecurityAsync` / `SetSecurityAsync` added as default-`NotSupported` interface methods
      (existing backends unaffected); `SyncFileStore` exposes overridable virtuals. New
      `SecurityInformation` flags enum (MS-DTYP §2.4.7).
- [x] QUERY_INFO `InfoType.Security` (`HandleQuerySecurityAsync`): returns the handle's descriptor
      filtered to the components requested via `AdditionalInformation`; `STATUS_BUFFER_TOO_SMALL` when it
      does not fit.
- [x] SET_INFO `InfoType.Security` (`HandleSetSecurityAsync`): merges the requested components from the
      supplied descriptor into the stored one and persists it.
- [x] `LocalFileStore` implements both via a pluggable **`ISecurityDescriptorStore`** seam (default
      `InMemorySecurityDescriptorStore`, physical-path keyed) — portable and testable; a deployment can
      inject a real NTFS/POSIX-ACL-backed store. A file with no explicit ACL returns a permissive default
      (owner Local System, Everyone full control) so behavior is unchanged until an ACL is set.
- [x] Tests: query default SD, set+persist a replaced DACL, buffer-too-small (`SecurityInfoDispatcherTests`,
      3). Full suite 267 green. *(access-denied-after-ACE-removal is M3.3.)*

> **Modularity:** the actual OS-ACL mapping (NTFS / POSIX) is the `ISecurityDescriptorStore`
> implementation the user supplies; the core stays dependency-free and cross-platform.

### M3.3 — Access check enforcement ✅

- [x] On CREATE, evaluate the file's DACL against the authenticated user's SIDs (primary + group +
      Everyone / Authenticated Users) to determine the effective access. The granted mask is capped to
      what the DACL permits and stored on the open (`Smb2Dispatcher.HandleCreateAsync` → `AccessCheck`,
      `BuildCallerSids`). Generic bits in `DesiredAccess` are mapped to specific file rights first
      (`AccessMask.MapGenericToSpecific`, MS-DTYP §2.5.3.2). A denial rolls the open back with no side
      effects. On a backend whose `GetSecurityAsync` is `NotSupported` only share-level authorization
      applies (unchanged), so non-ACL backends are unaffected.
- [x] Enforce the granted access per operation: READ needs `FILE_READ_DATA`, WRITE needs
      `FILE_WRITE_DATA`/`FILE_APPEND_DATA`, SET_INFO delete-disposition and rename need `DELETE`,
      end-of-file (truncate) needs `FILE_WRITE_DATA` (`Smb2Dispatcher.FileCommands.cs`). `SmbOpen.GrantedAccess`
      is now the authoritative specific-rights mask (previously write-only).
- [x] Inheritance: a newly created file/directory inherits the parent directory's inheritable ACEs
      (`AclInheritance.ComputeInherited`, MS-DTYP §2.5.3.4 — ObjectInherit/ContainerInherit,
      InheritOnly/NoPropagate, `Inherited` flag). Wired into `LocalFileStore` on `CreateOutcome.Created`;
      only applied when the parent carries an explicit descriptor, so shares that never set an ACL keep
      the permissive default for new files.
- [x] Tests: `AclInheritanceTests` (7 — the pure inheritance algorithm) + `AccessEnforcementTests`
      (5 — read-only DACL denies a write open, per-operation READ/WRITE enforcement via MAXIMUM_ALLOWED,
      deny-ACE overrides allow, delete-disposition needs DELETE, new file inherits the parent ACE). Full
      suite 287 green.

> **Modularity:** the pure evaluator (`AccessCheck`) and inheritance (`AclInheritance`) live in
> `Smb.Protocol.Security` (dependency-free); enforcement is in the dispatcher; the ACL *storage* remains
> the `ISecurityDescriptorStore` seam a deployment maps onto real NTFS/POSIX ACLs. **Phase 3 complete.**

**Estimated scope:** ~2,000 LOC production + ~800 LOC tests. *(Actual: ~120 LOC production + ~260 LOC
tests — the `AccessCheck` evaluator and SD model were already in place from M3.1.)*

---

## Phase 4 — Durable & persistent handles

Handles that survive network interruptions are essential for enterprise reliability
(laptop standby, Wi-Fi roaming, brief outages).

### M4.1 — Durable handles (v1, SMB 2.x) ✅

- [x] Parse `SMB2_CREATE_DURABLE_HANDLE_REQUEST` ("DHnQ") / `_RECONNECT` ("DHnC") create contexts
      (`Smb.Protocol.Messages.DurableHandleMessages`).
- [x] On CREATE with a durable request: grant durability only when the open holds a batch/exclusive
      oplock or a handle-caching lease (§3.3.5.9.6, `DurabilityAllowed`); assign a stable server-unique
      persistent FileId (`SmbServerState.AllocatePersistentId`, high bit set), mark `SmbOpen.IsDurable`
      and echo a "DHnQ" response context. A request without a caching guarantee is ignored (client falls
      back to a normal handle).
- [x] On transport drop (`OnConnectionClosed`): durable opens are **not** released — they are registered
      in the `IDurableHandleStore` with a deadline (`DurableHandleTimeout`, default 60 s) while their
      backend handle, locks, oplock/lease and share-mode reservation stay intact.
- [x] On reconnect ("DHnC"): `HandleDurableReconnectAsync` claims the open by FileId, verifies it is not
      expired and is owned by the same principal (`OwnerKey`), re-attaches it to the new session/tree and
      resumes. Not found/expired → `STATUS_OBJECT_NAME_NOT_FOUND`; wrong principal → `STATUS_ACCESS_DENIED`
      (handle kept).
- [x] On timeout expiry: `ScavengeDurableHandles()` (host-driven, `TimeProvider`-based) releases the open
      normally (dispose handle, release locks/oplock/lease/share mode).
- [x] Tests: `DurableHandleTests` (5) reconnect-within-timeout succeeds + reads, expired → scavenged →
      `OBJECT_NAME_NOT_FOUND`, principal mismatch denied but owner still reconnects, grant only with an
      oplock; `DurableHandleMessagesTests` (6) protocol round-trips.

### M4.2 — Resilient / persistent handles (SMB 3.0) ✅

- [x] Parse `SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2` ("DH2Q") / `_RECONNECT_V2` ("DH2C") contexts
      (create GUID, requested timeout, persistent flag).
- [x] Support the persistent flag for CA shares: new `IShare.ContinuousAvailability`; a persistent
      request is honored only on a CA share (else downgraded to a normal durable handle). Persistent
      handles never time out (skipped by the scavenger and the reconnect expiry check).
- [x] Resilient handles survive across sessions — the store is global and a reconnect is validated by
      FileId + create GUID + principal (not by session), so any new session of the same user reconnects.
- [x] Timeout honored from the v2 request (`ResolveDurableTimeout`, 0 = server default, clamped to
      `MaxDurableHandleTimeout`, default 16 min); a v2 reconnect must present the matching create GUID.
- [x] Tests: `DurableHandleTests` v2 additions (4) — v2 grant with timeout+GUID, GUID-mismatched
      reconnect rejected, persistent handle on a CA share survives a 2 h gap + scavenge, persistent flag
      on a non-CA share downgraded (still expires).

### M4.3 — Persistent handle store interface ✅

- [x] `IDurableHandleStore` (`src/Smb.Server/Durable/`) defines the durable/persistent open storage seam
      (`Add` / `TryClaim` / `TakeExpired` / `TakeAll`), swappable via `SmbServerOptions.DurableHandleStore`.
- [x] `InMemoryDurableHandleStore` — default, process-local (survives TCP drops, not a process restart).
- [x] Documented the contract for out-of-process implementations (SQLite/Redis): persist each entry's
      reconnect metadata and **rehydrate a live `SmbOpen` in `TryClaim`** after a restart (the dispatcher
      resumes I/O directly on `DurableHandle.Open`); only persistent (CA) entries must be recoverable.

> **Modularity:** durable-handle wire parsing is pure in `Smb.Protocol`; the storage is the
> `IDurableHandleStore` seam; expiry uses the injectable `SmbServerOptions.TimeProvider`. **Phase 4
> complete** (in-process). Cross-process *restart* survival for persistent handles is a documented
> extension point (a serializable store that rehydrates opens), not covered by the in-memory default.

**Estimated scope:** ~1,800 LOC production + ~700 LOC tests. *(Actual: ~330 LOC production + ~330 LOC
tests — much of Phase 4 reused the existing CREATE-context chain parser and lease/oplock managers.)*

---

## Phase 5 — Server-side copy & FSCTL extensions

Server-side copy (`FSCTL_SRV_COPYCHUNK`) eliminates double network transfer for
file copies. Additional FSCTLs are required by Windows Explorer and common tools.

### M5.1 — FSCTL_SRV_COPYCHUNK / COPYCHUNK_WRITE ✅

- [x] Parse `SRV_COPYCHUNK_COPY` input buffer (source key, chunk array) and build the
      `SRV_REQUEST_RESUME_KEY` / `SRV_COPYCHUNK_RESPONSE` payloads
      (`Smb.Protocol.Messages.CopyChunkMessage`, pure).
- [x] Resume-key mechanism: FSCTL_SRV_REQUEST_RESUME_KEY assigns the source open a stable opaque
      24-byte key (`SmbOpen.ResumeKey`, lazily allocated via `RandomNumberGenerator`) and returns it;
      FSCTL_SRV_COPYCHUNK(_WRITE) locates the source by that key within the same session
      (`TryFindOpenByResumeKey`, constant-length compare) — so cross-share copies inside one session
      work — and copies each chunk into the destination open the IOCTL targets.
- [x] Access checks: the destination needs `FILE_WRITE_DATA`, the source `FILE_READ_DATA` (M3.3
      granted mask); the §2.2.31.1 limits (≤16 chunks, ≤1 MiB/chunk, ≤16 MiB total) are enforced
      before any I/O and a violation returns the maxima with `STATUS_INVALID_PARAMETER`.
- [x] Extend `IFileStore` with an optional `CopyRangeAsync` offload seam (default
      `NotSupported`). The dispatcher prefers it when source and destination share the same store,
      otherwise falls back to a bounded 64 KiB read/write loop that also spans two backends.
- [x] Tests (`tests/Smb.Tests/CopyChunkTests.cs`, 7): resume-key / copy-request wire round-trips,
      same-share copy (two chunks), cross-share copy via the fallback, too-many-chunks →
      `INVALID_PARAMETER` + maxima, unknown resume key → `OBJECT_NAME_NOT_FOUND`, and the backend
      offload seam being taken for a same-store copy. Full suite 309 green.

> **Modularity:** the copychunk wire types are pure in `Smb.Protocol`; the copy orchestration
> (resume-key lookup, limit enforcement, fallback loop) lives in the dispatcher; native offload is
> the `IFileStore.CopyRangeAsync` seam a backend maps onto `copy_file_range` /
> `FSCTL_DUPLICATE_EXTENTS`. `LocalFileStore` keeps the default (fallback loop) for now.

### M5.2 — Additional FSCTLs ✅

Wire structures are pure in `Smb.Protocol.Messages.FsctlMessage`; the semantics sit behind two
opt-in seams (`ISparseFileStore`, `IReparsePointStore`, checked with `is` like `ISnapshotStore`) so
the core stays dependency-free and a backend maps them onto real OS calls.

- [x] `FSCTL_SET_SPARSE` — `ISparseFileStore.SetSparseAsync` (empty input ⇒ TRUE, MS-FSCC §2.3.68).
- [x] `FSCTL_SET_ZERO_DATA` — `SetZeroDataAsync` over the parsed FILE_ZERO_DATA_INFORMATION range.
- [x] `FSCTL_QUERY_ALLOCATED_RANGES` — `QueryAllocatedRangesAsync`; the FILE_ALLOCATED_RANGE_BUFFER
      array is serialized and capped to the request's `MaxOutputResponse` (`STATUS_BUFFER_TOO_SMALL`).
- [x] `FSCTL_GET_REPARSE_POINT` / `_SET_` / `_DELETE_` — `IReparsePointStore`; the reparse data buffer
      is opaque to the server. GET on a non-reparse backend answers `STATUS_NOT_A_REPARSE_POINT`,
      SET/DELETE `STATUS_NOT_SUPPORTED`. (`STATUS_STOPPED_ON_SYMLINK` path-resolution error data is
      deferred to Phase 11 / M11.2 where symlink traversal is handled.)
- [x] `FSCTL_DFS_GET_REFERRALS` / `_EX` — stub returning `STATUS_NOT_FOUND` (no DFS namespace), so the
      client falls back to the plain path. Full DFS is Phase 7.
- [x] Access gates: SET_SPARSE / SET_ZERO_DATA / SET_REPARSE need write, QUERY / GET need read.
      Backends without the seam return the correct unsupported status.
- [x] Tests (`tests/Smb.Tests/AdditionalFsctlTests.cs`, 10): wire round-trips, set-sparse on a capable
      vs. plain backend, zero-data actually zeroes, query-allocated-ranges output, reparse get/set
      round-trip + not-a-reparse-point on both a capable-but-empty and a plain backend, DFS → NOT_FOUND.

### M5.3 — FSCTL_VALIDATE_NEGOTIATE_INFO hardening ✅

- [x] Implemented FSCTL_VALIDATE_NEGOTIATE_INFO to §3.3.5.15.12 (it was previously unhandled and
      fell through to `STATUS_INVALID_DEVICE_REQUEST`). The handler parses the request
      (`IoctlMessage.ParseValidateNegotiate`) and compares **capabilities, client GUID, security mode
      and the negotiated dialect** (derived from the offered list via `PickDialect`) against the values
      this connection actually negotiated (stored on `SmbConnection` at NEGOTIATE time).
- [x] Any mismatch is treated as a downgrade attack: the dispatcher sets a new
      `SmbConnection.MustTerminate` flag and returns **no response**; the host read loop
      (`SmbConnectionHandler`) breaks and tears the transport connection down.
- [x] On a match the server returns its own negotiated values (`BuildValidateNegotiateResponse`,
      MS-SMB2 §2.2.32.6), signed via the normal path so the client can trust them.
- [x] Tests (`tests/Smb.Tests/ValidateNegotiateTests.cs`, 5): wire round-trip, matching parameters →
      server info echoed, and tampered capabilities / GUID / dialect-list each → empty reply +
      `MustTerminate`. Full suite 324 green.

> **Note:** `HandleIoctlAsync` now returns `ResponseSegment?` so an IOCTL can legitimately produce
> "no response" (mirroring CANCEL). Secure negotiate is defined for SMB 3.0/3.0.2; 3.1.1 clients rely
> on preauth integrity instead and do not issue it, but the handler compares against the actual
> negotiated dialect so it is correct for any dialect that sends it.

**Estimated scope:** ~1,000 LOC production + ~500 LOC tests. *(Actual: ~230 LOC production + ~200 LOC
tests across M5.1–M5.3 — the IOCTL dispatch, CREATE-context and access-check infrastructure were
already in place.)*

**Phase 5 complete.** Server-side copy (copychunk + resume keys, offload seam), the sparse/reparse/DFS
FSCTLs (opt-in `ISparseFileStore` / `IReparsePointStore` seams), and secure-negotiate downgrade
protection all landed with 22 new tests (7 + 10 + 5), suite 302 → **324 green**.

---

## Phase 6 — Multichannel (SMB 3.0+)

Multichannel binds multiple TCP connections to a single SMB session for
throughput aggregation and failover.

### M6.1 — Session binding ✅

- [x] Accept `SMB2_SESSION_SETUP` with `SMB2_SESSION_FLAG_BINDING` on a second connection
      (`Smb2Dispatcher.HandleSessionBinding`), routed from `HandleSessionSetup` by the request flag.
- [x] Verify the binding request's signature using the **session** signing key before anything else
      is done (proves the new connection possesses the session key, §3.3.5.5.2); unsigned or
      wrong-key → `STATUS_ACCESS_DENIED`. Guards: dialect must be 3.x and match the session's
      (`STATUS_INVALID_PARAMETER`), same `ClientGuid`, session must be `Valid`, not already bound to
      this connection (`STATUS_REQUEST_NOT_ACCEPTED`), unknown session → `STATUS_USER_SESSION_DELETED`.
- [x] Per-channel model: `SmbChannel` + `SmbSession.Channels` (keyed by `ConnectionId`), the primary
      channel registered when the session goes `Valid`. The binding re-runs the GSS exchange on a fresh
      per-connection context (`SmbConnection.PendingBindings`), confirms the re-authenticated identity
      matches the session's (`SameIdentity`, no privilege change), and derives a **per-channel signing
      key** from the *session* key: 3.1.1 uses the channel's own preauth hash so the key differs per
      channel (`DeriveChannelSigningKey`, §3.3.5.5.3); 3.0/3.0.2 has no preauth input so it equals the
      session key. Signing/verification resolve `SmbSession.SigningKeyFor(connection)` at the two choke
      points (`AssembleResponse`, `VerifyInboundSignature`).
- [x] Share session state: the bound connection joins the existing `SmbSession`, so identity, keys,
      tree connects and opens are shared. Channel-aware teardown (`OnConnectionClosed`) drops only the
      closing channel; the session and its opens survive until the **last** channel closes.
- [x] Tests (`tests/Smb.Tests/Phase6BindingTests.cs`, 4): bind on conn B then READ conn A's open over
      conn B signed with the channel key (asserting the channel key differs from the session key and the
      final binding response verifies under it); unsigned/wrong-key binding → `ACCESS_DENIED`; unknown
      session → `USER_SESSION_DELETED`; closing the bound channel keeps the session, closing the last
      tears it down. Full suite **328 green**.

> **Note:** the two remaining M6.x milestones build on this: M6.2 advertises the interfaces the client
> uses to *open* extra channels, M6.3 migrates in-flight I/O when a bound channel drops. Same
> break-before-grant-style simplification is not relevant here; the binding path is complete on the wire.

### M6.2 — Interface discovery (FSCTL_QUERY_NETWORK_INTERFACE_INFO) ✅

- [x] `FSCTL_QUERY_NETWORK_INTERFACE_INFO` (§2.2.32.5) handled in the IOCTL dispatcher
      (`HandleQueryNetworkInterfaceInfo`); issued without a file handle. Returns the chained
      `NETWORK_INTERFACE_INFO` array (IfIndex, capability, link speed, IPv4/IPv6 `SOCKADDR_STORAGE`).
      Refused (`STATUS_NOT_SUPPORTED`) when multichannel is disabled or the dialect is &lt; 3.0; the
      output is capped to the client's `MaxOutputResponse` (`STATUS_BUFFER_TOO_SMALL`).
- [x] Pure wire builder `NetworkInterfaceInfoMessage.Build` (152-byte entries) in `Smb.Protocol`.
      The NIC source is a seam **`INetworkInterfaceProvider`** (`Smb.Server.Multichannel`,
      `SmbServerOptions.NetworkInterfaceProvider`); default `SystemNetworkInterfaceProvider` enumerates
      operational, non-loopback NICs via `NetworkInterface.GetAllNetworkInterfaces()` (unicast
      IPv4/IPv6, link speed; RSS/RDMA not detectable via the managed API → `None`). So the core stays
      testable (fake provider) and a deployment advertises exactly the interfaces it wants.
- [x] `SMB2_GLOBAL_CAP_MULTICHANNEL` advertised on 3.x NEGOTIATE (`SmbServerOptions.EnableMultichannel`,
      default on) so clients actually attempt multichannel and issue this FSCTL.
- [x] Tests (`tests/Smb.Tests/Phase6InterfaceInfoTests.cs`, 5): two-interface chained round-trip
      (IPv4 + IPv6 parsed), empty list, multichannel disabled → NOT_SUPPORTED, 2.x dialect →
      NOT_SUPPORTED, capability advertised only for 3.x.

### M6.3 — Channel failover ✅

- [x] Session + opens survive a bound-channel drop (from M6.1); `OnConnectionClosed` removes only the
      closing channel and tears the session down solely when the last channel goes.
- [x] Pending async operations (blocking LOCK, CHANGE_NOTIFY) survive channel loss when another channel
      remains: `OnConnectionClosed` cancels only pending ops whose session did **not** survive; the rest
      complete and reroute. The host no longer blanket-cancels on drop (that logic moved into the
      channel-aware `OnConnectionClosed`).
- [x] Out-of-band responses fail over: `SmbSession.SelectSendChannel(preferred)` picks a live channel,
      and the centralized `SendOutOfBandAsync` selects it **before** signing/framing (so the per-channel
      3.1.1 key is correct) — used by lease break, oplock break, blocking-LOCK final and CHANGE_NOTIFY
      final. If the originating channel dropped, the final response goes out on a surviving one.
- [x] Tests (`tests/Smb.Tests/Phase6FailoverTests.cs`, 2): `SelectSendChannel` prefers the live channel
      then fails over then returns null; a blocking LOCK issued on channel B, whose channel drops while
      pending, is granted and its final response delivered on the surviving channel A (same AsyncId).

**Estimated scope:** ~1,500 LOC production + ~600 LOC tests. *(Actual: ~260 LOC production + ~330 LOC
tests across M6.1–M6.3 — the channel model + per-channel signing added in M6.1 carried M6.3 directly.)*

**Phase 6 complete.** Session binding (M6.1), interface discovery (M6.2) and channel failover (M6.3)
landed with 11 tests (4 + 5 + 2), suite 324 → **335 green**.

---

## Phase 7 — DFS (Distributed File System) referrals

DFS allows a single namespace to span multiple servers. Required for enterprise
environments with distributed storage.

### M7.1 — DFS referral responses ✅

Wire structures are pure in `Smb.Protocol.Messages.DfsReferralMessage`; the namespace (path → targets)
sits behind the `IDfsNamespace` seam in `Smb.Server.Dfs`, so the core stays dependency-free and a
deployment can back the namespace with a static map, a database, or a real DFS coordinator.

- [x] `FSCTL_DFS_GET_REFERRALS` (0x00060194) and `_EX` (0x000601B0) handled in the IOCTL dispatcher
      (`HandleDfsGetReferrals`, issued on IPC$ without a file handle). Parses REQ_GET_DFS_REFERRAL
      (§2.2.2) and REQ_GET_DFS_REFERRAL_EX (§2.2.3); builds RESP_GET_DFS_REFERRAL (§2.2.4) with
      **DFS_REFERRAL_V4** non-name-list entries (§2.2.5.4), string offsets relative to each entry with a
      de-duplicated string pool. Output capped to `MaxOutputResponse` (`STATUS_BUFFER_TOO_SMALL`).
- [x] `IDfsNamespace` seam (`Resolve(requestFileName) → DfsReferralResult?`) + `SmbServerOptions.DfsNamespace`
      (null default → `STATUS_NOT_FOUND`, client uses the literal path, §3.3.5.15.2).
- [x] `StandaloneDfsNamespace` (single-server, static link table). `AddLink`/`AddRoot`; `Resolve` returns
      the **longest matching link prefix** (component-boundary, case-insensitive) so sub-paths and nested
      links resolve correctly; `PathConsumed` = the matched prefix, targets in preference order, TTL.
- [x] TREE_CONNECT of a DFS-root share (`IShare.IsDfs`, default false via a default interface member)
      sets `SMB2_SHAREFLAG_DFS` / `_DFS_ROOT` and `SMB2_SHARE_CAP_DFS` (new `ShareCapabilities` enum).
      NEGOTIATE advertises `SMB2_GLOBAL_CAP_DFS` whenever a namespace is configured.
- [x] Tests (`tests/Smb.Tests/DfsReferralTests.cs`): request/response wire round-trips (single + multi
      target), longest-prefix / sub-path / non-boundary resolution, referral over the dispatcher, path
      outside the namespace → NOT_FOUND, DFS vs. plain share TREE_CONNECT flags, NEGOTIATE cap gating.

### M7.2 — DFS link resolution ✅

- [x] On CREATE against a DFS-root share, a path at or below a DFS link is intercepted and answered
      with `STATUS_PATH_NOT_COVERED` (new `NtStatus.PathNotCovered` = 0xC0000257) so the client requests
      a referral and reconnects to the target (§3.3.5.9). The candidate DFS path is reconstructed as
      `\Server\Share\relative` (`BuildDfsPath`) — the same shape the client sends in a referral request,
      keeping link resolution and referral serving consistent — and checked via `IDfsNamespace.IsLinkCovered`
      (default: `Resolve` returns a non-root referral). A plain share ignores the namespace entirely.
- [x] Referral TTL and target ordering for load balancing: targets are returned in insertion (preference)
      order and each referral carries the namespace's TTL (`DfsReferralResult.TimeToLiveSeconds`), so the
      client caches and load-balances per MS-DFSC.
- [x] Tests: CREATE under a link → PATH_NOT_COVERED, a file directly in the DFS root served locally, a
      link path on a non-DFS share served locally (never PATH_NOT_COVERED).

**Estimated scope:** ~800 LOC production + ~400 LOC tests. *(Actual: ~230 LOC production + ~300 LOC
tests — the IOCTL dispatch, CREATE prologue and access-check infrastructure were already in place.)*

**Phase 7 complete.** DFS referral responses (M7.1) and link resolution (M7.2) landed with 14 tests,
suite 335 → **349 green**.

---

## Phase 8 — Operational readiness

Enterprise file servers require structured logging, timeouts, rate limiting,
and graceful lifecycle management.

### M8.1 — Structured audit logging ✅

Kept dependency-free (no forced logging framework): a small structured-logging seam in
`Smb.Server.Diagnostics` rather than an `ILogger` dependency, so consumers adapt it to
Microsoft.Extensions.Logging / Serilog / a SIEM with a thin implementation. The freeform
`Action<string>?` debug trace stays for developer diagnostics.

- [x] `ISmbAuditLogger` seam + `SmbAuditEvent` (value type: timestamp, level, event type/id, user,
      client address, share, path, status, message) + defaults `NullSmbAuditLogger` (off) and
      `DelegatingSmbAuditLogger`. Wired via `SmbServerOptions.AuditLogger`.
- [x] `SmbAuditEventType` with Windows-equivalent event ids: authentication succeeded/failed (4624/4625),
      session logoff (4634), file closed/deleted (4658/4660), permission changed (4670), share access
      granted/denied (5140/5143), file opened (5145), connection accepted/closed.
- [x] Emitted at: session auth success/failure, LOGOFF, TREE_CONNECT grant/deny, CREATE (open), CLOSE
      (close + delete-on-close), SET_SECURITY (permission change), connection accept/close (host). Each
      call is guarded by `IsEnabled` so the default path allocates nothing. `SmbConnection.ClientAddress`
      carries the client IP for the events.
- [x] Tests (`AuditLoggingTests`, 8): a capturing logger asserts each event and its fields.

### M8.2 — Session & connection timeouts ✅

- [x] Idle-session timeout (`SessionIdleTimeout`, default 15 min): a valid session idle past the window
      is torn down (opens/locks/oplocks/share-modes released) by `Smb2Dispatcher.SweepIdleTimeouts` →
      `ExpireSession`. `SmbSession.LastActivityTicks` updated in `TryGetValidSession`.
- [x] Idle-connection timeout (`ConnectionIdleTimeout`, default 5 min): a connection with no frame for
      the window is dropped via a host-supplied `SmbConnection.RequestClose` (cancels the read loop).
      `SmbConnection.LastActivityTicks` updated per frame.
- [x] Authentication timeout (`AuthenticationTimeout`, default 30 s): a connection with no valid session
      by `CreatedTicks + timeout` is dropped (slow-loris protection).
- [x] The host runs the sweep on a background loop (`TimeoutSweepInterval`, default 30 s; 0 disables).
      All timeouts measured against `SmbServerOptions.TimeProvider`.
- [x] Tests (`TimeoutTests`, 5): idle session expires, active session kept, slow-auth connection closed,
      authenticated connection not closed by auth timeout, idle connection closed — all over a `ManualTimeProvider`.

### M8.3 — Connection rate limiting & DoS protection ✅

- [x] `ConnectionLimiter` (thread-safe, pure): global cap (`MaxConnections`, default 1024) and per-client-IP
      cap (`MaxConnectionsPerClient`, default 64); ≤ 0 disables a cap. `TryAdmit` at accept, `Release` at close.
- [x] The host admits at accept and closes an over-limit connection immediately without allocating session
      state (accept loop `TryAdmit` → `client.Dispose()` on rejection; release via a continuation).
- [x] Per-connection request rate limiter: intentionally **deferred** (roadmap marks it optional/off by
      default; the credit window already bounds outstanding requests, and the async-op cap covers the
      resource-holding ones — H1).
- [x] Tests (`ConnectionLimiterTests`, 5): per-client and global rejection, release frees a slot, zero =
      unlimited, a rejected admission increments nothing.

### M8.4 — Graceful shutdown & connection draining ✅

- [x] `StopAsync(drainTimeout?)` (default `ShutdownDrainTimeout`, 30 s): stops accepting (listener stop),
      signals connections via a drain token so they stop reading **new** frames but finish in-flight work
      and send its response (reads observe the drain token; sends/ops keep the hard token), waits up to the
      drain timeout, then force-closes the remainder.
- [x] `Smb2Dispatcher.SendShutdownBreaksAsync` notifies every caching holder (oplock ≥ LevelII, or a lease
      with caching) to break to `None` before handles close, so the client can flush.
- [x] Drain progress logged (count + timeout, and a force-close notice on timeout).
- [x] Tests (`ShutdownDrainTests`, 2): shutdown-break reaches an oplock holder; a graceful stop drains an
      idle real-TCP connection and closes the socket within the window.

### M8.5 — Health & performance metrics ✅

- [x] `SmbServerMetrics` (`Smb.Server.Diagnostics`, lock-free Interlocked, dependency-free): gauges (active
      connections/sessions/tree-connects/open-handles), counters (connections accepted, auth success/failure,
      requests, bytes read/written total **and per share**, lock contention) and a bucketed request-latency
      histogram exposing p50/p95/p99. `Snapshot()` returns an immutable `MetricsSnapshot`.
- [x] Wired throughout the dispatcher/host at the natural points (accept/close, auth, tree connect/disconnect,
      CREATE/CLOSE, READ/WRITE bytes, lock conflict, per-request latency). Exposed as `SmbServer.Metrics` and
      `SmbServerOptions.Metrics`.
- [x] OpenTelemetry: kept dependency-free — subclass `SmbServerMetrics` (methods are `virtual`) or poll
      `Snapshot()` to bridge to `System.Diagnostics.Metrics`, rather than forcing the package on all consumers.
- [x] Tests (`MetricsTests`, 3): histogram percentiles monotonic/bucketed, auth counters, handle/byte
      counters over real READ/WRITE.

**Estimated scope:** ~2,000 LOC production + ~600 LOC tests. *(Actual: ~520 LOC production + ~470 LOC
tests across M8.1–M8.5.)*

**Phase 8 complete.** Structured audit logging, idle/auth timeouts, connection admission control, graceful
draining shutdown and health/perf metrics landed with 23 tests (8 + 5 + 5 + 2 + 3), suite 349 → **372 green**.

---

## Phase 9 — Alternate data streams & extended attributes

macOS clients use alternate data streams for resource forks and Finder metadata.
Windows tools may use named streams for thumbnails and zone identifiers.

Wire structures are pure in `Smb.Protocol.Messages.Fscc` (`StreamInformation`, `FullEaInformation`);
the semantics sit behind two opt-in seams (`INamedStreamStore`, `IExtendedAttributeStore`, checked with
`is` like `ISparseFileStore`) so the core stays dependency-free and a backend maps them onto real NTFS
ADS / OS xattr. The default `LocalFileStore` backing is in-process (portable + testable).

### M9.1 — Named stream support in IFileStore ✅

- [x] `INamedStreamStore` seam (`OpenNamedStreamAsync` + `QueryStreamsAsync`) instead of widening
      `IFileStore.CreateAsync` — the dispatcher splits a CREATE name of the form `file.txt:stream[:$DATA]`
      (`TrySplitStreamName`, leaf-component colon; the `$DATA` type is ignored, an empty stream name =
      the file's default data stream served as a normal open) and routes a named stream to the seam. The
      returned `NamedStreamHandle` flows through the normal READ/WRITE/SET_INFO path.
- [x] Stream enumeration: QUERY_INFO `FileStreamInformation` (§2.4.43) via `HandleQueryStreamsAsync` —
      an ADS backend reports the default `::$DATA` plus every named stream; any other backend reports
      just the default stream from the file size. Output capped to the client's buffer
      (`STATUS_BUFFER_TOO_SMALL`).
- [x] `LocalFileStore` implements `INamedStreamStore` with an in-process stream table keyed by base
      physical path + case-folded stream name; content I/O (`StreamRead`/`StreamWrite`/`StreamSetLength`)
      routes through the store, `DeleteOnClose` on a stream handle removes just that stream. A named
      stream shares the base file's security descriptor. (Real NTFS ADS / xattr is the deployment's
      `INamedStreamStore` — the default backing is intentionally in-memory.)
- [x] Tests: create/write/read a named stream, enumerate (default + named), delete-on-close removes only
      the stream (base file intact), and stream open on a non-ADS backend → `STATUS_NOT_SUPPORTED`, plus
      the pure wire round-trip.

### M9.2 — Extended attribute support ✅

- [x] QUERY_INFO / SET_INFO `FileFullEaInformation` (§2.4.15): `HandleQueryEaAsync` (needs FILE_READ_EA)
      / `HandleSetEaAsync` (needs FILE_WRITE_EA); a SET entry with a zero-length value deletes that EA.
      Pure `FullEaInformation` builder/parser (4-byte-aligned chain) + `ComputeEaSize`.
- [x] `IExtendedAttributeStore` seam (`Get/SetExtendedAttributesAsync`); `LocalFileStore` implements it
      with an in-process EA table keyed by physical path (add/replace/delete merge). A backend without
      the seam reports no EAs and rejects EA writes with `STATUS_NOT_SUPPORTED`.
- [x] Tests: set two EAs, read them back, delete one by zero-length value, and query on a backend with
      no EAs → empty, plus the pure wire round-trip.

**Estimated scope:** ~800 LOC production + ~400 LOC tests. *(Actual: ~360 LOC production + ~290 LOC
tests — the QUERY/SET_INFO dispatch, CREATE prologue and access-check infrastructure were already in
place; both features landed behind opt-in seams with no change to `IFileStore` or existing backends.)*

**Phase 9 complete.** Named streams (M9.1) and extended attributes (M9.2) landed with 7 tests, suite
372 → **379 green**.

---

## Phase 10 — Transport hardening

### M10.1 — TLS wrapping (SMB over TLS)

- [ ] Accept TLS connections on a configurable port (default 445 plain, 8445 TLS).
- [ ] Wrap `NetworkStream` in `SslStream` with server certificate configuration.
- [ ] Support mutual TLS (client certificate) for additional authentication.
- [ ] Tests: TLS handshake, encrypted transport, certificate validation.

### M10.2 — SMB over QUIC (Windows Server 2022+ parity)

- [ ] Implement QUIC listener using `System.Net.Quic` (.NET 9+).
- [ ] Map QUIC streams to SMB connections.
- [ ] Certificate-based client authentication (QUIC mandates TLS 1.3).
- [ ] Tests: QUIC transport, stream multiplexing, connection migration.

### M10.3 — SMB compression

- [ ] Parse `SMB2_COMPRESSION_CAPABILITIES` negotiate context (§2.2.3.1.3).
- [ ] Implement `SMB2_COMPRESSION_TRANSFORM_HEADER` framing (chained/unchained).
- [ ] Support algorithms: LZ77, LZ77+Huffman, LZNT1 (Pattern_V1 optional).
- [ ] Compression thresholds: only compress payloads > configurable minimum size.
- [ ] Tests: compress/decompress round-trip, algorithm negotiation, threshold behavior.

**Estimated scope:** ~2,500 LOC production + ~800 LOC tests.

---

## Phase 11 — Quota & advanced file system features

Lower priority features that complete the enterprise feature matrix.

### M11.1 — Quota support

- [ ] Implement `QUERY_QUOTA_INFO` / `SET_QUOTA_INFO` (§2.2.37/39).
- [ ] Define `IQuotaProvider` interface for quota enforcement.
- [ ] Implement `FileSystemQuotaProvider` (delegates to OS quota on NTFS/ZFS).
- [ ] Tests: query quota, exceed quota → `STATUS_DISK_FULL`.

### M11.2 — Reparse point / symlink responses

- [ ] On symlink encounter during path resolution, return
      `STATUS_STOPPED_ON_SYMLINK` with `SYMLINK_ERROR_RESPONSE` error data
      (§2.2.2.2.1) instead of silently resolving.
- [ ] Let the client decide whether to follow the symlink.
- [ ] Tests: symlink in path → proper error response, absolute/relative targets.

### M11.3 — WS-Discovery (network browsing)

- [ ] Implement WSD responder for automatic server discovery in Windows Explorer.
- [ ] Multicast UDP announcement and probe response.
- [ ] Tests: probe → response contains server endpoint.

**Estimated scope:** ~1,200 LOC production + ~500 LOC tests.

---

## Priority matrix

| Phase | Feature | Priority | Impact | Effort |
|-------|---------|----------|--------|--------|
| **1** | Leases | Critical | Performance — all modern clients expect leases | Medium |
| **2** | Kerberos / AD | Critical | Enterprise auth — blocks AD domain deployment | High |
| **3** | Security descriptors / ACLs | Critical | Per-file permissions — core enterprise requirement | High |
| **4** | Durable / persistent handles | Critical | Reliability — reconnect after network interruption | Medium |
| **5** | Server-side copy & FSCTLs | High | Performance — eliminates double transfer for copies | Low |
| **6** | Multichannel | High | Throughput & failover — multi-NIC aggregation | High |
| **7** | DFS referrals | High | Namespace — distributed storage spanning servers | Medium |
| **8** | Operational readiness | High | Production — logging, timeouts, rate limiting | Medium |
| **9** | Alternate data streams / EA | Medium | Compatibility — macOS resource forks, metadata | Low |
| **10** | Transport hardening | Medium | Security — TLS, QUIC, compression | High |
| **11** | Quota & advanced FS | Low | Completeness — quota, reparse, discovery | Low |

---

## Dependency graph

```
Phase 1 (Leases) ──────────────────────┐
                                        ├──▶ Phase 4 (Durable Handles)
Phase 2 (Kerberos) ─┐                  │         requires lease state for reconnect
                     ├──▶ Phase 3 (ACLs)│
                     │    requires SIDs  │
                     │                   ├──▶ Phase 6 (Multichannel)
                     │                   │         requires session binding
Phase 8 (Ops) ───────┘                  │
  can start independently               │
                                        ├──▶ Phase 7 (DFS)
Phase 5 (FSCTLs) ──────────────────────┘         can start independently
  can start independently

Phase 9  (ADS/EA)     ──── independent
Phase 10 (Transport)  ──── independent (QUIC requires .NET 9+)
Phase 11 (Quota)      ──── independent
```

---

## Status journal

> Update this section as milestones are completed. Format:
> `[YYYY-MM-DD] Phase X / M.X.Y — status — notes`

| Date | Milestone | Status | Notes |
|------|-----------|--------|-------|
| 2026-07-06 | Roadmap created | Complete | Baseline: M1–M5 core + async I/O + security audit done |
| 2026-07-06 | Phase 1 / M1.1 | Complete | Lease state model, context parse/serialize, InMemoryLeaseManager; 18 tests, full suite 175 green |
| 2026-07-06 | Phase 1 / M1.2 | Complete (break-before-grant deferred) | Lease grant on the wire (CREATE parses "RqLs", echoes granted state), LEASE_BREAK notification + acknowledgment + response, release at CLOSE/teardown; 5 dispatcher tests, full suite 180 green. Blocking break-before-grant wait deferred (same simplification as classic oplocks). |
| 2026-07-07 | Phase 1 / M1.3 | Complete | Directory leases: `LeaseHolder.IsDirectory` tracking, `ILeaseManager.BreakDirectoryLease` + dispatcher `BreakParentDirectoryLease`, hooked into CREATE (add), CLOSE/DeleteOnClose (remove) and SET_INFO rename; RH→R downgrade + epoch bump + out-of-band LEASE_BREAK. `SmbOpen.DeleteOnClose` now kept in sync. 5 dispatcher tests (`DirectoryLeaseTests.cs`), full suite 187 green. |
| 2026-07-07 | Phase 2 / M2.1 | Complete (platform binding = user seam) | Composable `SpnegoNegotiator` (ordered `IGssMechanismFactory` list, mech selection + SPNEGO wrap/unwrap, raw-NTLM path); `NtlmSpnegoNegotiator` now delegates to it. `KerberosServerMechanism` + `KerberosGssToken` framing delegating ticket crypto to injectable `IKerberosTicketValidator`; `Kerberos`/`NtlmMechanismFactory`, `DelegatingKerberosTicketValidator`. SPNEGO parser gained `SupportedMech`; added `SpnegoTokens.CreateNegTokenInit`. 11 tests (`Phase2AuthTests.cs`), full suite 198 green. |
| 2026-07-07 | Phase 2 / M2.2 | Complete | LDAP/AD identity backend, built in 5 tested increments. Core (dependency-free, in `Smb.Auth/Ldap/`): `SidConverter`, `ILdapSearcher`/`LdapEntry`, `LdapIdentityBackendOptions`, `LdapIdentityBackend` (`Resolve`→SID/UPN/tokenGroups, `ISidResolver` reverse lookup, `TtlCache`), `LdapFilter`; `SecurityIdentity.UserPrincipalName` added. Opt-in binding: `Smb.Auth.DirectoryServices` (`DirectoryServicesLdapSearcher` over `System.DirectoryServices.Protocols`). 30 tests (SidConverter 17, backend 9, searcher 4), full suite 228 green. |
| 2026-07-07 | Phase 2 / M2.3 | Complete | NTLM/negotiate hardening (audit O1/O3/O4). O1: NTLM MIC verification in `NtlmServerMechanism` (raw NEGOTIATE/CHALLENGE kept, MIC recomputed + constant-time compared; conditional on `MsvAvFlags`, unconditional under new `NtlmServerOptions.RequireMessageIntegrity`); `NtlmClient` MIC generation for tests. O3: 3.1.1 negotiate without a SHA-512 PreauthIntegrity context → `INVALID_PARAMETER`. O4: `SESSION_SETUP` before `NEGOTIATE` → `INVALID_PARAMETER`. 11 tests (`NtlmMicTests` 6, `AuthHardeningTests` 5), full suite 239 green. **Phase 2 complete.** |
| 2026-07-07 | Phase 3 / M3.1 | Complete | Security-descriptor model in `Smb.Protocol.Security`: `Sid`, `Ace`/`Acl`, self-relative `SecurityDescriptor`, `WellKnownSids`, plus the pure `AccessCheck` evaluator (MS-DTYP §2.5.3.2). 25+ tests. |
| 2026-07-07 | Phase 3 / M3.2 | Complete | QUERY/SET_SECURITY over the dispatcher; `IFileStore.Get/SetSecurityAsync` (default NotSupported), `LocalFileStore` via the pluggable `ISecurityDescriptorStore` (default in-memory, permissive fallback). 3 dispatcher tests, suite 267 green. |
| 2026-07-07 | Phase 3 / M3.3 | Complete | Access-check enforcement. CREATE evaluates the file DACL against the caller's SIDs (generic→specific mapping via `AccessMask.MapGenericToSpecific`), caps `SmbOpen.GrantedAccess`, rolls back on denial; NotSupported backends fall back to share-level only. Per-op enforcement on READ (`FILE_READ_DATA`), WRITE (`WRITE`/`APPEND`), SET_INFO delete/rename (`DELETE`) and EOF (`FILE_WRITE_DATA`). ACE inheritance for new entries (`AclInheritance.ComputeInherited`) wired into `LocalFileStore`. 12 tests (`AclInheritanceTests` 7, `AccessEnforcementTests` 5), full suite 287 green. **Phase 3 complete.** |
| 2026-07-07 | Phase 4 / M4.1 | Complete | Durable handles v1. `DurableHandleMessages` (DHnQ/DHnC parse/serialize); grant gated on batch/exclusive oplock or handle-lease (`DurabilityAllowed`), stable persistent FileId (`AllocatePersistentId`); `OnConnectionClosed` preserves durable opens in `IDurableHandleStore` with a `TimeProvider`-based deadline; reconnect restores by FileId + principal; `ScavengeDurableHandles` releases expired. `SmbOpen.Session/TreeConnect/PersistentFileId` now settable for re-attach. 11 tests (`DurableHandleTests` 5, `DurableHandleMessagesTests` 6), suite 298 green. |
| 2026-07-07 | Phase 4 / M4.2 | Complete | Durable/persistent v2. DH2Q/DH2C (create GUID, requested timeout, persistent flag); `IShare.ContinuousAvailability` gates persistent handles (else downgraded); persistent never scavenged; cross-session reconnect (global store, validated by FileId+GUID+principal); `ResolveDurableTimeout` clamps to `MaxDurableHandleTimeout` (16 min). 4 v2 dispatcher tests, suite 302 green. |
| 2026-07-07 | Phase 4 / M4.3 | Complete | `IDurableHandleStore` seam + `InMemoryDurableHandleStore` (default) — introduced in M4.1, documented in M4.3 for out-of-process (SQLite/Redis) stores incl. the rehydrate-live-`SmbOpen`-in-`TryClaim` contract for restart survival. **Phase 4 complete (in-process); cross-restart persistence is a documented extension point.** |
| | Phase 4 / M4.2 | Not started | |
| | Phase 4 / M4.3 | Not started | |
| 2026-07-07 | Phase 5 / M5.1 | Complete | Server-side copy. `CopyChunkMessage` (resume-key + SRV_COPYCHUNK_COPY / _RESPONSE, pure); FSCTL_SRV_REQUEST_RESUME_KEY assigns `SmbOpen.ResumeKey`; FSCTL_SRV_COPYCHUNK(_WRITE) locates the source by key in the session, enforces §2.2.31.1 limits (maxima on violation), copies chunks. Optional `IFileStore.CopyRangeAsync` offload seam preferred for same-store copies, else a 64 KiB read/write fallback (spans shares). 7 tests (`CopyChunkTests.cs`), full suite 309 green. |
| 2026-07-07 | Phase 5 / M5.2 | Complete | Additional FSCTLs. Pure wire in `FsctlMessage` (set-sparse / zero-data / allocated-ranges structs, FSCTL codes); two opt-in seams `ISparseFileStore` + `IReparsePointStore` (checked with `is`). SET_SPARSE/SET_ZERO_DATA/QUERY_ALLOCATED_RANGES, GET/SET/DELETE_REPARSE_POINT (opaque buffer, NOT_A_REPARSE_POINT/NOT_SUPPORTED defaults), DFS_GET_REFERRALS → NOT_FOUND stub. Access-gated; output capped to MaxOutputResponse. New NtStatus `NotFound`/`NotAReparsePoint`. 10 tests (`AdditionalFsctlTests.cs`). |
| 2026-07-07 | Phase 5 / M5.3 | Complete | FSCTL_VALIDATE_NEGOTIATE_INFO hardening (was unhandled). Parses the request and compares capabilities / client GUID / security mode / negotiated dialect against the connection's negotiated state; mismatch → new `SmbConnection.MustTerminate` flag, no reply, host drops the connection; match → server info (signed). `HandleIoctlAsync` now returns `ResponseSegment?`. 5 tests (`ValidateNegotiateTests.cs`). **Phase 5 complete — suite 324 green.** |
| 2026-07-07 | Phase 6 / M6.1 | Complete | Session binding (multichannel). `SmbChannel` + `SmbSession.Channels`/`SigningKeyFor`, primary channel registered on login; `HandleSessionBinding` validates (dialect/ClientGuid/Valid/not-already-bound), verifies the request signature under the session key, re-runs GSS on a per-connection context (`ChannelBindInProgress`), matches identity, derives a per-channel signing key (3.1.1 uses the channel preauth hash, §3.3.5.5.3). Per-channel sign/verify at `AssembleResponse`/`VerifyInboundSignature`. Channel-aware teardown keeps the session until the last channel closes. New `NtStatus.RequestNotAccepted`. 4 tests (`Phase6BindingTests.cs`), full suite 328 green. |
| 2026-07-07 | Phase 6 / M6.2 | Complete | FSCTL_QUERY_NETWORK_INTERFACE_INFO. Pure `NetworkInterfaceInfoMessage.Build` (152-byte chained entries, IPv4/IPv6 SOCKADDR_STORAGE) in `Smb.Protocol`; seam `INetworkInterfaceProvider` + default `SystemNetworkInterfaceProvider` (NIC enumeration) in `Smb.Server.Multichannel`, injectable via `SmbServerOptions.NetworkInterfaceProvider`. Handler `HandleQueryNetworkInterfaceInfo` (NOT_SUPPORTED when disabled/<3.0, output capped to MaxOutputResponse). `SMB2_GLOBAL_CAP_MULTICHANNEL` advertised on 3.x NEGOTIATE (`EnableMultichannel`, default on). 5 tests (`Phase6InterfaceInfoTests.cs`), suite 333 green. |
| 2026-07-07 | Phase 6 / M6.3 | Complete | Channel failover. `SmbSession.SelectSendChannel(preferred)` + centralized `SendOutOfBandAsync` (selects a live channel BEFORE signing so the per-channel key is right) — wired into lease/oplock break + blocking-LOCK/CHANGE_NOTIFY finals. `OnConnectionClosed` now cancels only pending async ops whose session didn't survive (others complete + reroute); host no longer blanket-cancels. 2 tests (`Phase6FailoverTests.cs`: SelectSendChannel prefer/failover/null; blocking LOCK on a dropping channel granted + delivered on the survivor). **Phase 6 complete — suite 335 green.** |
| 2026-07-08 | Phase 7 / M7.1 | Complete | DFS referral responses. Pure `DfsReferralMessage` (REQ/REQ_EX parse, RESP with V4 non-name-list entries + de-duplicated string pool) in `Smb.Protocol`; `IDfsNamespace` seam + `StandaloneDfsNamespace` (static link table, longest-prefix resolution) in `Smb.Server.Dfs`, injectable via `SmbServerOptions.DfsNamespace`. `HandleDfsGetReferrals` (FSCTL 0x00060194 / _EX 0x000601B0, NOT_FOUND when no namespace / path outside it, output capped to MaxOutputResponse). `IShare.IsDfs` → TREE_CONNECT DFS share flags + `SMB2_SHARE_CAP_DFS` (new `ShareCapabilities` enum); NEGOTIATE advertises `SMB2_GLOBAL_CAP_DFS` when a namespace is set. 11 tests (`DfsReferralTests.cs`), suite 346 green. |
| 2026-07-08 | Phase 7 / M7.2 | Complete | DFS link resolution. CREATE on a DFS-root share whose path is at/below a DFS link → `STATUS_PATH_NOT_COVERED` (new `NtStatus.PathNotCovered`) via `IDfsNamespace.IsLinkCovered`; candidate path reconstructed as `\Server\Share\relative` (`BuildDfsPath`), consistent with the referral request shape. TTL + preference-ordered targets already carried by the referral. 3 tests (link → PATH_NOT_COVERED, root file served locally, non-DFS share ignores the namespace). **Phase 7 complete — suite 349 green.** |
| 2026-07-08 | Phase 8 / M8.1 | Complete | Structured audit logging. `ISmbAuditLogger` seam + `SmbAuditEvent`/`SmbAuditEventType` (Windows-equivalent ids) + `Null`/`Delegating` defaults in `Smb.Server.Diagnostics`, wired via `SmbServerOptions.AuditLogger` (kept dependency-free, not `ILogger`). Emitted at auth success/fail, LOGOFF, TREE_CONNECT grant/deny, CREATE/CLOSE/delete, SET_SECURITY, connection accept/close; `SmbConnection.ClientAddress` added. 8 tests (`AuditLoggingTests`). |
| 2026-07-08 | Phase 8 / M8.2 | Complete | Idle/auth timeouts. `SweepIdleTimeouts`/`ExpireSession` + `SmbSession.LastActivityTicks`, `SmbConnection.LastActivityTicks`/`CreatedTicks`/`RequestClose`; options `SessionIdleTimeout` (15 min), `ConnectionIdleTimeout` (5 min), `AuthenticationTimeout` (30 s), `TimeoutSweepInterval` (30 s); host background sweep loop + per-connection cancellation. 5 tests (`TimeoutTests`, `ManualTimeProvider`). |
| 2026-07-08 | Phase 8 / M8.3 | Complete | Connection admission control. `ConnectionLimiter` (global `MaxConnections` 1024 + per-IP `MaxConnectionsPerClient` 64; ≤0 = unlimited), host `TryAdmit` at accept → immediate close on rejection, `Release` via continuation. Per-connection request rate limiter deferred (optional). 5 tests (`ConnectionLimiterTests`). |
| 2026-07-08 | Phase 8 / M8.4 | Complete | Graceful shutdown/draining. `StopAsync(drainTimeout?)` (default `ShutdownDrainTimeout` 30 s): stop accepting → drain token stops new reads while in-flight finish (reads use drain token, sends/ops the hard token) → wait → force-close; `Smb2Dispatcher.SendShutdownBreaksAsync` breaks caching holders to None first; drain progress logged. 2 tests (`ShutdownDrainTests`: shutdown-break to holder, real-TCP idle drain). |
| 2026-07-08 | Phase 8 / M8.5 | Complete | Health/perf metrics. `SmbServerMetrics` (Interlocked, dependency-free): gauges (active connections/sessions/trees/handles), counters (accepted, auth ok/fail, requests, bytes read/written total+per-share, lock contention), bucketed latency histogram p50/p95/p99, `Snapshot()`→`MetricsSnapshot`. Wired across dispatcher/host; `SmbServer.Metrics`. `virtual` methods for OTel bridging (no forced dep). 3 tests (`MetricsTests`). **Phase 8 complete — suite 372 green.** |
| 2026-07-08 | Phase 9 / M9.1 | Complete | Alternate data streams. Opt-in `INamedStreamStore` seam (`OpenNamedStreamAsync` + `QueryStreamsAsync`) instead of widening `IFileStore.CreateAsync`; dispatcher `TrySplitStreamName` splits `file:stream[:$DATA]` and routes named streams (empty name = default data stream → normal open), `NamedStreamHandle` flows through READ/WRITE/SET_INFO. QUERY_INFO `FileStreamInformation` (§2.4.43) via `HandleQueryStreamsAsync` (non-ADS backend → default `::$DATA` only). `LocalFileStore` in-process stream table (base path + case-folded name), delete-on-close removes only the stream, streams share the base file's SD. Pure `StreamInformation` builder. |
| 2026-07-08 | Phase 9 / M9.2 | Complete | Extended attributes. Opt-in `IExtendedAttributeStore` seam (`Get/SetExtendedAttributesAsync`); QUERY/SET_INFO `FileFullEaInformation` (§2.4.15) via `HandleQueryEaAsync` (FILE_READ_EA) / `HandleSetEaAsync` (FILE_WRITE_EA), zero-length value = delete. Pure `FullEaInformation` builder/parser + `ComputeEaSize`. `LocalFileStore` in-process EA table (physical-path keyed, add/replace/delete merge); non-EA backend → no EAs / `NOT_SUPPORTED` on write. 7 tests (`Phase9StreamsAndEaTests`). **Phase 9 complete — suite 379 green.** |
| | Phase 10 / M10.1 | Not started | |
| | Phase 10 / M10.2 | Not started | |
| | Phase 10 / M10.3 | Not started | |
| | Phase 11 / M11.1 | Not started | |
| | Phase 11 / M11.2 | Not started | |
| | Phase 11 / M11.3 | Not started | |
