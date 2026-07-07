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

### M3.1 — Security descriptor model

- [ ] Define `SecurityDescriptor`, `Acl`, `Ace` types in `Smb.Protocol` (NT SID
      format, DACL/SACL, ACE types: ACCESS_ALLOWED, ACCESS_DENIED, SYSTEM_AUDIT).
- [ ] Implement binary serialization/deserialization (self-relative format,
      MS-DTYP §2.4.6).
- [ ] Tests: round-trip known descriptors, parse Windows-generated SD blobs.

### M3.2 — QUERY_SECURITY_INFO / SET_SECURITY_INFO

- [ ] Implement `SmbCommand.QueryInfo` with `InfoType.Security` (§2.2.37):
      return the security descriptor of an open handle.
- [ ] Implement `SmbCommand.SetInfo` with `InfoType.Security` (§2.2.39):
      modify owner, group, DACL, SACL.
- [ ] Extend `IFileStore` with `GetSecurityAsync` / `SetSecurityAsync`.
- [ ] Implement in `LocalFileStore` by reading/writing NTFS ACLs (Windows) or
      extended attributes / POSIX ACLs (Linux/ZFS).
- [ ] Tests: read SD, modify DACL, verify access denied after ACE removal.

### M3.3 — Access check enforcement

- [ ] On CREATE, evaluate the file's DACL against the authenticated user's SIDs
      (primary + group) to determine the effective `MaximalAccess`.
- [ ] Enforce access mask on READ, WRITE, DELETE, SET_INFO operations.
- [ ] Inheritance: new files/directories inherit ACEs from parent directory.
- [ ] Tests: user with read-only ACE cannot write, inherited ACEs apply, deny ACE
      overrides allow ACE.

**Estimated scope:** ~2,000 LOC production + ~800 LOC tests.

---

## Phase 4 — Durable & persistent handles

Handles that survive network interruptions are essential for enterprise reliability
(laptop standby, Wi-Fi roaming, brief outages).

### M4.1 — Durable handles (v1, SMB 2.x)

- [ ] Parse `SMB2_CREATE_DURABLE_HANDLE_REQUEST` / `_RECONNECT` create contexts.
- [ ] On CREATE with durable request: persist the `SmbOpen` state (file path, access,
      share mode, lease key, position) in a `DurableHandleStore`.
- [ ] On TCP disconnect: do not release durable opens; start a configurable timeout
      (default 60 s).
- [ ] On reconnect with `DURABLE_HANDLE_RECONNECT`: restore the open, verify
      identity match, resume.
- [ ] On timeout expiry: release the open normally (close handle, release locks).
- [ ] Tests: disconnect → reconnect within timeout succeeds, expired handle returns
      `STATUS_OBJECT_NAME_NOT_FOUND`, identity mismatch rejected.

### M4.2 — Resilient handles (SMB 3.0)

- [ ] Parse `SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2` / `_RECONNECT_V2` contexts.
- [ ] Support `CREATE_FLAG_PERSISTENT` for persistent handles (CA shares).
- [ ] Resilient handles survive across sessions (not just connections).
- [ ] Timeout configurable via `SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2.Timeout`.
- [ ] Tests: session-level reconnect, persistent handle across full server restart
      (requires serializable handle store).

### M4.3 — Persistent handle store interface

- [ ] Define `IDurableHandleStore` interface for persisting handle state beyond
      process lifetime (needed for server restart resilience).
- [ ] Implement `InMemoryDurableHandleStore` (default, survives TCP drops but not
      process restart).
- [ ] Document the interface for external implementations (SQLite, Redis, etc.).

**Estimated scope:** ~1,800 LOC production + ~700 LOC tests.

---

## Phase 5 — Server-side copy & FSCTL extensions

Server-side copy (`FSCTL_SRV_COPYCHUNK`) eliminates double network transfer for
file copies. Additional FSCTLs are required by Windows Explorer and common tools.

### M5.1 — FSCTL_SRV_COPYCHUNK / COPYCHUNK_WRITE

- [ ] Parse `SRV_COPYCHUNK_COPY` input buffer (source key, chunk array).
- [ ] Implement copy logic in `Smb2Dispatcher`: read from source handle, write to
      destination handle, return chunk results.
- [ ] Extend `IFileStore` with optional `CopyRangeAsync` for backends that support
      native copy offload (e.g., `copy_file_range` on Linux, `FSCTL_DUPLICATE_EXTENTS`
      on NTFS).
- [ ] Fallback: user-space read/write loop when backend does not support offload.
- [ ] Tests: copy within same share, cross-share copy, partial chunk, overlapping
      ranges, large file (>4 GB).

### M5.2 — Additional FSCTLs

- [ ] `FSCTL_SET_ZERO_DATA` — sparse file zero fill.
- [ ] `FSCTL_QUERY_ALLOCATED_RANGES` — report allocated extents.
- [ ] `FSCTL_SET_SPARSE` — mark file as sparse.
- [ ] `FSCTL_GET_REPARSE_POINT` / `FSCTL_SET_REPARSE_POINT` — reparse point
      (symlink) support with `STATUS_STOPPED_ON_SYMLINK` error data.
- [ ] `FSCTL_DFS_GET_REFERRALS` — stub returning `STATUS_NOT_FOUND` (no DFS) or
      referral response (if DFS is implemented in Phase 7).
- [ ] Tests per FSCTL: valid input, invalid input, unsupported → `STATUS_NOT_SUPPORTED`.

### M5.3 — FSCTL_VALIDATE_NEGOTIATE_INFO hardening

- [ ] Verify the existing implementation matches §3.3.5.15.12 completely.
- [ ] Reject dialect/capability/GUID mismatches with connection termination.
- [ ] Test: tampered validate-negotiate → connection dropped.

**Estimated scope:** ~1,000 LOC production + ~500 LOC tests.

---

## Phase 6 — Multichannel (SMB 3.0+)

Multichannel binds multiple TCP connections to a single SMB session for
throughput aggregation and failover.

### M6.1 — Session binding

- [ ] Accept `SMB2_SESSION_SETUP` with `SMB2_SESSION_FLAG_BINDING` flag on a
      second TCP connection.
- [ ] Verify the binding request's signature using the session's signing key.
- [ ] Share session state (identity, encryption keys, tree connects, opens)
      across bound connections.
- [ ] Tests: establish session on conn A, bind on conn B, access open from conn B.

### M6.2 — Interface discovery (FSCTL_QUERY_NETWORK_INTERFACE_INFO)

- [ ] Implement `FSCTL_QUERY_NETWORK_INTERFACE_INFO` (§2.2.32.5): return the
      server's network interfaces (IP, link speed, RSS capability).
- [ ] Enumerate system NICs via `NetworkInterface.GetAllNetworkInterfaces()`.
- [ ] Tests: IOCTL returns valid interface list, client can parse it.

### M6.3 — Channel failover

- [ ] When a bound connection drops, ongoing I/O migrates to surviving connections.
- [ ] Pending async operations (LOCK, CHANGE_NOTIFY) survive channel loss if
      another channel remains.
- [ ] Tests: drop one of two channels, verify session and opens survive.

**Estimated scope:** ~1,500 LOC production + ~600 LOC tests.

---

## Phase 7 — DFS (Distributed File System) referrals

DFS allows a single namespace to span multiple servers. Required for enterprise
environments with distributed storage.

### M7.1 — DFS referral responses

- [ ] Implement `FSCTL_DFS_GET_REFERRALS` / `_V2` in the IOCTL handler.
- [ ] Define `IDfsNamespace` interface: resolve DFS path → target server/share.
- [ ] Implement `StandaloneDfsNamespace` (single-server DFS root, static mapping).
- [ ] Set `SMB2_SHARE_CAP_DFS` and `SMB2_SHAREFLAG_DFS` / `_DFS_ROOT` flags on
      DFS-enabled shares in TREE_CONNECT response.
- [ ] Tests: client requests referral, receives target list, follows referral.

### M7.2 — DFS link resolution

- [ ] Intercept `STATUS_PATH_NOT_COVERED` from the file store and return a DFS
      referral instead.
- [ ] Support referral TTL and priority/ordering for load balancing.
- [ ] Tests: access through DFS link, expired referral triggers re-request.

**Estimated scope:** ~800 LOC production + ~400 LOC tests.

---

## Phase 8 — Operational readiness

Enterprise file servers require structured logging, timeouts, rate limiting,
and graceful lifecycle management.

### M8.1 — Structured audit logging

- [ ] Replace `Action<string>?` logger with `ILogger` (Microsoft.Extensions.Logging)
      or a similar structured logging interface.
- [ ] Define log event IDs for security-relevant operations:
  - Authentication success/failure (event 4624/4625 equivalent)
  - Share access granted/denied
  - File open/close/delete
  - Permission change
  - Session establish/teardown
- [ ] Include structured fields: timestamp, user, client IP, share, file path,
      action, result.
- [ ] Tests: verify log events emitted for key operations.

### M8.2 — Session & connection timeouts

- [ ] Implement idle session timeout: sessions without activity for a configurable
      period (default 15 min) are torn down (opens closed, locks released).
- [ ] Implement idle connection timeout: TCP connections without any SMB traffic
      for a configurable period (default 5 min) are closed.
- [ ] Implement authentication timeout: SESSION_SETUP must complete within a
      configurable window (default 30 s) or the connection is dropped.
- [ ] Tests: idle session expires, idle connection closes, slow auth times out.

### M8.3 — Connection rate limiting & DoS protection

- [ ] Add per-IP connection rate limiter (configurable max connections per IP,
      default 64).
- [ ] Add global connection limit (configurable, default 1024).
- [ ] Add per-connection request rate limiter (optional, disabled by default).
- [ ] Reject excess connections with TCP RST (do not allocate state).
- [ ] Tests: exceed per-IP limit → rejected, global limit → rejected.

### M8.4 — Graceful shutdown & connection draining

- [ ] On `StopAsync()`, stop accepting new connections but allow existing
      connections to finish in-flight operations (configurable drain timeout,
      default 30 s).
- [ ] Send `SMB2_OPLOCK_BREAK` / lease break to all holders before closing handles.
- [ ] Log connection drain progress.
- [ ] Tests: shutdown during active I/O, all operations complete or time out.

### M8.5 — Health & performance metrics

- [ ] Expose counters via a `SmbServerMetrics` class:
  - Active connections, sessions, tree connects, open handles
  - Bytes read/written (per share, total)
  - Authentication attempts (success/failure)
  - Lock contention count
  - Request latency histogram (p50, p95, p99)
- [ ] Optional integration with `System.Diagnostics.Metrics` (OpenTelemetry).
- [ ] Tests: verify counters increment on operations.

**Estimated scope:** ~2,000 LOC production + ~600 LOC tests.

---

## Phase 9 — Alternate data streams & extended attributes

macOS clients use alternate data streams for resource forks and Finder metadata.
Windows tools may use named streams for thumbnails and zone identifiers.

### M9.1 — Named stream support in IFileStore

- [ ] Extend `IFileStore.CreateAsync` to accept stream names (`file.txt:stream`).
- [ ] Implement stream enumeration (`FileStreamInformation`, §2.4.43).
- [ ] Implement in `LocalFileStore`: delegate to OS stream support (NTFS on Windows,
      xattr on Linux/macOS, or user-space sidecar files for ZFS).
- [ ] Tests: create/read/write/delete named streams, enumerate streams.

### M9.2 — Extended attribute support

- [ ] Implement `QUERY_INFO` / `SET_INFO` for `FileFullEaInformation` (§2.4.15).
- [ ] Extend `IFileStore` with `GetExtendedAttributesAsync` / `SetExtendedAttributesAsync`.
- [ ] Implement in `LocalFileStore` via OS xattr APIs.
- [ ] Tests: set/get/list/delete EA entries.

**Estimated scope:** ~800 LOC production + ~400 LOC tests.

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
| | Phase 2 / M2.2 | Not started | |
| | Phase 2 / M2.3 | Not started | |
| | Phase 3 / M3.1 | Not started | |
| | Phase 3 / M3.2 | Not started | |
| | Phase 3 / M3.3 | Not started | |
| | Phase 4 / M4.1 | Not started | |
| | Phase 4 / M4.2 | Not started | |
| | Phase 4 / M4.3 | Not started | |
| | Phase 5 / M5.1 | Not started | |
| | Phase 5 / M5.2 | Not started | |
| | Phase 5 / M5.3 | Not started | |
| | Phase 6 / M6.1 | Not started | |
| | Phase 6 / M6.2 | Not started | |
| | Phase 6 / M6.3 | Not started | |
| | Phase 7 / M7.1 | Not started | |
| | Phase 7 / M7.2 | Not started | |
| | Phase 8 / M8.1 | Not started | |
| | Phase 8 / M8.2 | Not started | |
| | Phase 8 / M8.3 | Not started | |
| | Phase 8 / M8.4 | Not started | |
| | Phase 8 / M8.5 | Not started | |
| | Phase 9 / M9.1 | Not started | |
| | Phase 9 / M9.2 | Not started | |
| | Phase 10 / M10.1 | Not started | |
| | Phase 10 / M10.2 | Not started | |
| | Phase 10 / M10.3 | Not started | |
| | Phase 11 / M11.1 | Not started | |
| | Phase 11 / M11.2 | Not started | |
| | Phase 11 / M11.3 | Not started | |
