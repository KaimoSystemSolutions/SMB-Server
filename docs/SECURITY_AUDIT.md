# Security / Compliance Audit — Smb.Server

**Audit date:** 2026-06-28 · **Code marker:** `[AUDIT-2026-06]` (greppable) · **Suite:** 150 tests green

This document is the auditable ledger. Each finding has a stable ID
(`H#` = high, `M#` = medium, `L#` = low, `O#` = open/deliberately deferred). Fixed findings
are marked in code with `[AUDIT-2026-06]` and backed by a regression test.

How to find everything:

```bash
grep -rn "AUDIT-2026-06" src tests          # all affected locations
dotnet test --filter FullyQualifiedName~AuditFixTests   # the fix regression tests
```

> **How to maintain this document:** When an open finding (`O#`) is addressed, update its status
> here, set the code marker, and add a test. If a fix is reverted, the associated test will fail —
> the "Re-verification" line names it.

---

## Fixed

### H1 — Unbounded outstanding async operations (DoS)
- **Risk:** A client could keep arbitrarily many blocking `LOCK`/`CHANGE_NOTIFY` requests open; each
  holds a `PendingRequest` (+ possibly a `FileSystemWatcher`) → memory/handle exhaustion.
- **Cause:** `CreditManager.IsWithinWindow`/`ComputeCreditCharge` were dead code; no limit on
  outstanding operations at all.
- **Fix:** New option `SmbServerOptions.MaxOutstandingRequests` (default 512). `HandleLock`
  (blocking branch) and `HandleChangeNotify` reject with `STATUS_INSUFFICIENT_RESOURCES` when
  the limit is reached.
- **Files:** `SmbServerOptions.cs`, `Smb2Dispatcher.Locking.cs`, `Smb2Dispatcher.Notification.cs`,
  `NtStatus.cs` (new code `InsufficientResources = 0xC000009A`).
- **Re-verification:** `AuditFixTests.OutstandingAsyncRequests_AreCappedPerConnection`.

### H2 — MessageId sequence window not enforced
- **Risk:** Replays and wildly jumping MessageIds were accepted (anti-replay only via signature,
  which allows an identical frame to be validly replayed). MS-SMB2 §3.3.5.2.3.
- **Cause:** `SequenceWindowStart/Size` were set but never read; `IsWithinWindow` unused.
- **Fix:** `Smb2Dispatcher.ValidateSequence` checks each MessageId against `[Start, Start+Size)` and
  advances the lower bound (requests arrive monotonically per connection). **Excluded** (deliberately):
  before completed NEGOTIATE, NEGOTIATE itself, CANCEL (references an already-consumed
  MessageId), related compound elements.
- **Files:** `Smb2Dispatcher.cs` (`ValidateSequence`, call in `DispatchOne`).
- **Re-verification:** `AuditFixTests.SequenceWindow_RejectsReplayedAndOutOfWindowMessageId`.
- **Known simplification:** constant window size (= `MaxCreditsPerResponse`) instead of exact,
  set-based credit accounting. Sufficient for TCP-ordered single-connection clients;
  a bitmap-exact implementation (true credit extension) remains open → see O6.

### H3 — `MaximalAccess` from authorization policy ignored at CREATE
- **Risk:** `GrantedAccess = DesiredAccess` unfiltered → a policy with reduced rights
  (e.g. `ReadOnly` per user/group) was **ineffective** for file operations; only the global
  `readOnly` flag of the FileStore limited access.
- **Fix:** `HandleCreate` compares the DesiredAccess (at the intent level Read/Write/Delete) against
  `tree.MaximalAccess` and rejects with `STATUS_ACCESS_DENIED` if more is requested than granted.
  `MAXIMUM_ALLOWED` grants exactly the permitted mask.
- **Files:** `Smb2Dispatcher.FileCommands.cs` (`HandleCreate`).
- **Re-verification:** `AuditFixTests.Create_WriteAccess_DeniedWhenPolicyGrantsReadOnly`,
  `…_AllowedWhenPolicyGrantsReadWrite`.

### H4 — Symlink sandbox escape in LocalFileStore
- **Risk:** `LocalFileStore.TryResolve` only checked the string canonicalization (`Path.GetFullPath` +
  prefix check). `GetFullPath` **does not follow symlinks** — a symlink *inside* the share pointing
  outside passed the prefix check and was followed by the OS on open → reading/writing
  outside the share root. Especially critical on Unix/ZFS (TrueNAS), where unprivileged symlinks
  are the default. (Corrects the earlier claim "path traversal protection … no gap", which only
  covered `..`/slashes/drive-relative paths, not symlinks.)
- **Fix:** Second gate `IsWithinRealRoot` after the string check: `TryResolveRealPath` resolves the real
  path by following the reparse point/symlink at **every existing component** (manual
  `realpath` via `FileSystemInfo.ResolveLinkTarget(returnFinalTarget: true)`), and checks
  containment against the equally resolved root `_realRoot`. Fail-closed: unresolvable (cyclic/
  broken/error) → `null` → access denied. Non-existent final segments (file to be created)
  contain no link and are appended unchanged.
- **Files:** `LocalFileStore.cs` (`TryResolve`, `IsWithinRealRoot`, `TryResolveRealPath`, `_realRoot`).
- **Re-verification:** `SymlinkSandboxTests` (escape via directory **and** file symlink denied;
  normal in-root access and access under a symlink-linked root still allowed). Linux CI
  tests with real symlinks; on Windows without Developer Mode a junction fallback is used.

### O2 — QUERY_DIRECTORY without paging + unstable FileId (fixed)
- **Risk:** The entire listing was serialized into a single buffer; if it did not fit in the client's
  `OutputBufferLength` → `INVALID_PARAMETER` instead of paging → **large directories not
  listable**. Additionally `Name.GetHashCode()` as FileId/IndexNumber (process-randomized, collision-prone).
- **Fix:** `FsccStructures.BuildDirectoryListing(…, maxBytes, out written)` fills budget-precisely; the
  dispatcher snapshots the listing at scan start (`SmbOpen.DirectoryListing`/`DirectoryCursor`) and
  delivers it **page by page** over multiple QUERY_DIRECTORY calls (RESTART_SCAN/SINGLE_ENTRY honored;
  empty follow-up → `NO_MORE_FILES`; not even one entry fits → `INFO_LENGTH_MISMATCH`). Stable
  FileId: new `FileEntryInfo.IndexNumber`, set by the backend (`LocalFileStore` → `PathId`, FNV-1a
  over the full path instead of randomized hash).
- **Files:** `FsccStructures.cs`, `Smb2Dispatcher.FileCommands.cs` (`HandleQueryDirectory`, `ToStat`),
  `SmbOpen.cs`, `FileSystemTypes.cs`, `LocalFileStore.cs` (`PathId`), `NtStatus.cs` (`InfoLengthMismatch`).
- **Re-verification:** `QueryDirectoryPagingTests` (paging over multiple pages, single entry, buffer too
  small → INFO_LENGTH_MISMATCH); `LocalFileStoreHandleTests.FileId_IsStableAcrossCalls_AndDistinctPerFile`.

### O5 — LocalFileStore without OS handle + ShareAccess not enforced (fixed)
- **Risk:** Each READ/WRITE opened a fresh `FileStream`; the `IFileHandle` held no real
  OS handle. The CREATE `ShareAccess` sharing modes were **not enforced at all** → two clients
  could get "exclusive" access simultaneously → **silent data corruption** (Office/DB-like apps). Also
  handles leaked on abrupt disconnect (opens were never closed).
- **Fix:** (1) `LocalFileHandle` holds **one** persistent `FileStream` per open (READ/WRITE/Flush/SetEOF/
  Rd-while-open via `FileShare.Delete`). (2) New seam `IShareModeManager` (default `InMemoryShareModeManager`)
  enforces the Windows sharing rule **symmetrically** and **portably** — before the backend create (no
  side effect on conflict) → `SHARING_VIOLATION`; deliberately in-process instead of OS `FileShare`, since Unix/ZFS
  (TrueNAS) does not enforce the latter. (3) `Smb2Dispatcher.OnConnectionClosed` + logoff now close
  all opens (handle/lock/oplock/share-mode), no more leaks.
- **Files:** `LocalFileStore.cs`, `Sharing/IShareModeManager.cs`, `Sharing/InMemoryShareModeManager.cs`,
  `SmbServerOptions.cs`, `SmbServerBuilder.cs`, `Smb2Dispatcher.FileCommands.cs` (`HandleCreate`/`HandleClose`/
  `OnConnectionClosed`), `Smb2Dispatcher.cs` (logoff), `SmbConnectionHandler.cs` (teardown), `SmbOpen.cs`.
- **Re-verification:** `ShareModeManagerTests` (compatibility matrix), `LocalFileStoreHandleTests`
  (roundtrip/DeleteOnClose/rename-while-open), `QueryDirectoryPagingTests` (SHARING_VIOLATION + release after CLOSE).
- **Remaining point:** OS `FileShare` is opened permissively (`ReadWrite|Delete`); the sharing semantics
  intentionally reside in `IShareModeManager` (cluster/cross-protocol capable via custom implementation).

### M1 — AEAD nonce random instead of counter
- **Risk:** MS-SMB2 §3.3.4.1.4 requires a nonce that is unique and monotonically increasing per
  `EncryptionKey`. A random 11/12-byte value runs into the birthday bound; with AES-GCM,
  nonce reuse is catastrophic.
- **Fix:** Session-local counter `SmbSession.NextEncryptionNonce()`; host builds the nonce from it
  (`BuildNonce`, LE in the first 8 bytes). Unique per session/key.
- **Files:** `SmbSession.cs`, `SmbConnectionHandler.cs`.
- **Re-verification:** via `PerShareEncryptionTests`/`TransformAndPreauthTests` (roundtrip remains
  valid). **Open:** no test that directly checks the *monotonicity/uniqueness* of two consecutive
  nonces (not accessible via the public host API) → see O7.
- **Residual risk:** Counter overflow at 2⁶⁴ messages/session not handled (practically irrelevant).

### M2 — Signing requirement was permanently disabled by encryption (downgrade)
- **Risk:** The host set `session.SigningRequired = false` *permanently* after the first decrypted
  frame. If `RejectUnencryptedAccess` was off, the session then accepted **unsigned
  plaintext commands** → downgrade.
- **Fix:** Signing and encryption status are decoupled. `session.SigningRequired` is no longer
  modified. Instead, `VerifyInboundSignature` skips the signature check **only for the
  currently encrypted-received frame** (`_frameWasEncrypted`), since the AEAD already
  authenticates it (§3.1.4.1). `session.EncryptData = true` (response obligation) remains.
- **Files:** `SmbConnectionHandler.cs`, `Smb2Dispatcher.cs` (`VerifyInboundSignature`,
  `_frameWasEncrypted`).
- **Re-verification:** existing `PerShareEncryptionTests` (encrypted flow remains valid) +
  `DispatcherEndToEndTests.SigningRequired_SignedEchoAccepted_UnsignedRejected` (plaintext requirement
  unchanged).

### M3 — AES-256 cipher keys used the full GSS key as KDK (presumed spec deviation)
- **Risk:** MS-SMB2 §3.3.5.5.3 always truncates `Session.SessionKey` to 16 bytes; §3.1.4.2 uses exactly
  those as KDK for **all** derived keys (only the output length `L` becomes 256). The full GSS key
  as KDK would have produced different keys with Kerberos+AES-256 → interop breakage with Windows.
- **Status:** With NTLM (16-byte key) **functionally equivalent**, therefore latent. Fix addresses it proactively.
- **Fix:** `Smb3KeyDerivation` always uses the 16-byte `SessionKey` for the cipher keys. The
  parameter `fullSessionKey` remains in the signature (deliberately unused).
- **Files:** `Smb3KeyDerivation.cs`, `SmbSession.cs` (docs).
- **Re-verification:** `SigningAndKdfTests.Smb3KeyDerivation_311Aes256_DerivesFrom16ByteSessionKey_NotFullKey`.
- **⚠️ Explicitly re-verify:** Before production Kerberos+AES-256, verify against a **real Windows interop
  capture** (Wireshark/MS-SMB2 test vector) — no official KAT exists for the complete SMB3 key
  derivation in this library.

### M4 — LOGOFF without signature check
- **Risk:** `HandleLogoff` — unlike all other session handlers — did not check the signature; an
  injected LOGOFF could tear down a signing-required session.
- **Fix:** `VerifyInboundSignature` added to `HandleLogoff`.
- **Files:** `Smb2Dispatcher.cs` (`HandleLogoff`, signature extended with `segment`).
- **Re-verification:** `AuditFixTests.Logoff_Unsigned_RejectedWhenSigningRequired`.

### L1 — Dead ternary in `PreauthIntegrityHash.Append`
- `combinedLen <= 4096 ? new byte[combinedLen] : new byte[combinedLen]` (identical branches) →
  simplified. Purely cosmetic. File: `PreauthIntegrityHash.cs`.

### O1 — NTLM MIC not verified (fixed 2026-07-07, Phase 2 / M2.3)
- **Risk:** Without MIC verification, a MITM could tamper with the NTLM NEGOTIATE flags (a downgrade)
  undetected — `NtlmCryptography.ComputeMic` existed but was never called server-side.
- **Fix:** `NtlmServerMechanism` retains the raw NEGOTIATE and CHALLENGE messages and, in
  `HandleAuthenticate`, recomputes MIC = `HMAC_MD5(ExportedSessionKey, NEGOTIATE ‖ CHALLENGE ‖
  AUTHENTICATE-with-zero-MIC)` and compares it in constant time (`FixedTimeEquals`). Verified whenever
  the client announces a MIC via `MsvAvFlags` (bit 0x2); unconditionally when the new
  `NtlmServerOptions.RequireMessageIntegrity` is set. A present-but-invalid MIC is always rejected.
- **Files:** `NtlmServerMechanism.cs` (`_negotiateMessage`/`_challengeMessage`, `ClientAnnouncedMic`,
  `VerifyMic`, `RequireMessageIntegrity`), `NtlmClient.cs` (optional MIC generation for tests).
- **Re-verification:** `NtlmMicTests` (valid accepted, tampered MIC rejected, tampered negotiate flags
  detected, strict-mode accept/reject, compat without MIC).

### O3 — 3.1.1 NEGOTIATE preauth context not validated (fixed 2026-07-07, Phase 2 / M2.3)
- **Risk:** §3.3.5.4 requires a client offering SMB 3.1.1 to send a PreauthIntegrityCapabilities
  context; without it the preauth-integrity hash has no agreed algorithm.
- **Fix:** `Smb2Dispatcher.HandleNegotiate` rejects a 3.1.1-offering request lacking a PreauthIntegrity
  context that lists SHA-512 with `STATUS_INVALID_PARAMETER` (`HasSupportedPreauthContext`).
- **Files:** `Smb2Dispatcher.cs`.
- **Re-verification:** `AuthHardeningTests.Negotiate311_WithoutPreauthContext_IsRejected` (+ 3.0 unaffected).

### O4 — SESSION_SETUP before NEGOTIATE not rejected (fixed 2026-07-07, Phase 2 / M2.3)
- **Risk:** Acting on a SESSION_SETUP before a dialect/security state exists is undefined behavior.
- **Fix:** `HandleSessionSetup` rejects with `STATUS_INVALID_PARAMETER` when `connection.NegotiateDone`
  is false.
- **Files:** `Smb2Dispatcher.cs`.
- **Re-verification:** `AuthHardeningTests.SessionSetup_BeforeNegotiate_IsRejected`.

---

## Open (deliberately deferred — review when convenient)

| ID | Topic | Risk | Recommendation |
|----|-------|------|----------------|
| **O6** | **Credit accounting** is a constant window size, not exact set-based extension (see H2) | Low precision vs. spec; non-critical for single-connection | Bitmap-exact sequence window + dynamic credit extension. |
| **O7** | **No direct test** of AEAD nonce monotonicity (see M1) | Test gap | Make nonce counter checkable via a test-visible interface. |

> **O1, O3, O4 fixed 2026-07-07** (Phase 2 / M2.3) — see the *Fixed* section above.

---

## Reviewed & OK (no action needed)

- **Crypto core** verified against official vectors: AES-CMAC (RFC 4493), MD4 (RFC 1320),
  NTOWFv2 (MS-NLMP §4.2.2); sign/verify + tamper for all three algorithms.
- **Preauth integrity ordering** (include request/intermediate response, exclude final response) correct.
- **Path traversal protection** (`LocalFileStore.TryResolve`): canonicalization + prefix check (`..`,
  forward slashes, drive-relative paths) **and** symlink-resolved real-path containment (see H4).
- **Byte-range lock manager**: overflow-safe overlap (`UInt128`), atomic multi-locks,
  race-safe `NotifyOnce` for CHANGE_NOTIFY.
- **Compound signing** per segment (including padding) correct.
