# SMB-Server

**A SMB 2/3 server library - written in C# (.NET 9)**

This is a library specifically build, for implementing / creating your own SMB Fileserver.
The library was created based on the official Microsoft Specifications (MS-ERREF, MS-FSCC, MS-NLMP, MS-SMB2, ...)

[![CI](https://github.com/KaimoSystemSolutions/SMB-Library/actions/workflows/ci.yml/badge.svg)](https://github.com/KaimoSystemSolutions/SMB-Library/actions/workflows/ci.yml)

## What it does

- :file_folder: **File shares** with full NTFS semantics (read, write, rename, delete, locking).
- :closed_lock_with_key: **Secure by default** - signing required, optional per-share encryption, guest/anonymous rejected.
- :key: **Real login** via NTLMv2; the user source (local, LDAP/AD …) is freely pluggable.
- :jigsaw: **Modular** - plug in your own file backend, auth, lock manager or directory watcher.

## Installation

The library is available via download of the source files or as nuget package.
URL is coming...

## Using the library

You will find an example with different usages under /examples.

# More background

The rest of this document is a technical reference for contributors and the curious. You don't need
it for normal use of the library.

## Architecture

Strict *Parse ↔ State ↔ Effect* layering - each layer its own project, no cycles:

| Project | Contents |
|---|---|
| **Smb.Protocol** | Pure wire types: NBSS framing, SMB2 header (sync/async), enums, Negotiate/SessionSetup/TreeConnect/Echo, transform header. Span-based, little-endian. No I/O, no state. |
| **Smb.Crypto** | Signing (HMAC-SHA256 / AES-CMAC / AES-GMAC), AEAD transform (AES-CCM/GCM 128/256), SP800-108 KDF, SMB 3 key derivation, SHA-512 preauth hash, MD4 + NTLMv2 crypto. |
| **Smb.Auth** | GSS/SPNEGO abstraction: `IGssMechanism`, `ISpnegoNegotiator`, `IIdentityBackend`. SPNEGO token encoding (ASN.1 DER), OIDs, in-memory backend, dev negotiator. |
| **Smb.FileSystem** | `IShare` / `IFileStore` backend abstraction (NTFS semantics over any backend). Async-first (`ValueTask`/`Memory`); purely synchronous backends attach via `SyncFileStore` (see `docs/ASYNC_IO_ROADMAP.md`). |
| **Smb.Server** | State model (Connection/Session/TreeConnect/Open), credit logic, negotiate processor, command dispatcher (receive pipeline). |
| **Smb.Host** | TCP listener (default 445), per-connection read loop, NBSS/transform handling, fluent builder. |

Foundation and fact-check: [`SMB2-3_Server_Context.md`](../SMB2-3_Server_Context.md).

### Modular authentication

SESSION_SETUP talks **only** to `ISpnegoNegotiator`. New mechanisms = register a new `IGssMechanism`;
new identity source (e.g. LDAP/AD) = a new `IIdentityBackend` - **without touching** the protocol or
server layer.

```
ISpnegoNegotiator  ──>  IGssMechanism (NTLM today, Kerberos later)
                                │
                                └──>  IIdentityBackend (local today, LDAP/AD later)
```

## Security defaults & audit

- SMB1 file access **off** (only the negotiate-upgrade path is provided).
- **Signing required** by default; 3.1.1 preferred with **preauth integrity** (SHA-512).
- Cipher preference **AES-128-GCM** > AES-256-GCM > AES-128-CCM > AES-256-CCM.
- Signing preference **AES-GMAC** > AES-CMAC > HMAC-SHA256.
- **Guest/anonymous rejected by default.**
- **Per-share encryption** enforceable (`Share.EncryptData`): responses are encrypted, and
  unencrypted access to an encrypted tree is rejected with `RejectUnencryptedAccess` (on by default);
  an encrypted share on a connection without a 3.x cipher → `ACCESS_DENIED`.
- Crypto exclusively via the .NET BCL (`System.Security.Cryptography`).

> **Security audit:** status and open items in [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md)
> (fixed findings are marked in code with `[AUDIT-2026-06]` and guarded by `AuditFixTests`).
> Still open, among others: NTLM MIC verification (O1), 3.1.1 negotiate validation (O3),
> credit accounting (O6).
> ⚠️ Cross-check AES-256 key derivation (M3) against a real Windows interop capture before using Kerberos.

## Verification

The suite (383 tests) covers, among others:

- **Official crypto vectors:** AES-CMAC (RFC 4493 §4), MD4 (RFC 1320 A.5), NTOWFv2 (MS-NLMP §4.2 example).
- Wire roundtrips: header (sync/async), NBSS (big-endian length prefix), negotiate contexts
  (8-byte alignment, offset correctness).
- Crypto: KDF determinism, key derivation (3.0/3.1.1, AES-128/256, `ServerIn ` label with the
  trailing space), sign/verify + tamper detection (all 3 algorithms), transform roundtrip
  + AEAD tag check, preauth hash chain.
- Server end-to-end: NEGOTIATE → SESSION_SETUP → TREE_CONNECT → ECHO; dialect selection;
  cipher/signing negotiation; signing enforcement (signed accepted, unsigned rejected);
  guest rejection; TCP integration over real NBSS.
- Per-share encryption: tree marking + ShareFlags, plaintext request on an encrypted tree
  rejected (`RejectUnencryptedAccess`), encrypted-share connect without a cipher rejected, and the
  host returns the TREE_CONNECT response of an encrypted share as a TRANSFORM frame.
- Oplocks: grant of the requested level on a solo open (Batch/Exclusive), downgrade to
  Level II + OPLOCK_BREAK notification on a second open of the same file, acknowledgment,
  release on CLOSE; lease-break acknowledgment (still) → `STATUS_NOT_SUPPORTED`.
- Audit fixes (`AuditFixTests`): LOGOFF signing enforcement, MessageId sequence window
  (replay/out-of-window rejected), MaximalAccess enforcement on CREATE, cap on pending async operations.
- Path sandbox (`SymlinkSandboxTests`): a symlink/reparse point inside the share that points outside
  is denied (file **and** directory); normal in-root access stays allowed (H4).
- QUERY_DIRECTORY paging + stable FileId (`QueryDirectoryPagingTests`, O2): large directory across
  multiple pages, single entry, buffer too small → `INFO_LENGTH_MISMATCH`.
- Share modes / persistent handle (`ShareModeManagerTests`, `LocalFileStoreHandleTests`,
  `QueryDirectoryPagingTests`, O5): sharing violation on an incompatible second open + release after
  CLOSE; read/write/DeleteOnClose/rename-while-open over a persistent OS handle; stable FileId.

## Roadmap

| Milestone | Status |
|---|---|
| M1 Transport & parsing | ✅ |
| M2 Negotiate (incl. 3.1.1 contexts, preauth hash) | ✅ |
| M3 Auth (SPNEGO + **real NTLMv2 login**, key derivation, signing) | ✅ (MIC verification still open) |
| M4 Tree & file access (CREATE/READ/QUERY_DIRECTORY/QUERY_INFO/CLOSE) | ✅ via `LocalFileStore` |
| M5 Writing (WRITE, SET_INFO/Rename/Delete ✅; **byte-range LOCK ✅** incl. blocking + CANCEL, pluggable `ILockManager`) | ✅ |
| M6 Encryption & hardening (transform path) | ✅ Per-share encryption wired (tree `EncryptData`, response encryption incl. TREE_CONNECT response) + hardening: `RejectUnencryptedAccess` (on by default) rejects plaintext access to encrypted trees; encrypted-share connect without a 3.x cipher → `ACCESS_DENIED` |
| Share enumeration (srvsvc NetrShareEnum over DCERPC/IPC$, IOCTL FSCTL_PIPE_TRANSCEIVE) | ✅ |
| SMB1→SMB2 negotiate upgrade (§6.1, for impacket et al.) | ✅ |
| M7 **CHANGE_NOTIFY ✅** (pluggable `IDirectoryWatcher`); **oplocks ✅** (pluggable `IOplockManager`: grant + OPLOCK_BREAK notification + acknowledgment + release); **leases** & compound polish open | 🟡 |
| Native Windows Explorer interop (full FSCC/IOCTL coverage, Secure Negotiate) | 🟡 Secure Negotiate ✅ (FSCTL_VALIDATE_NEGOTIATE_INFO, downgrade → connection drop); server-side copy ✅ |
| **Phase 5 Server-side copy & FSCTLs** ✅ (FSCTL_SRV_COPYCHUNK + resume keys + `CopyRangeAsync` offload; SET_SPARSE / SET_ZERO_DATA / QUERY_ALLOCATED_RANGES / GET·SET·DELETE_REPARSE_POINT via opt-in seams; Secure Negotiate) | ✅ |
| **Phase 6 Multichannel** ✅ (session binding + per-channel signing, FSCTL_QUERY_NETWORK_INTERFACE_INFO via `INetworkInterfaceProvider`, channel failover) | ✅ |
| **Phase 7 DFS referrals** ✅ (FSCTL_DFS_GET_REFERRALS / _EX via pluggable `IDfsNamespace` + `StandaloneDfsNamespace`; DFS TREE_CONNECT/NEGOTIATE flags; link resolution → `STATUS_PATH_NOT_COVERED`) | ✅ |
| **Phase 8 Operational readiness** ✅ (structured audit logging `ISmbAuditLogger`; idle/auth timeouts; connection admission control `ConnectionLimiter`; graceful draining shutdown; health/perf metrics `SmbServerMetrics`) | ✅ |
| **Phase 9 Alternate data streams & extended attributes** ✅ (named streams `file.txt:stream` + FileStreamInformation via opt-in `INamedStreamStore`; FileFullEaInformation via opt-in `IExtendedAttributeStore`) | ✅ |
| **Phase 10 Transport hardening** ✅ (**M10.1 SMB over TLS** — `SslStream` wrapper via `SmbServerBuilder.UseTls(cert)`, mutual TLS; **M10.2 SMB over QUIC** — `SmbServerBuilder.UseQuic(cert)`, TLS 1.3 + ALPN "smb"; **M10.3 compression** — LZ77 via `UseCompression`, negotiate context) | ✅ |
| **Phase 11 Quota & advanced FS** ✅ (**M11.1 quota** — QUERY/SET_QUOTA_INFO via opt-in `IQuotaProvider`, write enforcement → `STATUS_DISK_FULL`; **M11.2 reparse/symlink** — `STATUS_STOPPED_ON_SYMLINK` + SYMLINK_ERROR_RESPONSE via opt-in `ISymlinkResolver`, dialect-correct SMB2_ERROR_CONTEXT framing; **M11.3 WS-Discovery** — UDP responder via `SmbServerBuilder.UseWsDiscovery()` for Explorer network browsing) | ✅ |
| M8 Kerberos ✅, LDAP backend ✅, durable/persistent handles ✅, multichannel ✅, DFS ✅, operational readiness ✅, ADS/EA ✅, TLS/QUIC/compression ✅, quota ✅, reparse/symlink ✅, WS-Discovery ✅; RDMA | 🟡 |

## License note

The underlying Microsoft Open Specifications are covered by the Open Specifications Promise.
Structures/constants were reimplemented (no verbatim text was copied).
