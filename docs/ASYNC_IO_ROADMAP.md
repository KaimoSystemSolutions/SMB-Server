# Async I/O Roadmap: asynchronous `IFileStore` + concurrent READ/WRITE dispatches

> **Purpose of this document:** Work plan AND resumption protocol. The [Status Journal](#status-journal)
> section below states exactly which milestone is complete, where work is currently happening,
> and what comes next. On interruption: read the journal, continue at the first unchecked item.

## Motivation

Two problems, one conversion:

1. **Sync-over-async for external backends.** `IFileStore` is synchronous (`Span`-based).
   A backend that is internally async (e.g. the Kaimo SmbSync bridge) must block per Read/Write
   (`Task.Run` + `.Wait()`) — this ties up thread pool threads and scales poorly with many
   connections.
2. **Serialized pipeline per connection.** The read loop (`SmbConnectionHandler.RunAsync`)
   processes frame by frame; `ProcessMessage` → handler → `store.Read()` runs inline.
   SMB2 clients pipeline multiple READs/WRITEs via credits — today these are answered strictly
   sequentially. I/O latencies add up instead of overlapping.

Stage 1 (A1–A3) solves problem 1, stage 2 (A4) problem 2, A5 makes the local backend truly async.

## Design decisions (established during analysis)

- **`IFileStore` becomes async-first** (`ValueTask`, `Memory<byte>`/`ReadOnlyMemory<byte>`,
  `CancellationToken`). `Create` loses the `out CreateOutcome` parameter (not possible with
  async) → new result type `FileCreateResult(Handle, Action)`.
- **`SyncFileStore` base class** in `Smb.FileSystem`: implements the async interface via
  the old synchronous (Span) signatures. Sync backends (LocalFileStore) derive from it and
  remain almost unchanged; the async methods are `virtual` so individual operations
  can later be overridden with truly async versions (→ A5).
- **`IFileHandle`** gains `GetInfoAsync()`/`DisposeAsync()` as default interface methods
  that fall back to `GetInfo()`/`Dispose()` — sync handles need no change, async
  backends can override.
- **`Smb2Dispatcher.ProcessMessageAsync(ReadOnlyMemory<byte>, …)`** becomes the main path; the
  previous synchronous `ProcessMessage(ReadOnlySpan<byte>, …)` remains as a thin wrapper
  (≈100 call sites in tests remain untouched; for sync stores the ValueTask chain runs
  synchronously anyway).
- **`_frameWasEncrypted` field in the dispatcher becomes a parameter** (`frameEncrypted` through all
  handlers to `VerifyInboundSignature`). Reason: with concurrent dispatches (A4) the instance
  field would be a data race. Done alongside A2, since every handler signature is touched there
  anyway.
- **C# 12 caveat (net8.0):** In async methods no `Span` locals are allowed. Handlers therefore parse
  directly in the call expression (`XyzMessage.ParseRequest(segment.Span, …)`); the
  request records hold `byte[]`/scalars (verified: `WriteMessage.Request.Data` is
  `byte[]`), nothing Span-like survives an `await`.
- **A4 concurrency lives in the host, not in the dispatcher core:** The read loop classifies
  frames (`TryBeginConcurrentFrame`): only single, non-compound READ/WRITE frames run
  concurrently (capped via option); everything else is a barrier (first drain all running ops,
  then process sequentially as before). Responses go via the existing serialized
  out-of-band send channel (`SendRawAsync`/`SendFramedAsync` with `_writeLock`) — SMB2 allows
  out-of-order responses (correlation via MessageId).
- **Sequence window invariant:** `ValidateSequence` mutates `connection.SequenceWindowStart`
  and MUST run in frame arrival order. Therefore `TryBeginConcurrentFrame` consumes
  the window synchronously IN the read loop, before execution is handed off. No lock needed
  as long as only the read loop validates.
- Already verified: `SmbSession.NextEncryptionNonce()` is `Interlocked` (concurrent
  encryption of responses is safe); `RpcPipe` needs an internal lock for A4;
  thread safety of `LockManager.IsRangeAccessible` to be checked in A4.

## Milestones

### A1 — Async contract in `Smb.FileSystem` ✅
- [x] Convert `IFileStore` to async (8 methods, `CancellationToken` parameter)
- [x] Introduce `FileCreateResult` (replaces `out CreateOutcome`)
- [x] `IFileHandle`: `GetInfoAsync()`/`DisposeAsync()` default implementations
- [x] `SyncFileStore` base class (async→sync adapter, async methods `virtual`)
- [x] `LocalFileStore` → inherits from `SyncFileStore` (methods `protected override`, logic unchanged)
- [x] Port `VersioningFileStore` to natively async (decorator, `TryReadAll` → async)
- [x] Port `examples/DemoExternalVersionStore` to natively async (build check only possible with A3)
- [x] `dotnet build src/Smb.FileSystem` green

### A2 — Dispatcher async (`Smb.Server`) ✅
- [x] `ProcessMessageAsync(ReadOnlyMemory<byte>, …)` as main path; `ProcessMessage`(Span) as sync wrapper
- [x] `DispatchOneAsync`; file handlers async: CREATE, CLOSE, READ, WRITE, QUERY_DIRECTORY, QUERY_INFO, SET_INFO, FLUSH
- [x] `_frameWasEncrypted` field removed → `frameEncrypted` parameter through all handlers/`VerifyInboundSignature`
- [x] Remaining handlers (Negotiate/Session/Tree/Echo/Ioctl/Lock/Cancel/Notify/Oplock) stay sync, but get the parameter
- [x] `dotnet build src/Smb.Server` green

### A3 — Host integration (`Smb.Host`) ⇒ **Stage 1 complete** ✅
- [x] `ProcessFrame` → `ProcessFrameAsync` (await `ProcessMessageAsync`)
- [x] Full build green (incl. examples)
- [x] Existing test suite green (133 existing tests; VersioningTests helper converted to async API)
- [x] New tests (`AsyncIoTests.cs`, 3 tests): natively-async fake store end-to-end (CREATE/WRITE/READ/CLOSE
      + DELETE_ON_CLOSE via `DisposeAsync`); `SyncFileStore` adapter incl. CreateOutcome mapping.
      Suite: **136/136 green.**
- **Checkpoint reached:** From here an async backend (Kaimo bridge) can connect without sync-over-async.

### A4 — Concurrent READ/WRITE dispatches ⇒ **Stage 2 complete** ✅
- [x] Dispatcher: `TryBeginConcurrentFrame` (classification + sequence window in read loop) +
      `ExecutePreparedFrameAsync` (new partial `Smb2Dispatcher.Concurrency.cs`);
      `DispatchOneAsync` with `preValidated` flag
- [x] Host: in-flight tracking (`_inflight` + `_ioGate`), barrier for non-eligible frames
      (`DrainInflightAsync`), drain in teardown BEFORE `_writeLock.Dispose`
- [x] `SmbServerOptions.MaxConcurrentFileOpsPerConnection` (default 8; 1 = old behavior)
- [x] `RpcPipe` internally locked; `InMemoryLockManager.IsRangeAccessible` is already `_gate`-locked (verified)
- [x] Tests (`ConcurrentIoTests.cs`, 4 tests): classifier (READ/WRITE yes; CREATE/compound/
      pre-NEGOTIATE no; window consumption), deterministic overlap at dispatcher level,
      out-of-order responses over real TCP. Suite: **140/140 green.**

### A5 — `LocalFileStore` with real async I/O ✅
- [x] `ReadAsync`/`WriteAsync` via `File.OpenHandle(FileOptions.Asynchronous)` + `RandomAccess`
      (override the `virtual` sync wrappers of the base class; sync path remains for direct users)
- [x] Error mapping unchanged (IOException → InvalidParameter/DiskFull; EOF → Ok(0))
- [x] Suite green (140/140)

### A6 — Finalization ✅
- [x] README (module description Smb.FileSystem) updated to async-first; no outdated snippets
- [x] This document finalized, memory/roadmap note updated

## Status Journal

> Format: Date — milestone — what happened / where exactly work stands / next step.

- **2026-07-06 — A0 (analysis) completed.** Mapped affected locations: `IFileStore` +
  3 implementations (LocalFileStore, VersioningFileStore, examples/DemoExternalVersionStore),
  dispatcher partials (FileCommands + signature check in all partials), host read loop,
  ~100 sync `ProcessMessage` call sites in tests (remain stable via wrapper). Design decisions
  recorded above. **Next step: A1.**
- **2026-07-06 — A1 completed.** New async contract in `IFileStore.cs` + `SyncFileStore.cs`;
  LocalFileStore/VersioningFileStore/demo store ported; `Smb.FileSystem` builds green.
  Note for later: `tests/VersioningTests.cs` (helpers `Write`/`ReadAll`) calls the old
  sync store methods directly → will be converted to async helpers in A3.
  **Next step: A2 (dispatcher).**
- **2026-07-06 — A2+A3 completed (stage 1 done).** Dispatcher async
  (`ProcessMessageAsync`/`DispatchOneAsync`, `frameEncrypted` as parameter instead of instance field),
  host read loop awaited; VersioningTests helpers converted. New `AsyncIoTests` (3).
  Suite 136/136 green.
- **2026-07-06 — A4 completed (stage 2 done).** Concurrent READ/WRITE frames:
  `Smb2Dispatcher.Concurrency.cs` (TryBeginConcurrentFrame/ExecutePreparedFrameAsync),
  host in-flight tracking with barrier and teardown drain, option
  `MaxConcurrentFileOpsPerConnection` (default 8), RpcPipe locked. New `ConcurrentIoTests` (4,
  incl. out-of-order over real TCP). Suite 140/140 green.
- **2026-07-06 — A5+A6 completed. PROJECT COMPLETE.** LocalFileStore with real
  overlapped I/O (`RandomAccess`), README updated. Final state: suite **140/140 green**,
  all milestones ✅. Possible future follow-up work (deliberately NOT part of this conversion):
  pass `CancellationToken` from host through to store calls (CANCEL for READ/WRITE),
  SafeFileHandle caching per open in LocalFileStore (saves open/close per request),
  concurrency within compounds (non-related chains).
