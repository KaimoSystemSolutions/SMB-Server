# Windows Compatibility Roadmap: „jeder Case funktioniert einwandfrei"

> **Zweck dieses Dokuments:** Arbeitsplan **und** Resumption-Protokoll, um den SMB-Server so weit zu
> bringen, dass ein echter **Windows-Client (Explorer, Office, robocopy, CLI, Backup/AV)** ohne Freezes,
> ohne Datenverlust und ohne „geht meistens"-Verhalten auf die Freigaben zugreift. Das
> [Status-Journal](#status-journal) unten sagt exakt, welcher Meilenstein fertig ist und was als
> Nächstes kommt. Bei Unterbrechung: Journal lesen, beim ersten offenen Punkt weitermachen. Inline
> `<!-- NOTE: -->` beim Arbeiten hinterlassen.
>
> Diese Roadmap ergänzt `ENTERPRISE_ROADMAP.md` (Feature-Vollständigkeit) und
> `ENTERPRISE_HARDENING_ROADMAP.md` (Skalierung/Auth/HA/Observability). Beide sind fertig; der Kern ist
> funktional. **Offen ist genau das, was jene beiden Roadmaps wiederholt als „manual-verify against a
> real Windows client" vertagt haben** — plus die konkreten Protokoll-Feinheiten, an denen sich Windows
> von einem Test-Client (smbprotocol/pysmb) unterscheidet. Genau dort entstehen die gemeldeten Freezes.

## Ausgangslage (verifiziert gegen den Code, 2026-07-14)

Der Baseline ist stark und Windows-nah konfiguriert: SMB 3.1.1 bevorzugt, Signing Pflicht, AES-GMAC/GCM,
Pre-Auth-Integrity, Multichannel an, Leases + klassische Oplocks + Durable/Persistent Handles + Witness
vorhanden. Die Lücken sind **nicht** „Feature fehlt", sondern **Verhalten unter echtem Windows-Timing**:

| # | Befund (Code-belegt) | Datei | Freeze-Relevanz |
|---|----------------------|-------|-----------------|
| 1 | `ConcurrentMetadataOps` **default off** → jede CREATE/CLOSE/SET_INFO/QUERY_* ist eine **Connection-Barrier**, die alle inflight-I/Os drainiert und seriell läuft. | `SmbServerOptions.cs:137`, `Smb2Dispatcher.Concurrency.cs` | **HÖCHSTER Verdacht.** Auf einem echten Backend (TrueNAS/ZFS, Netz-Latenz) blockiert **ein** langsamer Metadaten-Op die ganze Verbindung. Explorer feuert beim Ordneröffnen Bursts aus CREATE+QUERY_INFO+CLOSE → sichtbarer Freeze. |
| 2 | Oplock-/Lease-**Break-before-grant nicht implementiert**: der Konflikt-Zugriff **wartet nicht** auf das Acknowledgment, der Holder wird sofort heruntergestuft. Explizit als „deferred to a later pass" markiert. | `Smb2Dispatcher.Oplock.cs:18`, `Smb2Dispatcher.Lease.cs:16-20` | Kein Server-Hang, aber **Cache-Kohärenz-Bruch** und Windows-seitige Retries/Stalls (Explorer/Office öffnen dieselbe Datei mehrfach: Thumbnail, Preview, Defender, SearchIndexer). |
| 3 | Break-Notification ist **fire-and-forget** (`_ = SendOplockBreakAsync`), **kein Break-Timeout**, kein Retry, keine Force-Downgrade-Uhr. | `Smb2Dispatcher.Oplock.cs:38`, `.Lease.cs:34` | Ein Client, der nie ack't, wird nicht abgeräumt; keine Observability, warum eine Datei „klemmt". |
| 4 | CHANGE_NOTIFY: Änderungen **zwischen** zwei Requests gehen verloren (im Code als offen markiert). | `Smb2Dispatcher.Notification.cs:78-79` | Kein Freeze, aber „Case funktioniert nicht einwandfrei": Explorer-Ansicht wird stale, F5 nötig. |
| 5 | Directory-Watcher default = `FileSystemDirectoryWatcher` (.NET `FileSystemWatcher`). | `SmbServerOptions.cs:186` | Auf ZFS/Netz-Mounts liefert `FileSystemWatcher` u. U. keine/verspätete Events → CHANGE_NOTIFY „tot" (Kommentar nennt inotify/ZFS-Events als Alternative). |
| 6 | **Kein** End-to-End-Test gegen echtes Windows existiert im Repo (alle Roadmaps enden mit „manual-verify"). | — | Die eigentliche Aufgabe: „jeder Case" ist nie gegen den echten Client belegt worden. |
| 7 | `InMemoryOplockManager` XML-Doc behauptet „a lease … is not yet implemented" — **veraltet**, Leases sind in `InMemoryLeaseManager` real umgesetzt. | `Oplocks/InMemoryOplockManager.cs:29` | Nur Doku-Irreführung; beim Break-before-grant-Umbau (W2) mitkorrigieren. |

**Kernaussage:** Der Freeze ist mit hoher Wahrscheinlichkeit **#1** (Barrier auf langsamem Backend),
sekundär **#2/#3** (Break-Handshake). Deshalb steht vorne eine **Diagnose-Phase (W0)**, die den Freeze
*beweist* statt rät — danach zielgerichtet fixen.

---

## Phase W0 — Freeze beweisen: Repro-Harness, Windows-Labor, Observability

Ziel: den Freeze **reproduzierbar** machen und **eindeutig einer der Hypothesen #1–#5 zuordnen**, bevor
Code geändert wird. Ohne diesen Schritt fixt man blind.

### W0.1 — Echtes Windows-Testlabor
- **Deployment festgelegt (2026-07-14):** Der Server wird als **Bibliothek** konsumiert, die
  Shares / Nutzer-Auth / Rechteprüfung über die Extension-Points **selbst überschreibt** — **kein Kerberos,
  keine Domäne**. Damit ist der Auth-Pfad **NTLMv2 gegen den eigenen `IIdentityBackend`** (bzw. ein
  eigener `ISpnegoNegotiator`), und Rechte laufen über `IShareAccessPolicy` + den CREATE-Zeit-DACL-Check.
  Die Kerberos/`Smb.Auth.Sspi`-Schiene (Roadmap-Phase B1) ist für dieses Deployment **out of scope**.
- Eine reale Windows-11-24H2-VM gegen den Host laufen lassen; Share via `\\<host>\<share>` mappen. **Nur der
  Workgroup/lokale-Konten-Modus** (NTLMv2). Testkonten = die, die der eigene Identity-Backend kennt.
- **Deliverable:** `docs/interop/WINDOWS_LAB.md` — VM-Setup, Netzwerk, wie man den eigenen Lib-Host startet,
  Share-/User-/Policy-Konfiguration über den `SmbServerBuilder`.

### W0.2 — Client-seitige Freeze-Repro-Skripte
- Drei PowerShell/`robocopy`-Lasten, die die Hypothesen provozieren:
  1. **Metadaten-Burst** (Hyp. #1): `robocopy` eines Baums mit 50k kleinen Dateien + `Remove-Item -Recurse`;
     Explorer-Ordner mit 10k Einträgen öffnen. Latenz künstlich erhöhen (Backend-Delay-Shim, s. W0.3).
  2. **Mehrfach-Open derselben Datei** (Hyp. #2/#3): Datei in Word offen halten, parallel aus PowerShell
     lesen/umbenennen/löschen; Preview-Pane + SearchIndexer aktiv.
  3. **Live-Ordner** (Hyp. #4/#5): Explorer-Fenster offen, aus einer zweiten Session Dateien anlegen/löschen;
     prüfen ob die Ansicht ohne F5 aktualisiert.
- **Deliverable:** `docs/interop/repro/*.ps1` + erwartetes vs. beobachtetes Verhalten pro Skript.

### W0.3 — Server-seitige Freeze-Observability
- **Latenz-Shim-Backend:** ein `IFileStore`-Dekorator, der pro Metadaten-Op eine konfigurierbare Verzögerung
  einfügt (simuliert ZFS/Netz-Latenz), damit der Barrier-Effekt (#1) auch lokal ohne TrueNAS reproduzierbar
  ist. Analog zum bereits existierenden Benchmark-Backend aus `A5`.
- **Barrier-/Break-Instrumentierung:** über die vorhandene OTel-Bridge (`Smb.Server.OpenTelemetry`) messen:
  Wartezeit an der Metadaten-Barrier (Zeit zwischen „Frame klassifiziert" und „dispatch startet"),
  Anzahl offener Breaks ohne Ack, `PendingRequests`-Tiefe. Ein Span, der > *N* ms an der Barrier hängt,
  markiert den Freeze **im Trace**.
- **Deliverable:** `tests/Smb.Tests/…LatencyShim`, OTel-Attribute `smb.dispatch.barrier_wait_ms`,
  `smb.oplock.pending_breaks`. **Test:** Shim + Burst zeigt messbar wachsende `barrier_wait_ms` bei
  `ConcurrentMetadataOps=false` und flache Kurve bei `true` (Beweis für Hyp. #1).

> **Gate:** Erst wenn W0.3 den Freeze einer Hypothese zuordnet, wird die zugehörige Phase (W1/W2/W3)
> priorisiert. Wahrscheinlichstes Ergebnis: **W2 zuerst**.

---

## Phase W1 — Break-before-grant: kohärente Oplock-/Lease-Semantik

Ziel: der Konflikt-Zugriff **wartet** auf den Break-Ack (bzw. einen Timeout), bevor er fortfährt — das ist
das Windows-konforme Verhalten (§3.3.5.9.8) und schließt Cache-Kohärenz-Lücke #2 sowie die fehlende
Break-Uhr #3. Nur nötig, falls W0 #2/#3 als Freeze-Ursache bestätigt **oder** Datenkohärenz gefordert ist.

### W1.1 — Blockierender Break im CREATE-Pfad
- Wenn CREATE einen Break auslöst, den auslösenden Op **pending** stellen (STATUS_PENDING-Interim wie bei
  CHANGE_NOTIFY, Muster in `Smb2Dispatcher.Notification.cs` wiederverwenden), bis der Holder ack't oder der
  Break-Timeout feuert; dann erst CREATE-Response senden. Für Lease-Write/Handle-Downgrades zwingend, für
  reine Read-Downgrades optional.
- **Dateien:** `Smb2Dispatcher.FileCommands.cs` (CREATE-Konfliktpfad), `Smb2Dispatcher.Oplock.cs`,
  `.Lease.cs`. **Tests:** CREATE-hinter-Break pended → Ack → CREATE completes; paralleler READ des zweiten
  Openers sieht erst nach Ack konsistente Daten.

### W1.2 — Break-Timeout + Force-Downgrade
- Pro gesendetem Break eine Uhr (`TimeProvider`, wie Durable-Scavenger). Kein Ack binnen Timeout
  (Windows: ~35 s) → Holder zwangs-downstufen, Manager-Leak vermeiden, pending CREATE freigeben.
- **Dateien:** neuer Break-Tracker in `Smb.Server/Oplocks`/`Leases`. **Tests:** Timeout ohne Ack →
  Force-Downgrade + CREATE completes; verspätetes Ack danach wird sauber ignoriert (`NotifyOnce`-Muster).

### W1.3 — Doku-Korrektur
- Veralteten „lease not implemented"-Kommentar in `InMemoryOplockManager` und die „deferred"-Absätze in
  `.Oplock.cs`/`.Lease.cs` an das neue Verhalten anpassen.

---

## Phase W2 — Metadaten-Durchsatz unter Windows (den Barrier-Freeze beheben)

Ziel: Hypothese #1 abstellen. Die Maschinerie existiert bereits (`ConcurrentMetadataOps`), ist aber
**default off und nie gegen echtes Windows validiert**.

### W2.1 — Gegen echtes Windows validieren, dann Default kippen
- Mit W0.2-Lasten `ConcurrentMetadataOps=true` gegen die Windows-VM fahren; korrekte Semantik prüfen:
  Delete-on-close-Reihenfolge, SET_INFO(rename)→CLOSE, QUERY_DIRECTORY-Paging unter Parallelität.
- Wenn stabil: **Default auf `true`** ziehen (oder in der TrueNAS-Preset-Config setzen) und `barrier_wait_ms`
  (W0.3) als Regressionswächter behalten.
- **Dateien:** `SmbServerOptions.cs` (Default), Host-Preset. **Tests:** die A2b/A5-Suite bleibt grün;
  neuer End-to-End-Delete-Burst über den echten Host-Loop unter Last.

### W2.2 — Latenz aus dem Metadaten-Hot-Path (Backend **und** eigene Hooks)
- **Szenario-spezifisch (Lib mit Overrides):** Nicht nur das `IFileStore`-Backend erzeugt Latenz — auch die
  **überschriebene Auth/Rechteprüfung** liegt im selben Barrier-Pfad. `IShareAccessPolicy.AuthorizeConnect`
  (TREE_CONNECT) und der **CREATE-Zeit-DACL-Check** laufen synchron im Op; wenn sie einen DB-/Netz-/LDAP-Lookup
  pro Zugriff machen, verschärfen sie den Freeze aus #1 **direkt**. Prüfen: cachen diese Hooks? Blocken sie
  synchron? Ein 20-ms-Lookup pro CREATE ist auf einem Explorer-Ordner-Öffnen (Hunderte CREATEs) genau der Freeze.
- Backend-Latenz reduzieren: `IFileStore`-Aufrufe prüfen (unnötige `stat`/`GetInfo`-Roundtrips im CREATE/QUERY-Pfad?),
  Delete-on-close-Pfad, Bounded-Enumeration-Pfad (`QueryDirectoryAsync(maxEntries)`).
- **Deliverable:** Messung der Metadaten-Latenz pro Op-Typ **inkl. der eigenen Auth/Policy-Hooks**; Hotspots
  dokumentieren. (W2.1 mit `ConcurrentMetadataOps=true` verhindert, dass ein einzelner solcher Lookup die ganze
  Verbindung einfriert — behebt aber nicht die Latenz selbst.)

---

## Phase W3 — CHANGE_NOTIFY & Explorer-Verhalten („Case funktioniert einwandfrei")

### W3.1 — Change-Buffering-Lücke schließen (#4)
- Änderungen, die zwischen Abmeldung und erneuter CHANGE_NOTIFY-Registrierung auf demselben Directory-Open
  auftreten, puffern und beim nächsten Request sofort ausliefern (statt zu verlieren). Explorer meldet sich
  nach jeder Notify neu an — genau hier gehen Events verloren.
- **Dateien:** `Smb2Dispatcher.Notification.cs`, `IDirectoryWatcher`. **Tests:** Change im Fenster zwischen
  zwei Notifies → beim Re-Register sofort geliefert.

### W3.2 — ZFS-tauglicher Watcher (#5)
- Für den TrueNAS-Einsatz einen `IDirectoryWatcher` auf Basis von inotify/ZFS-Events (statt .NET
  `FileSystemWatcher`) bereitstellen und gegen Explorer verifizieren (Anlegen/Löschen/Umbenennen erscheint
  ohne F5). Falls Events unzuverlässig: dokumentierter Fallback = `NullDirectoryWatcher` (Explorer pollt
  dann selbst, langsamer aber korrekt).
- **Dateien:** neuer Watcher in `Smb.FileSystem` oder Host. **Tests:** Watcher liefert Create/Delete/Rename;
  Explorer-Live-Refresh im Labor (manual-verify).

---

## Phase W4 — Flow-Control, Large-MTU, Verschlüsselung gegen Windows

Baseline sieht korrekt aus (Credits mit Floor 256/Cap 512, `MaxRead/Write 8 MiB`, GMAC/GCM) — aber nie gegen
Windows-Timing belegt.

### W4.1 — Credit-/Sequence-Window unter Windows-Last
- Große Kopien (mehrere GB, viele parallele multi-credit READ/WRITE) fahren und prüfen, dass das
  Sequence-Window nie zusteht (Windows stallt bei Credit-Mangel). `CreditRequestResponse` auf allen Pfaden
  (inkl. Interim/Async-Final) gegentesten.
- **Tests:** Durchsatz-Lauf ohne Stall; OTel zeigt Credits > 0 durchgängig.

### W4.2 — Encryption + Signing end-to-end
- `RequireEncryption` + per-Share-Encryption gegen Windows (AES-128-GCM Default, AES-256 erzwungen) prüfen;
  Signing-Pflicht mit GMAC gegen 24H2. Reconnect/Durable-Handle nach Netz-Blip (Timeout 60 s vs. Windows
  ~16 min — W4.3).
- **Tests:** verschlüsselte Session Lesen/Schreiben ok; falsch signierter Frame → AccessDenied.

### W4.3 — Durable/Persistent-Reconnect nach echtem Netz-Blip
- WLAN-Drop/NIC-Umschaltung an der Windows-VM erzwingen; prüfen, dass offene Handles (Word-Dokument)
  überleben und ohne Datenverlust weiterlaufen. Ggf. `DurableHandleTimeout` (aktuell 60 s) an Windows-Erwartung
  anpassen.

---

## Phase W5 — Der „jeder Case"-Interop-Katalog (Abnahmematrix)

Ziel: **jede** relevante Windows-Operation einmal explizit gegen den echten Client abhaken. Das ist die
eigentliche „einwandfrei"-Zusage. Jede Zeile = ein manueller/halbautomatischer Testfall in
`docs/interop/MATRIX.md` mit Status Grün/Rot/Notiz.

- **Explorer:** Ordner öffnen (klein/groß), Live-Refresh, Kopieren/Verschieben (Drag&Drop + `Ctrl+C/V`),
  Umbenennen, Löschen (Einzel/Recursive/Papierkorb), Eigenschaften/Zeitstempel, Thumbnails/Preview-Pane,
  „In Ordner suchen".
- **Datei-Semantik:** Delete-on-close, Rename über offenes Handle, ADS/Zone.Identifier (Downloads aus dem
  Netz), Attribute (ReadOnly/Hidden/System), Zeitstempel-Erhalt bei Copy, Sparse/große Dateien.
- **Office/Anwendungen:** Word/Excel öffnen+speichern (Lock-Files `~$…`, Byte-Range-Locks), gleichzeitiges
  Öffnen, „Datei in Benutzung"-Dialog korrekt.
- **CLI/Tools:** `robocopy /MIR`, `xcopy`, `Get-ChildItem -Recurse`, `icacls` (ACL-Read), Backup-Tools
  (VSS-Semantik out of scope, aber Read-All belegen).
- **Auth & eigene Overrides (Kern dieses Deployments):** NTLMv2-Login von Windows gegen den **eigenen
  `IIdentityBackend`**; die überschriebene `IShareAccessPolicy` filtert Share-Sichtbarkeit + TREE_CONNECT
  korrekt; ein **Rechte-Deny** kommt als sauberes `STATUS_ACCESS_DENIED` an → Explorer zeigt den richtigen
  Dialog (kein Freeze, kein generischer Fehler). Guest/Anonymous korrekt abgewiesen. (Kerberos/Domäne: n/a.)
- **Fehlerpfade:** Sharing-Violation-Dialog, Zugriff-verweigert bei DACL-Deny, Disk-Full (Quota →
  `STATUS_DISK_FULL`), Pfad-zu-lang.

**Deliverable:** vollständig grüne `docs/interop/MATRIX.md`. Jeder rote Fall wird zu einem konkreten
Milestone in W1–W4 zurückverlinkt.

---

## Phase W6 — Async-Autorisierung: I/O-gebundene Auth ohne Verbindungs-Freeze

Motivation: Der W2.2-Test beweist, dass eine langsame **synchrone** `IShareAccessPolicy.AuthorizeConnect` die
Verbindung einfriert und `ConcurrentMetadataOps` das **nicht** abdeckt. Für dieses Deployment (Lib mit
überschriebener Auth/Rechteprüfung) ist eine I/O-gebundene Policy (DB/LDAP) der Normalfall. Ziel: sie sauber
unterstützen, ohne (a) einen Thread-Pool-Thread sync-over-async zu blockieren und (b) ohne unabhängige I/O auf
anderen Trees einzufrieren.

> **Verifizierte Klarstellung (am Read-Loop geprüft, 2026-07-14):** Es reicht **nicht**, die Policy async zu
> machen. Der Host-Read-Loop führt einen Barrier-Op mit `await ProcessMessageAsync(...)` aus, **bevor** er den
> nächsten Frame liest (`SmbConnectionHandler.cs:171-172`). Eine async `AuthorizeConnect` gibt zwar den Thread
> frei (kein sync-over-async), aber der Read-Loop liest den nächsten Frame erst, wenn der TREE_CONNECT fertig
> ist → der unabhängige READ bleibt eingefroren. **Der eigentliche Freeze-Fix ist, TREE_CONNECT aus dem
> Read-Loop-Barrier zu lösen** (W6.3, analog „CREATE runs free" aus `ENTERPRISE_HARDENING_ROADMAP.md` A2b: der
> Client kann keine Op auf einer TreeId senden, die er noch nicht erhalten hat). Der async-Seam (W6.1/W6.2) ist
> die **Voraussetzung** dafür — sonst würde ein off-loop TREE_CONNECT nur den Task-Thread synchron blockieren.

### W6.1 — Async-Seam auf `IShareAccessPolicy` (additiv) ✅ DONE
- `IsVisibleAsync`/`AuthorizeConnectAsync` als **Default-Interface-Methoden**, die auf die synchronen
  delegieren. Kein Breaking Change; bestehende sync-Policies (`AllowAllSharePolicy`, `DelegateSharePolicy`,
  eigene) laufen unverändert.
- **Dateien:** `src/Smb.Server/Authorization/ShareAccess.cs`.
- **Tests:** eine async-only-Policy wird korrekt aufgerufen; eine sync-Policy delegiert per Default identisch.

### W6.2 — Dispatcher konsumiert den async-Seam ✅ DONE (TREE_CONNECT; Enumeration zurückgestellt)
- `HandleTreeConnect` → `HandleTreeConnectAsync` (`async ValueTask<ResponseSegment>`, Param `ReadOnlyMemory`
  statt `ReadOnlySpan`, Span-Parsing vor dem `await`); Dispatch-Switch awaitet es. `AuthorizeConnectAsync` wird
  awaited → kein sync-over-async-Thread-Block mehr. Default-Policy delegiert auf sync → Verhalten unverändert.
  (Verbindungs-Freeze noch **nicht** behoben — das ist W6.3.)
- **Zurückgestellt (bewusst):** Share-Enumeration (`IShareAccessPolicy.IsVisible` via
  `SmbServerState.GetVisibleShares`, aufgerufen aus dem **synchronen** srvsvc-RPC-Pfad
  `Smb2Dispatcher.FileCommands.cs:372`) bleibt vorerst synchron — das ist ein separater, invasiverer Umbau
  durch den RPC/NDR-Stack und ein deutlich selteneren Pfad (Netzwerk-Browse) als TREE_CONNECT. Eigener
  Milestone bei Bedarf (W6.2b).
- **Dateien:** `src/Smb.Server/Smb2Dispatcher.cs` (HandleTreeConnectAsync + Dispatch-Arm).
- **Tests:** `AsyncSeam_IsUsedAtTreeConnect_AsyncDenyRejects` (WindowsFreezeReproTests) — Policy erlaubt sync,
  verweigert async → TREE_CONNECT wird `ACCESS_DENIED` ⇒ beweist, dass der async-Seam entscheidet.

### W6.3 — TREE_CONNECT aus dem Read-Loop-Barrier lösen (der eigentliche Freeze-Fix) ✅ DONE
- TREE_CONNECT als concurrent-eligible klassifiziert (läuft **frei** wie CREATE, gated auf
  `ConcurrentMetadataOps`): creation-like, keine nachfolgende Op referenziert die noch nicht vergebene TreeId
  (`AllocateTreeId` via `Interlocked`), `session.TreeConnects` ist `ConcurrentDictionary`. **Teardown**-Lifecycle
  (LOGOFF/TREE_DISCONNECT/SESSION_SETUP/NEGOTIATE/CANCEL) bleibt Barrier und drained inflight TREE_CONNECTs
  zuerst; Ordering hält, weil SESSION_SETUP (Barrier) in Ankunftsreihenfolge vor einem folgenden TREE_CONNECT
  vollständig durchläuft.
- **Verifizierte Nuance (im Klassifizierer + Test dokumentiert):** off-barrier behebt den Freeze **nur mit einer
  echt-asynchronen Policy**. Eine sync-blockierende Policy stallt den Read-Loop-Thread schon im synchronen
  Präfix des Concurrent-Frames (bevor das `await` suspendiert) — friert also weiter ein (belegt durch den
  unveränderten W2.2-Test mit sync-Policy + Flag on). Der Fix braucht **beide** Teile: async-Seam (W6.1/W6.2)
  **und** off-barrier (W6.3).
- **Dateien:** `src/Smb.Server/Smb2Dispatcher.Concurrency.cs` (Klassifizierer-`case TreeConnect` + Klassen-Doku).
- **Tests (Paar, isoliert off-barrier als Fix — gleiche async-Policy, nur Flag unterschiedlich):**
  `SlowAsyncAuthorizeConnect_DefaultBarrier_StillFreezesOtherShareIo` (Flag off → READ friert) und
  `SlowAsyncAuthorizeConnect_ConcurrentMetadataOps_DoesNotFreezeOtherShareIo` (Flag on → READ kommt trotz
  hängendem async-Connect durch).

### W6.4 — Builder-Ergonomie ✅ DONE
- Neue `AsyncDelegateSharePolicy` (`Authorization/ShareAccess.cs`): async `AuthorizeConnectAsync`/`IsVisibleAsync`
  aus Lambdas; sync-Interface-Member als Fallback (blocken auf dem Delegate — nur für den noch-synchronen
  Enumerationspfad, W6.2b). Builder-Overload `SmbServerBuilder.UseShareAuthorizationAsync(authorizeConnect,
  isVisible?)` spiegelbildlich zur sync-Variante. `DelegateSharePolicy` (sync) unverändert.
- **Tests:** `ShareAccessPolicyAsyncTests` +2 (async-Pfad führt Delegate aus; sync-Fallback liefert dieselbe
  Entscheidung / Default-Sichtbarkeit true).

### W6.5 — Doku/Regel aktualisiert ✅ DONE (siehe unten)
- **Aktualisierte Design-Regel:** I/O-gebundene **Connect**-Auth gehört in `AuthorizeConnectAsync` (Lambda via
  `UseShareAuthorizationAsync` oder eigene Policy) und sollte **awaiten statt synchron blockieren**; mit
  `ConcurrentMetadataOps=true` friert sie dann keine unabhängige I/O mehr ein (W6.3). Caching bleibt sinnvoll,
  ist aber kein Freeze-Zwang mehr. **Per-Datei**-Rechte weiter in `IFileStore.CreateAsync` (vom selben Flag
  abgedeckt). **Noch offen:** Share-**Enumeration** (`IsVisible`) ist synchron (W6.2b) — eine I/O-gebundene
  Sichtbarkeitsprüfung blockiert dort noch (selten: Netzwerk-Browse).

---

## Status Journal

- **2026-07-14** — Roadmap erstellt. Ausgangslage gegen den Code verifiziert (Tabelle oben): Baseline
  Windows-nah, echte Lücken sind Verhalten-unter-Windows-Timing, nicht fehlende Features. Freeze primär
  Hypothese #1 (Metadaten-Barrier, `ConcurrentMetadataOps` default off) auf latenz-behaftetem Backend,
  sekundär #2/#3 (Break-Handshake ohne Warten/Timeout). **Reihenfolge:** W0 (Freeze beweisen) → dann die
  vom Trace bestätigte Phase, erwartet **W2** zuerst, W1 falls Kohärenz/#2 bestätigt, dann W3/W4, laufend W5.
  **Offene Entscheidung:** Ziel-Deployment Workgroup (NTLM) oder Domäne (Kerberos) zuerst? → bestimmt W0.1/W5-Auth.
  Nächste Aktion: **W0.1** (Windows-VM-Labor aufsetzen) + **W0.3** (Latenz-Shim + `barrier_wait_ms`-Span),
  um den Freeze zu reproduzieren und einer Hypothese zuzuordnen.
- **2026-07-14** — **W0.3 Freeze BEWIESEN (Repro-Test grün).** Der Freeze-Mechanismus ist im Code
  eindeutig lokalisiert: mit `ConcurrentMetadataOps=false` (Default) führt der Host-Read-Loop einen
  Metadaten-Op als **Barrier** mit `await ProcessMessageAsync(...)` **direkt in der Leseschleife** aus
  (`SmbConnectionHandler.cs:172`) — er liest **keinen weiteren Frame**, bis der Op fertig ist. Ein am Backend
  hängendes CREATE friert damit die **ganze Verbindung** ein, inkl. unabhängiger READs auf bereits offene
  Dateien. Neuer Test `tests/Smb.Tests/WindowsFreezeReproTests.cs` (2 Tests) beweist das **deterministisch**
  über den echten TCP-Host-Loop: Backend `SlowCreateGatedStore` blockiert gezielt nur `slow.txt` (kein
  Timing → nicht flaky). (1) `DefaultBarrier_SlowMetadataOp_FreezesUnrelatedRead`: pipelined
  CREATE(slow)+READ(fast-offen) → **innerhalb 2 s keine Antwort** (Freeze); nach Gate-Release fließen beide.
  (2) `ConcurrentMetadataOps_SlowMetadataOp_UnrelatedReadCompletes`: gleiches Setup, Flag on → **READ (mid 6)
  antwortet sofort**, während CREATE (mid 5) noch hängt → kein Freeze. Gleiches Backend, nur Flag
  unterschiedlich → isoliert den Barrier als Ursache **und** belegt den Fix. **Damit ist Hypothese #1
  bestätigt.** Test-Gotcha (gefixt): `Task.WaitAsync(timeout)` bricht nur das Warten ab, nicht den Socket-Read
  → der hängende Read verschluckte danach die Antwort (Desync); jetzt Abbruch des Reads selbst per
  `CancellationTokenSource` (im Freeze 0 Bytes gelesen → sauber). **Suite Smb.Tests 545 → 547 grün.**
  Nächste Aktion: **W2.1** — `ConcurrentMetadataOps=true` gegen echtes Windows validieren (W0.1-Labor) und
  Default/TrueNAS-Preset kippen; parallel optional die OTel-`barrier_wait_ms`-Instrumentierung (W0.3-Rest)
  als Dauer-Regressionswächter. **Offene Entscheidung bleibt:** Workgroup (NTLM) oder Domäne (Kerberos) zuerst.
- **2026-07-14** — **Deployment-Entscheidung aufgelöst: kein Kerberos/keine Domäne.** Der Server wird als
  **Bibliothek** genutzt, die Shares / Nutzer-Auth / Rechteprüfung über die Extension-Points selbst
  überschreibt (eigener `IIdentityBackend`/`ISpnegoNegotiator`, `IShareAccessPolicy`, CREATE-DACL-Check).
  → Auth-Pfad = **NTLMv2 gegen eigenen Backend**; Roadmap-Phase B1 (SSPI-Kerberos) für dieses Deployment
  **out of scope**. W0.1 auf Workgroup-only reduziert; W5-Auth-Zeile auf die Override-Hooks fokussiert
  (Deny → sauberes `STATUS_ACCESS_DENIED`). **Neuer szenario-spezifischer Freeze-Faktor in W2.2:** die
  überschriebene Auth/Policy-Prüfung liegt im selben Barrier-Hot-Path wie das Backend — ein
  DB-/Netz-Lookup pro CREATE/TREE_CONNECT verschärft #1 direkt; `ConcurrentMetadataOps=true` verhindert das
  Einfrieren der ganzen Verbindung, nicht die Latenz selbst. Nächste Aktion unverändert **W2.1** (Flag gegen
  echtes Windows validieren + im eigenen Builder setzen).
- **2026-07-14** — **W2.2 Auth-Latenz-Grenzfall getestet + festgehalten.** Neuer Test
  `SlowAuthorizeConnect_FreezesOtherShareIo_EvenWithConcurrentMetadataFlag` in `WindowsFreezeReproTests.cs`.
  Ergebnis (grün): eine langsame **synchrone** `IShareAccessPolicy.AuthorizeConnect` friert — **auch mit
  `ConcurrentMetadataOps=true`** — einen unabhängigen READ auf einer bereits verbundenen, funktionierenden
  Freigabe ein, weil TREE_CONNECT ein Lifecycle-Op und damit **immer** ein Barrier außerhalb des Flags ist.
  **Die daraus abgeleitete Design-Regel für den Lib-Consumer:** (1) Per-Datei-Rechteprüfung gehört in den
  eigenen `IFileStore.CreateAsync` — dort deckt das Flag die Latenz ab (mechanisch identisch zum bewiesenen
  Backend-CREATE-Freeze). (2) Die Connect-Zeit-Policy (`AuthorizeConnect`) ist **synchron ohne Async-Variante**
  → Entscheidung **cachen**, nicht pro Connect I/O machen. **Suite Smb.Tests 547 → 548 grün.** Damit ist der
  Freeze aus beiden für dieses Deployment relevanten Winkeln (Backend-/Per-Datei-Latenz **und** Connect-Auth)
  abgedeckt. Nächste Aktion weiter **W2.1** (Flag im eigenen Builder setzen + gegen echtes Windows validieren);
  offener Verbesserungspunkt notiert: **async `IShareAccessPolicy`-Variante** erwägen (damit I/O-gebundene
  Auth den Barrier-Thread nicht synchron blockiert) — Kandidat für eine spätere W-Phase.
- **2026-07-14** — **Phase W6 dokumentiert + W6.1 DONE.** Korrektur einer vorher zu optimistischen Aussage:
  Am Read-Loop verifiziert, dass eine **async** Policy den Verbindungs-Freeze **nicht allein** behebt — der
  Read-Loop `await`t den Barrier-Op vor dem nächsten Frame-Read (`SmbConnectionHandler.cs:171-172`); der
  eigentliche Fix ist TREE_CONNECT off-barrier (**W6.3**). Phase W6 mit dieser Klarstellung + Milestones
  W6.1–W6.5 angelegt. **W6.1 implementiert:** `IShareAccessPolicy` um Default-Interface-Methoden
  `IsVisibleAsync`/`AuthorizeConnectAsync` erweitert (delegieren auf die synchronen) — rein additiv, kein
  Breaking Change, alle bestehenden Policies unverändert. Tests `ShareAccessPolicyAsyncTests` (3, grün):
  sync-Default-Delegation, Deny-Durchreichung, reiner async-Override-Pfad. **Suite Smb.Tests 548 → 551 grün.**
  Noch nicht verdrahtet (das ist W6.2). Nächste Aktion: **W6.2** — `HandleTreeConnect` async machen und
  `AuthorizeConnectAsync` awaiten (+ Enumeration `IsVisibleAsync`), sodass I/O-Auth nicht mehr sync-over-async
  einen Thread blockiert; danach **W6.3** (der Freeze-Fix).
- **2026-07-14** — **W6.2 DONE (TREE_CONNECT-Auth-Pfad).** `HandleTreeConnect` → `HandleTreeConnectAsync`
  (async, `ReadOnlyMemory` statt `ReadOnlySpan`, gesamtes Span-Parsing vor dem `await`; `TreeConnectRequest`
  ist eine `class`, überlebt das await problemlos); Dispatch-Switch-Arm awaitet. `AuthorizeConnectAsync` wird
  jetzt awaited — I/O-gebundene Auth blockiert keinen Thread mehr sync-over-async. Default-Policy delegiert auf
  sync ⇒ **verhaltensneutral** (551 Bestandstests unverändert grün). Verhaltensnachweis:
  `AsyncSeam_IsUsedAtTreeConnect_AsyncDenyRejects` (sync grant / async deny → `ACCESS_DENIED`). **Suite
  551 → 552 grün.** **Enumeration (`IsVisible`) bewusst zurückgestellt** (synchroner srvsvc-RPC-Pfad,
  separater Umbau, selteneres Browsing-Szenario — W6.2b bei Bedarf). Verbindungs-Freeze weiterhin offen →
  Nächste Aktion **W6.3**: TREE_CONNECT als concurrent-eligible klassifizieren („runs free" wie CREATE), damit
  eine langsame (async) Policy unabhängige I/O nicht mehr einfriert — der eigentliche Fix; dazu die Umkehrung
  des W2.2-Grenzfalltests.
- **2026-07-14** — **W6.3 DONE → Connect-Freeze behoben.** TREE_CONNECT als concurrent-eligible klassifiziert
  (`Smb2Dispatcher.Concurrency.cs`, `case TreeConnect: return metadataConcurrency;`), „runs free" wie CREATE;
  Invarianten am Code verifiziert (`AllocateTreeId` Interlocked, `TreeConnects` ConcurrentDictionary, Ordering
  via SESSION_SETUP-Barrier). Klassen-Doku: TREE_CONNECT von „Lifecycle-Barrier" zu „creation-like runs free"
  umgestellt; nur Teardown-Lifecycle bleibt Barrier. **Wichtige verifizierte Nuance:** off-barrier hilft nur
  einer echt-asynchronen Policy — eine sync-blockierende Policy stallt den Read-Loop schon im synchronen Präfix
  des Concurrent-Frames (der W2.2-Test mit sync-Policy + Flag on friert deshalb weiterhin, unverändert grün).
  Fix = async-Seam (W6.1/W6.2) **und** off-barrier (W6.3) zusammen. Testpaar `SlowAsyncAuthorizeConnect_*`
  (Flag off friert / Flag on behoben, gleiche async-Policy → isoliert off-barrier als Fix). **Suite Smb.Tests
  552 → 554 grün, keine Regressionen.** Nächste Aktion: **W6.4** (Builder-Ergonomie:
  `UseShareAuthorizationAsync` + async-`DelegateSharePolicy`).
- **2026-07-14** — **W6.4 + W6.5 DONE → Phase W6 rund (bis auf W6.2b).** `AsyncDelegateSharePolicy` +
  `UseShareAuthorizationAsync(...)`-Builder-Overload (async-Auth per Lambda; sync-Fallback für den
  noch-synchronen Enumerationspfad). Tests `ShareAccessPolicyAsyncTests` +2. **Suite Smb.Tests 554 → 556 grün.**
  Kurz gestolpert: `<paramref>` im Typ-`<summary>` → CS1734 (paramref nur für Methoden/Ctor-Params gültig),
  auf `<c>isVisible</c>` geändert. **Phase W6 Zusammenfassung:** async-Autorisierungs-Seam (W6.1), Dispatcher
  awaitet ihn (W6.2), TREE_CONNECT off-barrier (W6.3 = Connect-Freeze-Fix), Builder-Ergonomie (W6.4),
  Regel/Doku (W6.5). **Offen bleibt W6.2b** (Enumeration `IsVisible` async — synchroner srvsvc-RPC-Pfad,
  selteneres Browsing-Szenario, bewusst zurückgestellt). Gesamt-Freeze-Status für dieses Deployment: Backend-/
  Per-Datei-Latenz (W2, `ConcurrentMetadataOps`) **und** I/O-gebundene Connect-Auth (W6) sind mit einem Flag +
  async-Policy abgedeckt.
- _(hier Fortschritt anhängen, Items in den Phasen abhaken)_
