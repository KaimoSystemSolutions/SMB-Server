# Sicherheits-/Normkonformitäts-Audit — Smb.Server

**Audit-Stand:** 2026-06-28 · **Code-Marker:** `[AUDIT-2026-06]` (grepbar) · **Suite:** 150 Tests grün

Dieses Dokument ist das nachprüfbare Ledger des Audits. Jedes Finding hat eine stabile ID
(`H#` = hoch, `M#` = mittel, `L#` = niedrig, `O#` = offen/bewusst zurückgestellt). Behobene Findings
sind im Code mit `[AUDIT-2026-06]` markiert und durch einen Regressionstest abgesichert.

So findet man alles wieder:

```bash
grep -rn "AUDIT-2026-06" src tests          # alle berührten Stellen
dotnet test --filter FullyQualifiedName~AuditFixTests   # die Fix-Regressionstests
```

> **Wie dieses Dokument pflegen:** Wird ein offenes Finding (`O#`) bearbeitet, hierher den Status
> umstellen, Code-Marker setzen und Test ergänzen. Wird ein Fix zurückgebaut, schlägt der zugehörige
> Test an — die „Re-Verifikation"-Zeile nennt ihn.

---

## Behoben

### H1 — Unbegrenzt ausstehende async-Operationen (DoS)
- **Risiko:** Ein Client konnte beliebig viele blockierende `LOCK`/`CHANGE_NOTIFY` offenhalten; jede
  hält einen `PendingRequest` (+ ggf. einen `FileSystemWatcher`) → Speicher-/Handle-Erschöpfung.
- **Ursache:** `CreditManager.IsWithinWindow`/`ComputeCreditCharge` waren toter Code; keinerlei
  Begrenzung ausstehender Operationen.
- **Fix:** Neue Option `SmbServerOptions.MaxOutstandingRequests` (Default 512). `HandleLock`
  (blockierender Zweig) und `HandleChangeNotify` lehnen bei Erreichen der Grenze mit
  `STATUS_INSUFFICIENT_RESOURCES` ab.
- **Dateien:** `SmbServerOptions.cs`, `Smb2Dispatcher.Locking.cs`, `Smb2Dispatcher.Notification.cs`,
  `NtStatus.cs` (neuer Code `InsufficientResources = 0xC000009A`).
- **Re-Verifikation:** `AuditFixTests.OutstandingAsyncRequests_AreCappedPerConnection`.

### H2 — MessageId-Sequenzfenster nicht durchgesetzt
- **Risiko:** Replays und wild springende MessageIds wurden akzeptiert (Anti-Replay nur durch Signatur,
  die einen identischen Frame aber gültig wiederholbar lässt). MS-SMB2 §3.3.5.2.3.
- **Ursache:** `SequenceWindowStart/Size` wurden gesetzt, aber nie gelesen; `IsWithinWindow` ungenutzt.
- **Fix:** `Smb2Dispatcher.ValidateSequence` prüft jede MessageId gegen `[Start, Start+Size)` und zieht
  die Untergrenze nach (Anfragen treffen pro Verbindung monoton ein). **Ausgenommen** (bewusst):
  vor abgeschlossenem NEGOTIATE, NEGOTIATE selbst, CANCEL (referenziert eine bereits konsumierte
  MessageId), Related-Compound-Elemente.
- **Dateien:** `Smb2Dispatcher.cs` (`ValidateSequence`, Aufruf in `DispatchOne`).
- **Re-Verifikation:** `AuditFixTests.SequenceWindow_RejectsReplayedAndOutOfWindowMessageId`.
- **Bekannte Vereinfachung:** konstante Fenstergröße (= `MaxCreditsPerResponse`) statt exakter,
  mengenbasierter Credit-Buchhaltung. Für TCP-geordnete Single-Connection-Clients ausreichend;
  eine bitmap-genaue Umsetzung (echte Credit-Erweiterung) bleibt offen → siehe O6.

### H3 — `MaximalAccess` der Autorisierungs-Policy beim CREATE ignoriert
- **Risiko:** `GrantedAccess = DesiredAccess` ungefiltert → eine Policy mit reduzierten Rechten
  (z.B. `ReadOnly` pro User/Gruppe) war für Datei-Operationen **wirkungslos**; nur das globale
  `readOnly`-Flag des FileStore begrenzte.
- **Fix:** `HandleCreate` vergleicht den DesiredAccess (auf Intent-Ebene Read/Write/Delete) gegen
  `tree.MaximalAccess` und lehnt mit `STATUS_ACCESS_DENIED` ab, wenn mehr verlangt als gewährt wird.
  `MAXIMUM_ALLOWED` gewährt genau die erlaubte Maske.
- **Dateien:** `Smb2Dispatcher.FileCommands.cs` (`HandleCreate`).
- **Re-Verifikation:** `AuditFixTests.Create_WriteAccess_DeniedWhenPolicyGrantsReadOnly`,
  `…_AllowedWhenPolicyGrantsReadWrite`.

### H4 — Symlink-Sandbox-Escape im LocalFileStore
- **Risiko:** `LocalFileStore.TryResolve` prüfte nur die String-Kanonisierung (`Path.GetFullPath` +
  Prefix-Check). `GetFullPath` **folgt keinen Symlinks** — ein Symlink *innerhalb* des Shares, der nach
  außen zeigt, bestand den Prefix-Check und wurde beim Öffnen vom OS verfolgt → Lesen/Schreiben
  außerhalb der Share-Wurzel. Besonders kritisch unter Unix/ZFS (TrueNAS), wo unprivilegierte Symlinks
  Standard sind. (Korrigiert die frühere Zusage „Pfad-Traversal-Schutz … keine Lücke", die nur `..`/
  Slashes/Drive-relative abdeckte, nicht Symlinks.)
- **Fix:** Zweites Gate `IsWithinRealRoot` nach dem String-Check: `TryResolveRealPath` löst den realen
  Pfad auf, indem es an **jeder existierenden Komponente** dem Reparse-Point/Symlink folgt (manuelles
  `realpath` über `FileSystemInfo.ResolveLinkTarget(returnFinalTarget: true)`), und prüft die
  Containment gegen die ebenfalls aufgelöste Wurzel `_realRoot`. Fail-closed: unauflösbar (zyklisch/
  defekt/Fehler) → `null` → Zugriff verweigert. Nicht-existierende Endsegmente (anzulegende Datei)
  enthalten keinen Link und werden unverändert angehängt.
- **Dateien:** `LocalFileStore.cs` (`TryResolve`, `IsWithinRealRoot`, `TryResolveRealPath`, `_realRoot`).
- **Re-Verifikation:** `SymlinkSandboxTests` (Escape über Verzeichnis- **und** Datei-Symlink verweigert;
  normaler In-Root-Zugriff und Zugriff unter symlink-verlinkter Wurzel weiterhin erlaubt). Linux-CI
  testet mit echten Symlinks; auf Windows ohne Developer Mode greift ein Junction-Fallback.

### O2 — QUERY_DIRECTORY ohne Paging + instabile FileId (behoben)
- **Risiko:** Das gesamte Listing wurde in einen Buffer serialisiert; passte es nicht in die
  `OutputBufferLength` des Clients → `INVALID_PARAMETER` statt Paging → **große Verzeichnisse nicht
  listbar**. Zusätzlich `Name.GetHashCode()` als FileId/IndexNumber (prozess-randomisiert, kollisionsanfällig).
- **Fix:** `FsccStructures.BuildDirectoryListing(…, maxBytes, out written)` füllt budgetgenau; der
  Dispatcher snapshotted das Listing beim Scan-Start (`SmbOpen.DirectoryListing`/`DirectoryCursor`) und
  liefert es **seitenweise** über mehrere QUERY_DIRECTORY-Aufrufe (RESTART_SCAN/SINGLE_ENTRY beachtet;
  leerer Folgeabruf → `NO_MORE_FILES`; passt nicht mal ein Eintrag → `INFO_LENGTH_MISMATCH`). Stabile
  FileId: neues `FileEntryInfo.IndexNumber`, vom Backend gesetzt (`LocalFileStore` → `PathId`, FNV-1a
  über den vollen Pfad statt randomisiertem Hash).
- **Dateien:** `FsccStructures.cs`, `Smb2Dispatcher.FileCommands.cs` (`HandleQueryDirectory`, `ToStat`),
  `SmbOpen.cs`, `FileSystemTypes.cs`, `LocalFileStore.cs` (`PathId`), `NtStatus.cs` (`InfoLengthMismatch`).
- **Re-Verifikation:** `QueryDirectoryPagingTests` (Paging über mehrere Seiten, Single-Entry, Buffer zu
  klein → INFO_LENGTH_MISMATCH); `LocalFileStoreHandleTests.FileId_IsStableAcrossCalls_AndDistinctPerFile`.

### O5 — LocalFileStore ohne OS-Handle + ShareAccess nicht durchgesetzt (behoben)
- **Risiko:** Jeder READ/WRITE öffnete einen frischen `FileStream`; das `IFileHandle` hielt kein echtes
  OS-Handle. Die CREATE-`ShareAccess`-Sharing-Modes wurden **gar nicht** durchgesetzt → zwei Clients
  bekamen „exklusiv" gleichzeitig → **stille Datenkorruption** (Office/DB-artige Apps). Zudem leakten
  Handles bei abruptem Disconnect (Opens wurden nie geschlossen).
- **Fix:** (1) `LocalFileHandle` hält **ein** persistentes `FileStream` je Open (READ/WRITE/Flush/SetEOF/
  Rd-while-open via `FileShare.Delete`). (2) Neue Naht `IShareModeManager` (Default `InMemoryShareModeManager`)
  setzt die Windows-Sharing-Regel **symmetrisch** und **portabel** durch — vor dem Backend-Create (kein
  Seiteneffekt bei Konflikt) → `SHARING_VIOLATION`; bewusst in-process statt OS-`FileShare`, da Unix/ZFS
  (TrueNAS) Letzteres nicht erzwingt. (3) `Smb2Dispatcher.OnConnectionClosed` + Logoff schließen jetzt
  alle Opens (Handle/Lock/Oplock/Share-Mode), kein Leak mehr.
- **Dateien:** `LocalFileStore.cs`, `Sharing/IShareModeManager.cs`, `Sharing/InMemoryShareModeManager.cs`,
  `SmbServerOptions.cs`, `SmbServerBuilder.cs`, `Smb2Dispatcher.FileCommands.cs` (`HandleCreate`/`HandleClose`/
  `OnConnectionClosed`), `Smb2Dispatcher.cs` (Logoff), `SmbConnectionHandler.cs` (Teardown), `SmbOpen.cs`.
- **Re-Verifikation:** `ShareModeManagerTests` (Kompatibilitäts-Matrix), `LocalFileStoreHandleTests`
  (Roundtrip/DeleteOnClose/Rename-while-open), `QueryDirectoryPagingTests` (SHARING_VIOLATION + Freigabe nach CLOSE).
- **Restpunkt:** OS-`FileShare` wird permissiv geöffnet (`ReadWrite|Delete`); die Sharing-Semantik liegt
  bewusst im `IShareModeManager` (cluster-/cross-protocol-fähig über eine eigene Implementierung).

### M1 — AEAD-Nonce zufällig statt Zähler
- **Risiko:** MS-SMB2 §3.3.4.1.4 verlangt einen je `EncryptionKey` eindeutigen, monoton steigenden
  Nonce. Ein zufälliger 11/12-Byte-Wert läuft in die Geburtstagsgrenze; bei AES-GCM ist
  Nonce-Wiederholung katastrophal.
- **Fix:** Session-lokaler Zähler `SmbSession.NextEncryptionNonce()`; Host baut die Nonce daraus
  (`BuildNonce`, LE in den ersten 8 Byte). Eindeutig pro Session/Key.
- **Dateien:** `SmbSession.cs`, `SmbConnectionHandler.cs`.
- **Re-Verifikation:** durch `PerShareEncryptionTests`/`TransformAndPreauthTests` (Roundtrip bleibt
  gültig). **Offen:** kein Test, der die *Monotonie/Eindeutigkeit* zweier aufeinanderfolgender
  Nonces direkt prüft (nicht über die öffentliche Host-API zugänglich) → siehe O7.
- **Restrisiko:** Zähler-Überlauf bei 2⁶⁴ Nachrichten/Session nicht behandelt (praktisch irrelevant).

### M2 — Signatur-Pflicht wurde durch Verschlüsselung dauerhaft abgeschaltet (Downgrade)
- **Risiko:** Der Host setzte nach dem ersten entschlüsselten Frame `session.SigningRequired = false`
  *dauerhaft*. War `RejectUnencryptedAccess` aus, akzeptierte die Session danach **unsignierte
  Klartext-Kommandos** → Downgrade.
- **Fix:** Signing- und Encryption-Status sind entkoppelt. `session.SigningRequired` wird nicht mehr
  verändert. Stattdessen überspringt `VerifyInboundSignature` die Signaturprüfung **nur für den
  jeweils verschlüsselt empfangenen Frame** (`_frameWasEncrypted`), da das AEAD ihn bereits
  authentifiziert (§3.1.4.1). `session.EncryptData = true` (Antwort-Pflicht) bleibt.
- **Dateien:** `SmbConnectionHandler.cs`, `Smb2Dispatcher.cs` (`VerifyInboundSignature`,
  `_frameWasEncrypted`).
- **Re-Verifikation:** bestehende `PerShareEncryptionTests` (verschlüsselter Fluss bleibt gültig) +
  `DispatcherEndToEndTests.SigningRequired_SignedEchoAccepted_UnsignedRejected` (Klartext-Pflicht
  unverändert).

### M3 — AES-256-Cipher-Keys nutzten den vollen GSS-Key als KDK (vermutliche Normabweichung)
- **Risiko:** MS-SMB2 §3.3.5.5.3 kürzt `Session.SessionKey` immer auf 16 Byte; §3.1.4.2 nutzt genau
  diese als KDK für **alle** abgeleiteten Keys (nur die Output-Länge `L` wird 256). Der volle GSS-Key
  als KDK hätte mit Kerberos+AES-256 abweichende Keys erzeugt → Interop-Bruch mit Windows.
- **Status:** Bei NTLM (16-Byte-Key) **wirkungsgleich**, daher latent. Fix behebt es vorsorglich.
- **Fix:** `Smb3KeyDerivation` nutzt für die Cipher-Keys immer die 16-Byte-`SessionKey`. Der
  Parameter `fullSessionKey` bleibt in der Signatur (bewusst ungenutzt).
- **Dateien:** `Smb3KeyDerivation.cs`, `SmbSession.cs` (Doku).
- **Re-Verifikation:** `SigningAndKdfTests.Smb3KeyDerivation_311Aes256_DerivesFrom16ByteSessionKey_NotFullKey`.
- **⚠️ Explizit erneut prüfen:** Vor produktivem Kerberos+AES-256 gegen eine **echte Windows-Interop-
  Aufzeichnung** (Wireshark/MS-SMB2-Testvektor) verifizieren — es existiert kein offizieller KAT für
  die vollständige SMB3-Key-Derivation in dieser Lib.

### M4 — LOGOFF ohne Signaturprüfung
- **Risiko:** `HandleLogoff` prüfte — anders als alle anderen Session-Handler — keine Signatur; ein
  eingeschleustes LOGOFF konnte eine signaturpflichtige Session abreißen.
- **Fix:** `VerifyInboundSignature` in `HandleLogoff` ergänzt.
- **Dateien:** `Smb2Dispatcher.cs` (`HandleLogoff`, Signatur um `segment` erweitert).
- **Re-Verifikation:** `AuditFixTests.Logoff_Unsigned_RejectedWhenSigningRequired`.

### L1 — Toter Ternary in `PreauthIntegrityHash.Append`
- `combinedLen <= 4096 ? new byte[combinedLen] : new byte[combinedLen]` (identische Zweige) →
  vereinfacht. Rein kosmetisch. Datei: `PreauthIntegrityHash.cs`.

---

## Offen (bewusst zurückgestellt — bei Gelegenheit prüfen)

| ID | Thema | Risiko | Empfehlung |
|----|-------|--------|------------|
| **O1** | **NTLM-MIC nicht verifiziert** (`NtlmCryptography.ComputeMic` existiert, wird serverseitig nie aufgerufen) | Kein NTLM-Downgrade-Schutz (Manipulation der NEGOTIATE-Flags unentdeckt) | MIC im `NtlmServerMechanism.HandleAuthenticate` gegen die drei Nachrichten prüfen, sofern `MsvAvFlags` ihn ankündigt. War bereits im README als offen vermerkt. |
| **O3** | **3.1.1-NEGOTIATE** validiert nicht, ob der Client einen PreauthIntegrity-Context (mit SHA-512) gesendet hat | §3.3.5.4 verlangt sonst Fehlschlag | Vorhandensein + Algorithmus prüfen, sonst `INVALID_PARAMETER`. |
| **O4** | **SESSION_SETUP vor NEGOTIATE** wird nicht abgewiesen | Robustheit/undefinierter Zustand | In `HandleSessionSetup` `connection.NegotiateDone` prüfen. |
| **O6** | **Credit-Buchhaltung** ist eine konstante Fenstergröße, keine exakte, mengenbasierte Erweiterung (siehe H2) | Geringe Genauigkeit ggü. Spec; für Single-Connection unkritisch | Bitmap-genaues Sequenzfenster + dynamische Credit-Erweiterung. |
| **O7** | **Kein Direkttest** der AEAD-Nonce-Monotonie (siehe M1) | Test-Lücke | Nonce-Zähler über eine test-sichtbare Schnittstelle prüfbar machen. |

---

## Geprüft & in Ordnung (kein Handlungsbedarf)

- **Krypto-Kern** gegen offizielle Vektoren verifiziert: AES-CMAC (RFC 4493), MD4 (RFC 1320),
  NTOWFv2 (MS-NLMP §4.2.2); Sign/Verify + Tamper für alle drei Algorithmen.
- **Preauth-Integrity-Reihenfolge** (Request/Zwischenantwort einbeziehen, finale Antwort nicht) korrekt.
- **Pfad-Traversal-Schutz** (`LocalFileStore.TryResolve`): Kanonisierung + Prefix-Check (`..`,
  Forward-Slashes, Drive-relative Pfade) **und** symlink-aufgelöste Real-Path-Containment (siehe H4).
- **Byte-Range-Lock-Manager**: overflow-sicheres Overlap (`UInt128`), atomare Multi-Locks,
  race-sicherer `NotifyOnce` bei CHANGE_NOTIFY.
- **Compound-Signierung** pro Segment (inkl. Padding) korrekt.
