# Smb.Server — SMB 2/3 Server-Library (C# / .NET 8)

Eine modulare, testgetriebene **SMB-2/3-Server**-Bibliothek, implementiert nach den offiziellen
Microsoft Open Specifications (MS-SMB2, MS-FSCC, MS-NLMP, MS-ERREF, MS-SPNG, MS-DTYP).
Grundlage und Faktencheck: [`SMB2-3_Server_Context.md`](../SMB2-3_Server_Context.md).

> **Reifegrad.** Diese Lib ist ein **korrektes, voll getestetes Fundament** (Meilensteine
> M1–M6 weitgehend fertig; siehe [Roadmap](#roadmap)). Der wire-/krypto-kritische Kern ist
> gegen offizielle Testvektoren verifiziert. Datei-I/O (CREATE/READ/WRITE/QUERY_*/SET_INFO/
> CLOSE) läuft über ein `IFileStore`-Backend (`LocalFileStore`); Byte-Range-**LOCK** ist inkl.
> blockierender Locks (`STATUS_PENDING` + Interim-Antwort, `CANCEL`) implementiert und über
> einen austauschbaren `ILockManager` verdrahtet.

## Schnellstart

```csharp
using System.Net;
using Smb.FileSystem;
using Smb.Host;

await using var server = SmbServerBuilder.Create()
    .WithEndpoint(IPAddress.Any, 445)        // Port frei wählbar (445 ggf. vom OS belegt)
    .WithServerName("MYSERVER")
    .RequireSigning(true)                    // sicherer Default (Context §20)
    .UseDevAuthentication()                  // NUR Test/Dev — siehe Hinweis unten
    .AddShare(new Share { Name = "Data", Type = ShareType.Disk /*, FileStore = … */ })
    .WithLogger(Console.WriteLine)
    .Build();

await server.StartAsync();
Console.WriteLine($"Lauscht auf {server.Endpoint}");
Console.ReadLine();
await server.StopAsync();
```

> ⚠️ `UseDevAuthentication()` akzeptiert **jede** Anmeldung anonym und ist ausschließlich für
> Tests/Entwicklung gedacht. In Produktion einen echten Auth-Provider setzen:
> `.UseAuthentication(meinNtlmOderKerberosNegotiator)`.

## Beispielprojekt

Ein lauffähiges Beispiel liegt unter [`examples/Smb.Sample.Server`](examples/Smb.Sample.Server/Program.cs):
echter **NTLM-Login** + ordner-basierter Share (relativer `shared/`-Ordner). Es startet den Server,
führt einen **TCP-Selbsttest** aus (anmelden → Verzeichnis listen → Datei lesen) und bleibt laufen.

```bash
dotnet run --project examples/Smb.Sample.Server
# Anmeldung:    WORKGROUP\demo / demo123
# === Selbsttest (echter TCP-Client) ===
# Login als WORKGROUP\demo: OK
# Login mit falschem Passwort wird abgelehnt: OK
# Dateien im Share: ., notizen.txt, welcome.txt
# Inhalt von welcome.txt: Hallo aus dem SMB-Share! …
```

So konfiguriert man echtes Login + Datei-Backend in eigenem Code:

```csharp
var users = new InMemoryIdentityBackend().AddUser("WORKGROUP", "demo", "demo123");
await using var server = SmbServerBuilder.Create()
    .WithEndpoint(IPAddress.Any, 445)
    .UseAuthentication(new NtlmSpnegoNegotiator(users, new NtlmServerOptions { NetbiosDomainName = "WORKGROUP" }))
    .AddShare(new Share { Name = "Files", Type = ShareType.Disk,
                          FileStore = new LocalFileStore(@"C:\daten\freigabe", readOnly: true) })
    .Build();
await server.StartAsync();
```

## Architektur

Strikte Schichtung *Parse ↔ State ↔ Effect* (Context §2) — jede Schicht ein eigenes Projekt,
ohne Zyklen:

| Projekt | Inhalt |
|---|---|
| **Smb.Protocol** | Reine Wire-Typen: NBSS-Framing, SMB2-Header (sync/async), Enums, Negotiate/SessionSetup/TreeConnect/Echo, Transform-Header. Span-basiert, Little-Endian. Kein I/O, kein State. |
| **Smb.Crypto** | Signing (HMAC-SHA256 / AES-CMAC / AES-GMAC), AEAD-Transform (AES-CCM/GCM 128/256), SP800-108-KDF, SMB-3-Key-Derivation, SHA-512-Preauth-Hash, MD4 + NTLMv2-Krypto. |
| **Smb.Auth** | GSS/SPNEGO-Abstraktion: `IGssMechanism`, `ISpnegoNegotiator`, `IIdentityBackend`. SPNEGO-Token-Kodierung (ASN.1-DER), OIDs, In-Memory-Backend, Dev-Negotiator. |
| **Smb.FileSystem** | `IShare` / `IFileStore`-Backend-Abstraktion (NTFS-Semantik auf beliebiges Backend). |
| **Smb.Server** | Zustandsmodell (Connection/Session/TreeConnect/Open), Credit-Logik, Negotiate-Prozessor, Command-Dispatcher (Empfangs-Pipeline §19.1). |
| **Smb.Host** | TCP-Listener (Default 445), per-Connection-Lese-Loop, NBSS-/Transform-Handling, Fluent-Builder. |

### Modulare Authentifizierung (Kern der Anforderung)

SESSION_SETUP spricht **nur** mit `ISpnegoNegotiator`. Neue Mechanismen = neues
`IGssMechanism` registrieren; neue Identitätsquelle (z.B. LDAP/AD) = neues `IIdentityBackend` —
**ohne Eingriff** in Protokoll- oder Server-Schicht (Context §9).

```
ISpnegoNegotiator  ──>  IGssMechanism (NTLM heute, Kerberos später)
                                │
                                └──>  IIdentityBackend (lokal heute, LDAP/AD später)
```

## Sicherheits-Defaults (Context §20)

- SMB1-Dateizugriff **aus** (nur Negotiate-Upgrade-Pfad vorgesehen).
- **Signing erforderlich** per Default; 3.1.1 bevorzugt mit **Preauth-Integrity** (SHA-512).
- Cipher-Präferenz **AES-128-GCM** > AES-256-GCM > AES-128-CCM > AES-256-CCM.
- Signing-Präferenz **AES-GMAC** > AES-CMAC > HMAC-SHA256.
- **Guest/Anonymous standardmäßig abgelehnt.**
- **Per-Share-Verschlüsselung** erzwingbar (`Share.EncryptData`): Antworten werden verschlüsselt,
  und unverschlüsselte Zugriffe auf einen verschlüsselten Tree werden mit `RejectUnencryptedAccess`
  (Default an) abgelehnt; ein verschlüsselter Share auf einer Verbindung ohne 3.x-Cipher → `ACCESS_DENIED`.
- Krypto ausschließlich über die .NET-BCL (`System.Security.Cryptography`).

> **Sicherheits-Audit:** Stand und offene Punkte siehe [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md)
> (behobene Findings sind im Code mit `[AUDIT-2026-06]` markiert und durch `AuditFixTests` abgesichert).
> Noch offen u.a.: NTLM-MIC-Verifikation (O1), QUERY_DIRECTORY-Paging (O2). ⚠️ AES-256-Key-Derivation
> (M3) vor Kerberos-Einsatz gegen eine echte Windows-Interop-Aufzeichnung gegenprüfen.

## Verifikation

Build & Tests:

```bash
dotnet test
```

Die Suite (131 Tests) deckt u.a. ab:

- **Offizielle Krypto-Vektoren:** AES-CMAC (RFC 4493 §4), MD4 (RFC 1320 A.5),
  NTOWFv2 (MS-NLMP §4.2-Beispiel).
- Wire-Roundtrips: Header (sync/async), NBSS (Big-Endian-Längenpräfix), Negotiate-Contexts
  (8-Byte-Alignment, Offset-Korrektheit).
- Krypto: KDF-Determinismus, Schlüssel-Ableitung (3.0/3.1.1, AES-128/256, `ServerIn `-Label
  mit Leerzeichen), Sign/Verify + Tamper-Erkennung (alle 3 Algorithmen), Transform-Roundtrip
  + AEAD-Tag-Prüfung, Preauth-Hash-Kette.
- Server end-to-end: NEGOTIATE → SESSION_SETUP → TREE_CONNECT → ECHO; Dialektwahl;
  Cipher-/Signing-Aushandlung; Signaturpflicht (signiert akzeptiert, unsigniert abgelehnt);
  Guest-Ablehnung; TCP-Integration über echtes NBSS.
- Per-Share-Encryption: Tree-Markierung + ShareFlags, Klartext-Request auf verschlüsseltem Tree
  abgelehnt (`RejectUnencryptedAccess`), Encrypted-Share-Connect ohne Cipher abgelehnt, und der
  Host liefert die TREE_CONNECT-Antwort eines verschlüsselten Shares als TRANSFORM-Frame zurück.
- Oplocks: Grant des angeforderten Levels auf einem Solo-Open (Batch/Exclusive), Herabstufung auf
  Level II + OPLOCK_BREAK-Notification bei einem zweiten Open derselben Datei, Acknowledgment-Quittung,
  Freigabe beim CLOSE; Lease-Break-Acknowledgment (noch) → `STATUS_NOT_SUPPORTED`.
- Audit-Fixes (`AuditFixTests`): LOGOFF-Signaturpflicht, MessageId-Sequenzfenster (Replay/Out-of-Window
  abgelehnt), MaximalAccess-Durchsetzung beim CREATE, Obergrenze ausstehender async-Operationen.

## Roadmap

| Meilenstein | Status |
|---|---|
| M1 Transport & Parsing | ✅ |
| M2 Negotiate (inkl. 3.1.1-Contexts, Preauth-Hash) | ✅ |
| M3 Auth (SPNEGO + **echtes NTLMv2-Login**, Key-Derivation, Signing) | ✅ (MIC-Verifikation noch offen) |
| M4 Tree & Dateizugriff (CREATE/READ/QUERY_DIRECTORY/QUERY_INFO/CLOSE) | ✅ über `LocalFileStore` |
| M5 Schreiben (WRITE, SET_INFO/Rename/Delete ✅; **Byte-Range-LOCK ✅** inkl. blockierend + CANCEL, austauschbarer `ILockManager`) | ✅ |
| M6 Encryption & Härtung (Transform-Pfad) | ✅ Per-Share-Encryption verdrahtet (Tree-`EncryptData`, Antwort-Verschlüsselung inkl. TREE_CONNECT-Response) + Härtung: `RejectUnencryptedAccess` (Default an) lehnt Klartext-Zugriff auf verschlüsselte Trees ab; Encrypted-Share-Connect ohne 3.x-Cipher → `ACCESS_DENIED` |
| Share-Enumeration (srvsvc NetrShareEnum über DCERPC/IPC$, IOCTL FSCTL_PIPE_TRANSCEIVE) | ✅ |
| SMB1→SMB2 Negotiate-Upgrade (§6.1, für impacket u.a.) | ✅ |
| M7 **CHANGE_NOTIFY ✅** (austauschbarer `IDirectoryWatcher`); **Oplocks ✅** (austauschbarer `IOplockManager`: Grant + OPLOCK_BREAK-Notification + Acknowledgment + Freigabe); **Leases** & Compound-Feinschliff offen | 🟡 |
| Native Windows-Explorer-Interop (volle FSCC/IOCTL-Abdeckung, Secure Negotiate) | ⬜ |
| M8 Kerberos, LDAP-Backend, Multichannel, Durable Handles, DFS, QUIC, RDMA | ⬜ |

### Nächste konkrete Schritte für ein lesendes Share

1. `IFileStore`-Implementierung auf lokales Dateisystem (Backend-Handles, NT-Zeiten/Attribute).
2. CREATE-Handler (Disposition, Sharing-Violation, Create-Contexts `MxAc`/`QFid`).
3. QUERY_DIRECTORY (`FileIdBothDirectoryInformation`), QUERY_INFO, READ, CLOSE.
4. Echter NTLMv2-`IGssMechanism` über die vorhandene `Smb.Crypto.NtlmCryptography`.

## Lizenzhinweis

Die zugrunde liegenden Microsoft Open Specifications stehen unter der Open Specifications
Promise. Strukturen/Konstanten wurden neu implementiert (keine wörtlichen Textübernahmen).
