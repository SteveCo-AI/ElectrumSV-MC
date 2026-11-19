# ElectrumSV-MC — lokale Testfassung

Dieser Stand wurde anhand von Commit `bab27657a1465b99f0f027901a13d117136a19dd` neu aufgebaut. Der verlorene Patch konnte nicht bytegenau wiederhergestellt werden. Die Quellen enthalten die vorgenommenen Änderungen; das ursprüngliche Archiv enthielt kein kompiliertes Programm und keine echten Wallet-Dateien. Ein Linux-Release-Artefakt für die TLS- und History-Erweiterung wurde erstellt.

**Nicht für echte Guthaben oder reale Seeds verwenden.** Zu den offenen Punkten gehören fehlende unabhängige Chainvalidierung, Klartextspeicherung des TOTP-Geheimnisses, unsichere Altdatenpfade sowie nicht vollständig geprüfte Wiederherstellung. `KNOWN_ISSUES.md` enthält die konkreten Grenzen. Import privater Schlüssel und Legacy-Migration sind gesperrt.

## Vorbereitung

Benötigt werden Git, Node.js/npm, Rust mit Cargo und Tauri CLI 2. Auf Linux außerdem die vom Tauri-Projekt benötigten GTK- und WebKitGTK-Entwicklungsbibliotheken. Unter Windows werden die Microsoft-C++-Buildwerkzeuge und WebView2 benötigt. Das Projekt ist nur auf Linux im Build untersucht worden; Windows/macOS benötigen eigene Prüfung.

Im entpackten Projektverzeichnis:

```sh
cd gui
npm ci
cd ../src-tauri
cargo install tauri-cli --version '^2' --locked
cargo tauri dev
```

Für Windows dieselben Befehle in PowerShell ausführen. Der erste Rust-Build lädt zusätzliche Abhängigkeiten, darunter das in `Cargo.lock` referenzierte PicQr-Git-Repository.

## Lokale Prüfung

Erstelle ausschließlich eine neue Wegwerf-Wallet ohne echtes Guthaben. Prüfe Erstellen, Entsperren, Empfangsansicht, Backup und 2FA sowie eine Netzverbindung zu einem BSV-ElectrumX-Server. Für Wiederherstellung nur bekannte Testdaten nutzen. Dokumentiere Fehlermeldungen ohne Seeds, Passwörter, private Schlüssel oder 2FA-Codes zu teilen. Ein Seed-Wiederherstellungsscan erfolgt beim ersten Sync mit einem Abstand von 20 unbenutzten Adressen pro Kette und findet nicht unbedingt alle Gelder. Ein positiver Serverstatus beweist keine korrekte oder sichere Wallet.

Automatische Tests:

```sh
cd gui && npm test -- --run
cd ../src-tauri && cargo test --locked --no-default-features
```

Das finale Linux-Offlinebündel bestand mit 571 Lib-, 12 Agenten-, 1 Lifecycle- und 3 Walletlisten-Tests (587 insgesamt); der TLS-Loopback-Test war darin ausgeschlossen. Der TLS-Loopback-Test bestand separat auf dem aktuellen Snapshot (1/1). Die unveränderte GUI-Suite bestand zuvor 26 Tests. Der separate WAL-Test bestand 1/1: Der nur im WAL vorhandene Marker fehlte in einer Kopie der Hauptdatei und war im Backup vorhanden. Quellhash des finalen Stands: `16975870027d403990775892b18f8d5d0fc5df874a6deeecf8d5a2f77299ca02`.

Der frühere Testlauf prüfte unter anderem Signatur mit SDK-Scriptvalidierung, Gebühren anhand serialisierter Transaktionen und Größenübergängen, Mock-Broadcast, TOTP-Wiederholung, expliziten Retry bei unbekanntem Ergebnis und SIGNED-Persistenz nach erzwungenem Prozessende. Testdaten werden durch Fixtures eingebracht, nicht über produktive RPCs. Der GUI-Start und der Wallet-Listen-IPC wurden für das damalige Release geprüft. Screenshots, visuelle Interaktion, vollständige GUI-Abläufe, realer Broadcast, Windows/macOS und die Sicherheit für echtes Guthaben sind nicht verifiziert.

## Lokales Linux-Release-Artefakt

Das Release `0.1.1` unter `src-tauri/target/release/electrumsv-mc` wurde erfolgreich gebaut: Linux x86_64, dynamisch gelinktes und gestripptes ELF; `ldd` meldete auf dem Build-Host keine fehlenden Bibliotheken. SHA-256:

```text
45659e194a4b6836981f48ac7d47c99bc3304d054e6c156f722dd64a8d3ed121
```

Ein Offline-Release-Smoke prüfte mit ausschließlich aktivierter Maintenance-Freigabe die Ablehnung falscher und leerer Passwörter, Backup ohne Überschreiben, Passwortwechsel, Neustart mit altem und neuem Passwort sowie das Öffnen einer separaten Backupkopie mit dem alten Passwort. Ein weiterer Offline-Smoke prüfte TOTP, Signatur und TXID, Reservierung und Neustart; Netzwerk und Broadcast waren aus. Die SDK-Scriptvalidierung gehört zu den nativen Tests, nicht zu diesem Smoke.

Ein früheres Release `5f4434dd…` bestand einen Live-TLS-Smoke: Sync, Saldo 0 und 81 History-Einträge mit einer öffentlichen Test-Wallet, ohne Zahlung oder Broadcast. Das aktuelle Binary wurde noch nicht live geprüft. Serverwahrheit und unabhängige Chainvalidierung sind nicht belegt. Das aktualisierte Werkzeug `tools/live_electrumx_smoke.py` erwartet den neuen Hash und fragt History mit Limit 500 ab.

```sh
agent_dir=$(mktemp -d)
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"get_wallet_status","params":{}}' | \
  ./src-tauri/target/release/electrumsv-mc --agent --data-dir "$agent_dir"
```

Für einen GUI-Start ein anderes, neues Verzeichnis verwenden:

```sh
gui_dir=$(mktemp -d)
ELECTRUMSV_DATA_DIR="$gui_dir" ./src-tauri/target/release/electrumsv-mc
```

GUI-Start und Wallet-Listen-IPC wurden nur mit dem früheren Release `9269d458…` geprüft; beim neuen Release sind GUI-Start, visuelle Interaktion und Zahlungsabläufe noch offen.

Ein Versuch einer privaten visuellen Prüfung blieb ohne Bildnachweis: Cage mit Headless-/Pixman-Backend scheiterte an der Swapchain; KWin mit virtuellem XWayland startete im isolierten Netzwerk- und temporären Dateikontext teilweise, aber das Testfenster meldete „Can't open display“ und EGL einen DRI2-Fehler. Dabei wurde weder die Wallet gestartet noch ein Nutzerdesktop aufgenommen; installiert wurde nichts. Für die visuelle Abnahme ist ein funktionsfähiger privater Displayserver nötig, etwa Xvfb, das hier derzeit nicht vorhanden ist; alternativ müssen Renderer und XWayland separat repariert werden.

## Optionale lokale Agentenschnittstelle

Der Agentenmodus ist standardmäßig aus und wird für jeden Prozess ausdrücklich mit `--agent --data-dir VERZEICHNIS` gestartet. Er hat keinen GUI-Schalter. Die JSON-RPC-Schnittstelle, Beispiele und Sicherheitsgrenzen stehen in [docs/agent-interface.md](docs/agent-interface.md). Für Versuche ein eigenes leeres Datenverzeichnis und ausschließlich Testdaten verwenden. Der aktuelle Lauf enthielt zwölf Agententests; das Release wurde zusätzlich ohne Netzwerk lokal geprüft.
