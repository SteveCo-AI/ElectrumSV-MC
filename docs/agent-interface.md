# Lokale Agentenschnittstelle

Der nachfolgende Vertrag beschreibt den aktuellen Quellstand und das zugehörige Migrationsrelease.

Der Agentenmodus ist standardmäßig deaktiviert. Er wird pro Prozess ausdrücklich gestartet; es gibt keinen GUI-Schalter. Nach einem Build kann er zum Beispiel mit einem eigenen, leeren Testverzeichnis gestartet werden:

```sh
testdir=$(mktemp -d)
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"get_wallet_status","params":{}}' | \
  ./src-tauri/target/debug/electrumsv-mc --agent --data-dir "$testdir"
```

Der Pfad ist ein Beispiel für das Debug-Binary. `--data-dir` ist Pflicht und muss ein nicht leerer UTF-8-Pfad sein; das Verzeichnis wird bei Bedarf angelegt. Ein EOF auf stdin beendet den Prozess. Für mehrere Aufrufe dieselbe stdin offen halten und die Antwort nach jedem Aufruf lesen.

## Freigaben

Zusätzlich zum Pflichtparameter `--data-dir` aktiviert `--enable-payments` die Zahlungs- und TOTP-Methoden, `--allow-network` die explizite Verbindung und Synchronisation und `--allow-broadcast` das Senden. Letzteres setzt beide anderen Schalter voraus. `--enable-wallet-maintenance` schaltet unabhängig davon Backup, Passwortwechsel, TOTP-Deaktivierung und Recovery-Code-Verwaltung frei. Alle vier Freigaben sind pro Prozess standardmäßig aus; ein gesetzter Schalter startet weder eine Verbindung noch einen Broadcast. `get_capabilities` zeigt die aktiven Freigaben.

Nach einem Build im Projektverzeichnis, jeweils mit eigenem Testdatenverzeichnis:

```sh
# Nur Backup und Passwortwechsel freigeben
./src-tauri/target/debug/electrumsv-mc --agent --data-dir "$testdir" --enable-wallet-maintenance

# Nur Prepare/Sign, ohne Netzwerkfreigabe
./src-tauri/target/debug/electrumsv-mc --agent --data-dir "$testdir" --enable-payments

# Verbindung und Sync zusätzlich freigeben
./src-tauri/target/debug/electrumsv-mc --agent --data-dir "$testdir" --enable-payments --allow-network

# Broadcast zusätzlich freigeben; erfordert weiterhin einen eigenen RPC-Aufruf
./src-tauri/target/debug/electrumsv-mc --agent --data-dir "$testdir" --enable-payments --allow-network --allow-broadcast
```

Diese Beispiele sind Alternativen für separate Prozessstarts; `testdir` muss zuvor wie oben mit `mktemp -d` erstellt werden. Das Beispiel oben verwendet das Debug-Binary nach einem eigenen Build. Informationen zum aktuellen Linux-Release stehen in [START_HIER_DE.md](../START_HIER_DE.md#lokales-linux-release-artefakt).


## Protokoll

Die Kommunikation erfolgt über stdin und stdout als JSON-RPC-2.0-Objekte, jeweils ein Objekt pro Zeile. Eine Eingabe darf einschließlich Zeilenende höchstens 65.536 Bytes umfassen; größere Eingaben beenden den Prozess mit Fehler auf stderr. `params` ist ein Objekt und kann bei leeren Parametern entfallen. Eine Anfrage mit `id` erhält eine Antwort mit derselben ID, eine Notification ohne `id` keine Antwort. Nur Notifications für `list_wallets`, `get_wallet_status`, `get_capabilities`, `is_totp_enabled` und `verify_totp` werden ausgeführt; alle anderen werden ohne Aktion ignoriert. Andere wie `get_balance` oder Planstatus können abgelaufene Reservierungen bereinigen und benötigen daher eine Anfrage mit `id`. Fehler enthalten einen JSON-RPC-Fehlercode; Anwendungsfehler verwenden `-32000`.

| Methode | Parameter | Verhalten |
| --- | --- | --- |
| `get_capabilities` | keine | Zahlungs-, Netzwerk-, Broadcast- und Wallet-Maintenance-Freigaben anzeigen (`wallet_maintenance`). |
| `list_wallets` | keine | Wallet-Dateien im Datenverzeichnis auflisten. |
| `create_wallet` | `name`, `password`; optional `mnemonic`, `passphrase` | Wallet erstellen; ohne Mnemonic wird eine erzeugt. Die Antwort enthält `mnemonic`, `wallet_path`, `account_id`, `is_new_mnemonic`; die neue Wallet ist entsperrt. |
| `open_wallet` | `wallet_path` | Wallet innerhalb des Datenverzeichnisses öffnen; sie ist zunächst gesperrt. Ein bloßer Name erhält die Endung `.sqlite`. |
| `unlock_wallet` | `password`; optional `totp_code` | Wallet entsperren; falls 2FA eingerichtet ist, ist ein gültiger TOTP-Code erforderlich. |
| `close_wallet` | keine | Aktive Wallet schließen. |
| `backup_wallet` | `backup_path`, `password`; optional `totp_code` | Mit Wallet-Maintenance-Freigabe und Wallet-Passwort ein Backup innerhalb des Datenverzeichnisses erstellen; bestehende Ziele werden nicht überschrieben. |
| `change_password` | `old_password`, `new_password`; optional `totp_code` | Mit Wallet-Maintenance-Freigabe und bisherigem Passwort das Wallet-Passwort ändern; das neue Passwort darf nicht leer sein. |
| `get_wallet_status` | keine | Status einschließlich `is_open`, `is_unlocked`, `account_id` und gegebenenfalls `xpub`. |
| `get_history` | optional `account_id`, `limit`, `offset` | Lokalen Transaktionsverlauf abrufen; Standard sind 50 Einträge ab Offset 0. `limit` muss zwischen 1 und 500 liegen, `offset` mindestens 0; ungültige Werte ergeben Fehler `-32602`. Unbekannte Betragsänderungen werden als `null` zurückgegeben. |
| `get_balance` | optional `account_id` | Lokal gespeicherten Saldo abfragen; ohne ID das aktive Konto. |
| `get_receive_address` | optional `account_id` | Neue Empfangsadresse für das aktive Konto erzeugen und speichern; die Wallet muss entsperrt sein. |
| `begin_totp_setup` | `password` | Mit Zahlungsfreigabe Setup beginnen und vorläufiges Geheimnis und otpauth-URL erhalten. |
| `confirm_totp_setup` | `password`, `code` | Mit Zahlungsfreigabe Setup bestätigen und aktivieren. |
| `cancel_totp_setup` | keine | Mit Zahlungsfreigabe vorläufiges Setup verwerfen. |
| `enable_totp` | `password` | Alter Ein-Schritt-Aufruf nur für Legacy; Schema 34 lehnt ihn ab. |
| `disable_totp` | `password`, `code` | Mit Maintenance-Freigabe TOTP deaktivieren. |
| `generate_totp_recovery_codes` | `password`, `code` | Mit Maintenance-Freigabe neue einmalige Recovery-Codes erzeugen; bisherige verlieren ihre Gültigkeit. |
| `preview_migration` | `password`; optional `totp_code` | Mit Maintenance-Freigabe Inventur und Policyvorschau mit kurzlebigem Bestätigungstoken anfordern. |
| `migrate_wallet` | `password`, `backup_path`, `confirmation_token`; optional `totp_code` | Mit Maintenance-Freigabe und bewusst bestätigter Vorschau unterstützte Legacy-Wallet nach verifiziertem Backup migrieren; anschließend Wallet erneut öffnen. |
| `recover_totp` | `password`, `recovery_code` | Mit Maintenance-Freigabe Recovery auch bei gesperrter Wallet; deaktiviert TOTP und alle Recovery-Codes, Wallet bleibt gesperrt. |
| `is_totp_enabled` | keine | Mit Zahlungsfreigabe TOTP-Status abfragen; bei gesperrter Schema-34-Wallet `null` (unbekannt). |
| `verify_totp` | `code` | Mit Zahlungsfreigabe aktuellen TOTP-Code prüfen. |
| `connect_server` | `host`, `port` | Mit Netzwerkfreigabe explizit zum angegebenen ElectrumX-TLS-Ziel verbinden. |
| `disconnect_server` | keine | Mit Netzwerkfreigabe Verbindung trennen. |
| `sync_wallet` | optional `account_id`, `wallet_instance_token` | With network capability, synchronize over the existing connection. Supplying the token from `get_wallet_status` binds the request to that wallet instance; an old token is rejected. Existing callers may omit it and retain the previous unbound behavior. The token is an instance identifier, not authentication. A completed empty first discovery returns `synced: true` with a range and completeness warning, leaving its marker unset so discovery is repeated on the next sync. |
| `scan_address_range` | `account_id`, `wallet_instance_token`, `end_index_exclusive` | With network capability, explicitly scan both branches from index zero to the exclusive end (1–1000) using the connected ElectrumX server. The current wallet token is returned by `get_wallet_status`. A lost response around commit leaves the outcome unknown; inspect the wallet before retrying. The server sees queried script hashes and may return incomplete data. |
| `prepare_tx` | `outputs` mit `address` und `satoshis`, `fee_rate`; optional `op_return_data`, `strategy` | Mit Zahlungsfreigabe Plan vorbereiten und Inputs reservieren; Fee-Rate in sat/Byte ist ausdrücklich anzugeben. |
| `sign_tx` | `plan_id`, `totp_code` | Mit Zahlungsfreigabe und gültigem TOTP denselben Plan wie in der GUI signieren; sendet ihn nicht. |
| `get_spend_plan_status` | `plan_id` | Mit Zahlungsfreigabe Zustand und gegebenenfalls TXID abfragen. |
| `list_spend_plans` | keine | Mit Zahlungsfreigabe offene und gesendete Pläne auflisten. |
| `cancel_spend_plan` | `plan_id` | Mit Zahlungsfreigabe ausschließlich einen PREPARED-Plan stornieren und dessen Reservierungen freigeben. |
| `broadcast_plan` | `plan_id`, `expected_txid`; optional `retry_unknown` | Mit allen drei Freigaben und bereits verbundener Gegenstelle explizit senden. Bei unklarem Ergebnis verlangt eine erneute Sendung `retry_unknown: true`. |

`create_wallet` erzeugt oder übernimmt die Mnemonic und gibt sie in der Antwort zurück; es gibt keine Methode zum Export privater Schlüssel. TOTP muss für Signaturen aktiviert sein. Schema-34-Wallets werden neu mit AEAD erstellt; Schema 33 bleibt beim normalen Öffnen Legacy; für unterstützte Wallets ist im Quellstand eine ausdrücklich bestätigte Migration vorhanden. Bei aktivem TOTP verlangen Schema-34-Backup und Passwortwechsel zusätzlich `totp_code`. Neue Recovery-Codes besitzen 160 Bit, bestehende 40-Bit-Codes bleiben bis zu bewusster Neugenerierung oder Verwendung gültig. Ein Generierungsfehler kann ein ungewisses Commit-Ergebnis bedeuten; bisherige Codes könnten ersetzt worden sein. Codes einschließlich Bindestrichen exakt eingeben. Das zweistufige Setup und Recovery nutzen dieselben Dienste wie die GUI; das Setup gibt ein vertrauliches Geheimnis zurück.

Die Agentenmethode `create_wallet` behält bei Passphrasen die historische MC-UTF-8-Ableitung ohne BIP39-NFKD-Normalisierung. Die neue ausdrückliche Auswahl zwischen Standard-BIP39 und historischer Ableitung gehört zur Tauri-GUI-Wiederherstellung und ist keine neue Agenten-RPC-Methode. Bei Unicode-Passphrasen können beide Ableitungen unterschiedliche Wallets ergeben; Leerzeichen sind bedeutend und eine falsche Passphrase ist nicht erkennbar. Bestehende Wallets werden beim Öffnen nicht umgedeutet.

Legacy-TOTP-Deaktivierung ändert Secret und Recoveryliste atomar. Bei einem unklaren Commit-Ausgang melden die Dienste einen Fehler mit Hinweis zum erneuten Öffnen; der Agent wiederholt die Operation nicht. Nach einer unterbrochenen Codegenerierung können alte Codes ersetzt sein, ohne dass die neuen zugestellt wurden. Erst dieselbe Wallet erneut öffnen und den Schutzstatus prüfen, bevor bewusst ein neuer Versuch erfolgt.

`prepare_tx` reserviert die ausgewählten Outpoints dauerhaft. PREPARED-Pläne laufen nach fünf Minuten ab oder können explizit storniert werden; nach erneutem Öffnen der Wallet können sie nicht mehr signiert, aber storniert werden. SIGNED, BROADCAST_UNKNOWN und BROADCASTED bleiben reserviert; ein Sync entfernt die Reservierung nicht. Ein unbekanntes Broadcast-Ergebnis wird nicht automatisch wiederholt: Ein expliziter Retry sendet dieselben gespeicherten Bytes. Multisig-Signieren wird über dieses Ledger abgelehnt.

`get_balance` liefert den letzten lokalen Gesamtsaldo und getrennt `reserved` und `available`; `reserved` summiert dabei im aktuellen lokalen UTXO-Stand sichtbare Reservierungen; `available` berücksichtigt lokal als verwendbar eingestufte, nicht reservierte Outputs. Beide Werte sind kein Nachweis eines aktuellen Netzwerk- oder Chainstands. Für `connect_server` sind Host und Port verpflichtend; TLS-Zertifikats- und Hostnamenprüfung bleiben aktiv. Es gibt keine produktive Agenten-Methode für Fake-UTXOs oder zum Abschalten von TLS-Prüfungen.

## Geheimnisse und Grenzen

`create_wallet` überträgt Passwort und gegebenenfalls Mnemonic und Passphrase über stdin und gibt die Mnemonic über stdout zurück. Auch `unlock_wallet`, `enable_totp`, `verify_totp` und `sign_tx` übertragen je nach Aufruf Passwort oder TOTP-Code über stdin. Auch `backup_wallet` und `change_password` übertragen Passwörter über stdin. Diese Daten sowie die Antworten nicht in Shell-Historie, Logs oder Fehlermeldungen ablegen oder teilen. Die `xpub` ist kein privater Schlüssel, erlaubt aber Rückschlüsse auf Adressen und Transaktionen und ist ebenfalls vertraulich zu behandeln. Ausschließlich Wegwerf-Wallets ohne echtes Guthaben verwenden.

Die Backup-Grenzen und mögliche Dateireste nach Fehlern stehen in [KNOWN_ISSUES.md](../KNOWN_ISSUES.md). Ein Backup enthält vertrauliche Wallet-Daten; seine Wiederherstellbarkeit muss separat geprüft werden.

Create, Open und Status liefern zusätzlich `wallet_instance_token` (bei geschlossenem Status `null`). Es ist ein nicht geheimes, zufälliges Token der geöffneten Instanz, kein Authentisierungsmittel; nach Schließen und erneutem Öffnen ändert es sich. Die GUI bindet ihren Backupaufruf daran. Die Agentenmethode `backup_wallet` behält ihre oben dokumentierten Parameter und Authentisierung bei; sie verlangt kein Token. Bei ungewisser Veröffentlichung das Ziel vor einem bewussten erneuten Versuch prüfen.

Der CLI-Schalter ist keine Betriebssystem-Authentifizierung. Wer unter demselben Benutzer den Prozess und seine Daten kontrollieren kann, erhält dadurch keine zusätzliche Sicherheitsgrenze. Zugriffe auf stdin, stdout und das Datenverzeichnis müssen entsprechend geschützt werden.

Der Prozess sperrt das kanonisierte Datenverzeichnis über eine Lockdatei; Wallets erhalten zusätzlich eine pfadbasierte Lockdatei. Das verhindert konkurrierende Nutzung durch kooperierende Prozesse, auch bei Symlink-Aliasen des Datenverzeichnisses und überlappenden Verzeichnissen mit demselben kanonischen Wallet-Pfad. Hardlinks auf dieselbe Wallet unter unterschiedlichen Pfaden können unterschiedliche Lockdateien erhalten und werden dadurch nicht zuverlässig erkannt. Locks sind keine Zugriffskontrolle gegen andere Programme. Create, Open, Unlock, Passwortänderung, Löschen und Empfangsadressenvergabe laufen innerhalb eines Prozesses geordnet; Close meldet einen laufenden Wallet-Vorgang als belegt, statt ihn zu unterbrechen. Beim erfolgreichen Close wartet der Prozess asynchron auf ausgeliehene Datenbankverbindungen, schließt den Pool samt alten Poolklonen und gibt danach die Wallet-Sperre frei. Eine globale Synchronisierung aller übrigen Wallet-Mutationen ist nicht geprüft.

## Prüfstatus

Details zum Quelltestbündel und getrennten Läufen stehen in [START_HIER_DE.md](../START_HIER_DE.md#lokale-prüfung). Das aktuelle Release `18e1b1cd…` bestand isolierte Agenten-Smokes für Migration und Restore, Payment und Maintenance; Netzwerk und Broadcast waren ausgeschaltet. Beim früheren Release `a943d4d4…` prüfte ein privater GUI-/Agentenlauf bei aktivem 2FA die Notification für fehlendes TOTP und das fehlende Ziel, danach einen ausdrücklichen gültigen Backupversuch und nach GUI-Ende die getrennte 2FA-Authentisierung von Original und Kopie mit unterschiedlichem Inode sowie xpub-Vergleich im RAM und SQLite-Integrität. Beim früheren Release `5db137b7…` verglich ein privater GUI-Restorelauf mit einer öffentlichen Unicode-Fixture nach GUI-Ende und Agenten-Reopen beide xpubs erfolgreich mit unabhängigen Vektoren. Ein separater privater GUI-Recoverylauf erreichte nach Setup, zehn nur im RAM gelesenen Codes und Recoverymeldung den Passwort-Unlock sowie Hauptansicht und Setup-Bedienelement; diese GUI-Beobachtung allein belegt keine Backend-Codevernichtung oder Replay-Abweisung. Beim früheren Release `7c68b352…` wurde der positive GUI-Tauri-Backuppfad privat mit separater Agentenöffnung geprüft, der Walletwechsel-Race separat im Backend. Ein privater GUI-Lauf des früheren Releases `5b10e6e6…` erreichte nach 2FA-Setup und erzeugten Recovery-Codes einen sichtbaren Recovery-Abschlusstext, scheiterte aber beim nachfolgenden Unlock. Vollständige GUI-Zahlungsabläufe und echter Broadcast bleiben offen.

Der spätere Arbeitsstand bestand getrennte Recovery- und Zahlungs-Prozessabbruchtests mit synthetischen Daten. Die vollständigen getrennten Prüfungen umfassen 629 Rust-Tests ohne Sockettests sowie TLS-Loopback 1/1 und Netzwerk 2/2; die GUI-Suite bestand 66 Tests und den Build. Das zugehörige Release `b0291fbd…` wurde gebaut und bestand isolierte Agenten-Smokes für Migration, Zahlungsvorbereitung und Maintenance. Ein unabhängiger Live-Lesetest verband dieses Artefakt per TLS mit `electrumx.gorillapool.io:50002` und prüfte mit einer öffentlichen Test-Wallet Sync, Saldo 0, 81 History-Einträge und Disconnect, ohne Zahlung oder Broadcast. Serverwahrheit und unabhängige Chainvalidierung sind nicht belegt.

Die `get_history`-Agentenmethode wurde auf dem aktuellen Migrationssnapshot über einen In-Process-Agent-Dispatcher mit lokalem TLS-Mock geprüft: Connect, Sync, History, Saldo und Empfang sowie ein fehlerhafter Sync wurden getestet; Hostnamen- und Truststore-Negativfälle wurden abgewiesen. Der gezielte Loopback-Test bestand separat 1/1. Der ElectrumX-Client wählt seinen Crypto-Provider nun explizit; ein separater Konfigurationstest prüft, dass dabei kein globaler Provider vorausgesetzt oder installiert wird. Der Test ist kein Stdio-Childprozess- oder Live-Netz-Test. Ein früheres Release bestand einen lokalen Agentensmoke ohne Netzwerk mit `get_history`. Ein Live-Smoke des früheren Release `20a157…` verband sich über TLS mit `electrumx.gorillapool.io:50002` und prüfte Sync, Saldo 0, 81 History-Einträge, Disconnect und EOF. Er nutzte eine öffentliche Test-Wallet, ohne Zahlung oder Broadcast; Serverwahrheit und unabhängige Chainvalidierung sind damit nicht belegt.

Die Vorschau bindet einen einmaligen, kurzlebigen Token an Walletinstanz, Datenbestand und Policy; ein geänderter Bestand verlangt eine neue Vorschau. Das Backupziel muss neu und innerhalb des Datenverzeichnisses liegen. Passwort und bei aktivierter 2FA TOTP werden vor Backup und erneut vor Commit geprüft; unbekannte oder nicht unterstützte Inventare werden abgewiesen. Migrationsfehler enthalten strukturierte Angaben in `error.data`, darunter `outcome`, `reopen_required` und `backup_outcome`. Bei `outcome: unknown` Wallet erneut öffnen und prüfen, bevor ein neuer Versuch erwogen wird; `not_committed` bezeichnet einen nicht durchgeführten Commit. `backup_outcome` kann `not_created`, `published` oder `unknown` sein. Bereits veröffentlichte Backups bleiben erhalten; das Backup enthält weiterhin Legacy-Geheimnisse. Die bestehende Recovery-Code-Liste bleibt erhalten.
