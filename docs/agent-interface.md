# Lokale Agentenschnittstelle

Der Agentenmodus ist standardmäßig deaktiviert. Er wird pro Prozess ausdrücklich gestartet; es gibt keinen GUI-Schalter. Nach einem Build kann er zum Beispiel mit einem eigenen, leeren Testverzeichnis gestartet werden:

```sh
testdir=$(mktemp -d)
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"get_wallet_status","params":{}}' | \
  ./src-tauri/target/debug/electrumsv-mc --agent --data-dir "$testdir"
```

Der Pfad ist ein Beispiel für das Debug-Binary. `--data-dir` ist Pflicht und muss ein nicht leerer UTF-8-Pfad sein; das Verzeichnis wird bei Bedarf angelegt. Ein EOF auf stdin beendet den Prozess. Für mehrere Aufrufe dieselbe stdin offen halten und die Antwort nach jedem Aufruf lesen.

## Freigaben

Zusätzlich zum Pflichtparameter `--data-dir` aktiviert `--enable-payments` die Zahlungs- und TOTP-Methoden, `--allow-network` die explizite Verbindung und Synchronisation und `--allow-broadcast` das Senden. Letzteres setzt beide anderen Schalter voraus. `--enable-wallet-maintenance` schaltet unabhängig davon Backup und Passwortwechsel frei. Alle vier Freigaben sind pro Prozess standardmäßig aus; ein gesetzter Schalter startet weder eine Verbindung noch einen Broadcast. `get_capabilities` zeigt die aktiven Freigaben.

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
| `backup_wallet` | `backup_path`, `password` | Mit Wallet-Maintenance-Freigabe und Wallet-Passwort ein Backup innerhalb des Datenverzeichnisses erstellen; bestehende Ziele werden nicht überschrieben. |
| `change_password` | `old_password`, `new_password` | Mit Wallet-Maintenance-Freigabe und bisherigem Passwort das Wallet-Passwort ändern; das neue Passwort darf nicht leer sein. |
| `get_wallet_status` | keine | Status einschließlich `is_open`, `is_unlocked`, `account_id` und gegebenenfalls `xpub`. |
| `get_history` | optional `account_id`, `limit`, `offset` | Lokalen Transaktionsverlauf abrufen; Standard sind 50 Einträge ab Offset 0. `limit` muss zwischen 1 und 500 liegen, `offset` mindestens 0; ungültige Werte ergeben Fehler `-32602`. Unbekannte Betragsänderungen werden als `null` zurückgegeben. |
| `get_balance` | optional `account_id` | Lokal gespeicherten Saldo abfragen; ohne ID das aktive Konto. |
| `get_receive_address` | optional `account_id` | Neue Empfangsadresse für das aktive Konto erzeugen und speichern; die Wallet muss entsperrt sein. |
| `enable_totp` | `password` | Mit Zahlungsfreigabe TOTP über denselben Wallet-Pfad wie die GUI einrichten; gibt TOTP-Geheimnis und otpauth-URL zurück. |
| `is_totp_enabled` | keine | Mit Zahlungsfreigabe TOTP-Status abfragen. |
| `verify_totp` | `code` | Mit Zahlungsfreigabe aktuellen TOTP-Code prüfen. |
| `connect_server` | `host`, `port` | Mit Netzwerkfreigabe explizit zum angegebenen ElectrumX-TLS-Ziel verbinden. |
| `disconnect_server` | keine | Mit Netzwerkfreigabe Verbindung trennen. |
| `sync_wallet` | optional `account_id` | Mit Netzwerkfreigabe aktuelle Wallet über die bestehende Verbindung synchronisieren. |
| `prepare_tx` | `outputs` mit `address` und `satoshis`, `fee_rate`; optional `op_return_data`, `strategy` | Mit Zahlungsfreigabe Plan vorbereiten und Inputs reservieren; Fee-Rate in sat/Byte ist ausdrücklich anzugeben. |
| `sign_tx` | `plan_id`, `totp_code` | Mit Zahlungsfreigabe und gültigem TOTP denselben Plan wie in der GUI signieren; sendet ihn nicht. |
| `get_spend_plan_status` | `plan_id` | Mit Zahlungsfreigabe Zustand und gegebenenfalls TXID abfragen. |
| `list_spend_plans` | keine | Mit Zahlungsfreigabe offene und gesendete Pläne auflisten. |
| `cancel_spend_plan` | `plan_id` | Mit Zahlungsfreigabe ausschließlich einen PREPARED-Plan stornieren und dessen Reservierungen freigeben. |
| `broadcast_plan` | `plan_id`, `expected_txid`; optional `retry_unknown` | Mit allen drei Freigaben und bereits verbundener Gegenstelle explizit senden. Bei unklarem Ergebnis verlangt eine erneute Sendung `retry_unknown: true`. |

`create_wallet` erzeugt oder übernimmt die Mnemonic und gibt sie in der Antwort zurück; es gibt keine Methode zum Export privater Schlüssel. TOTP muss für Signaturen aktiviert sein. Die Einrichtung und Prüfung nutzen dieselben Wallet-Funktionen wie die GUI; `enable_totp` gibt ein vertrauliches Geheimnis zurück.

`prepare_tx` reserviert die ausgewählten Outpoints dauerhaft. PREPARED-Pläne laufen nach fünf Minuten ab oder können explizit storniert werden; nach erneutem Öffnen der Wallet können sie nicht mehr signiert, aber storniert werden. SIGNED, BROADCAST_UNKNOWN und BROADCASTED bleiben reserviert; ein Sync entfernt die Reservierung nicht. Ein unbekanntes Broadcast-Ergebnis wird nicht automatisch wiederholt: Ein expliziter Retry sendet dieselben gespeicherten Bytes. Multisig-Signieren wird über dieses Ledger abgelehnt.

`get_balance` liefert den letzten lokalen Gesamtsaldo und getrennt `reserved` und `available`; `reserved` summiert dabei im aktuellen lokalen UTXO-Stand sichtbare Reservierungen; `available` berücksichtigt lokal als verwendbar eingestufte, nicht reservierte Outputs. Beide Werte sind kein Nachweis eines aktuellen Netzwerk- oder Chainstands. Für `connect_server` sind Host und Port verpflichtend; TLS-Zertifikats- und Hostnamenprüfung bleiben aktiv. Es gibt keine produktive Agenten-Methode für Fake-UTXOs oder zum Abschalten von TLS-Prüfungen.

## Geheimnisse und Grenzen

`create_wallet` überträgt Passwort und gegebenenfalls Mnemonic und Passphrase über stdin und gibt die Mnemonic über stdout zurück. Auch `unlock_wallet`, `enable_totp`, `verify_totp` und `sign_tx` übertragen je nach Aufruf Passwort oder TOTP-Code über stdin. Auch `backup_wallet` und `change_password` übertragen Passwörter über stdin. Diese Daten sowie die Antworten nicht in Shell-Historie, Logs oder Fehlermeldungen ablegen oder teilen. Die `xpub` ist kein privater Schlüssel, erlaubt aber Rückschlüsse auf Adressen und Transaktionen und ist ebenfalls vertraulich zu behandeln. Ausschließlich Wegwerf-Wallets ohne echtes Guthaben verwenden.

Die Backup-Grenzen und mögliche Dateireste nach Fehlern stehen in [KNOWN_ISSUES.md](../KNOWN_ISSUES.md). Ein Backup enthält vertrauliche Wallet-Daten; seine Wiederherstellbarkeit muss separat geprüft werden.

Der CLI-Schalter ist keine Betriebssystem-Authentifizierung. Wer unter demselben Benutzer den Prozess und seine Daten kontrollieren kann, erhält dadurch keine zusätzliche Sicherheitsgrenze. Zugriffe auf stdin, stdout und das Datenverzeichnis müssen entsprechend geschützt werden.

Der Prozess sperrt das kanonisierte Datenverzeichnis über eine Lockdatei; Wallets erhalten zusätzlich eine pfadbasierte Lockdatei. Das verhindert konkurrierende Nutzung durch kooperierende Prozesse, auch bei Symlink-Aliasen des Datenverzeichnisses und überlappenden Verzeichnissen mit demselben kanonischen Wallet-Pfad. Hardlinks auf dieselbe Wallet unter unterschiedlichen Pfaden können unterschiedliche Lockdateien erhalten und werden dadurch nicht zuverlässig erkannt. Locks sind keine Zugriffskontrolle gegen andere Programme. Create, Open, Unlock, Passwortänderung, Löschen und Empfangsadressenvergabe laufen innerhalb eines Prozesses geordnet; Close meldet einen laufenden Wallet-Vorgang als belegt, statt ihn zu unterbrechen. Beim erfolgreichen Close wartet der Prozess asynchron auf ausgeliehene Datenbankverbindungen, schließt den Pool samt alten Poolklonen und gibt danach die Wallet-Sperre frei. Eine globale Synchronisierung aller übrigen Wallet-Mutationen ist nicht geprüft.

## Prüfstatus

Das aktuelle Linux-Offlinebündel enthält zwölf Agententests; Details und getrennte Läufe stehen in [START_HIER_DE.md](../START_HIER_DE.md#lokale-prüfung). Der aktuelle Release bestand Offline-Smokes für Backup und Passwortwechsel einschließlich Neustart und separater Backupöffnung sowie für TOTP, Signatur, Reservierung und Neustart. Netzwerk und Broadcast waren dabei ausgeschaltet; die SDK-Scriptvalidierung fand in nativen Tests statt. GUI-Start und Wallet-Listen-IPC wurden nur mit einem früheren Release geprüft; visuelle Interaktion, GUI-Zahlungsabläufe und echter Broadcast bleiben offen.

Die `get_history`-Agentenmethode wurde auf dem aktuellen Snapshot über einen In-Process-Agent-Dispatcher mit lokalem TLS-Mock geprüft: Connect, Sync, History, Saldo und Empfang sowie ein fehlerhafter Sync wurden getestet; Hostnamen- und Truststore-Negativfälle wurden abgewiesen. Der gezielte Loopback-Test bestand separat 1/1. Der ElectrumX-Client wählt seinen Crypto-Provider nun explizit; ein separater Konfigurationstest prüft, dass dabei kein globaler Provider vorausgesetzt oder installiert wird. Der Test ist kein Stdio-Childprozess- oder Live-Netz-Test. Ein früheres Release bestand einen lokalen Agentensmoke ohne Netzwerk mit `get_history`. Ein Live-Smoke dieses früheren Release verband sich über TLS mit `electrumx.gorillapool.io:50002` und prüfte Sync, Saldo 0, 81 History-Einträge, Disconnect und EOF. Er nutzte eine öffentliche Test-Wallet, ohne Zahlung oder Broadcast; Serverwahrheit und unabhängige Chainvalidierung sind damit nicht belegt.
