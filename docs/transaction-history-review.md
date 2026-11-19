# Transaktionsdetails und History: historischer Befund und Nacharbeit

Die folgenden Befunde beschreiben den früheren Arbeitsstand auf Basis von `bab27657a1465b99f0f027901a13d117136a19dd`. Sie sind durch die nachfolgend beschriebene Nacharbeit behoben und keine Beschreibung des aktuellen Quellstands. Historische Zeilennummern können abweichen; die Prüfung nutzte keine echte Wallet.

## Historische Befunde

- `repositories::get_transaction_by_txid` (`src-tauri/src/db/repositories.rs:1354`) fragt nicht existierende Spalten von `AccountTransactions` ab. Die View enthält laut `migrations/0024_account_transactions.sql:4` nur `account_id` und `tx_hash`. Der GUI-Pfad `HistoryView` → `api.getTransaction` → `commands::extra::get_transaction` (`src-tauri/src/commands/extra.rs:155`) scheitert bei jedem Detailaufruf bereits hier.
- `repositories::get_transaction_inputs` (`repositories.rs:1379`) fragt die nicht vorhandene Tabelle `TransactionInputs` ab. Dieser Aufruf liegt im selben Detailpfad hinter dem ersten Fehler. `get_tx_label` (`repositories.rs:1426`) fragt die ebenfalls nicht vorhandene Tabelle `TransactionLabels` ab; sein Fehler wird in `extra.rs:197` unterdrückt. Labels stehen tatsächlich in `Transactions.description`.
- `get_transaction_outputs` (`repositories.rs:1402`) verwendet im damaligen Arbeitsbaum die vorhandenen Spalten `tx_hash` und `tx_index`. Die Daten sind dennoch keine vollständige Transaktion: Der Sync speichert nur aktuelle eigene UTXOs und löscht nicht mehr vorhandene Outputs. Externe, bereits ausgegebene und OP_RETURN-Outputs fehlen möglicherweise; fehlende Skripte werden als leerer String ausgegeben.
- `sync_wallet` übernimmt History-Hashes und Höhen (`src-tauri/src/commands/network.rs:533`); `replace_sync_snapshot` schreibt für jeden Eintrag `value_delta = 0` (`repositories.rs:699`). `get_tx_history_for_account` summiert diese Werte (`repositories.rs:366`), `commands::account::get_history` liefert sie weiter (`src-tauri/src/commands/account.rs:128`), und `gui/src/views/HistoryView.tsx:172` zeigt dafür einen Strich. Ein erneuter Sync überschreibt auch vorhandene echte Deltas. Der Sync speichert gegenwärtig keine vollständige Raw-Transaktion für History-Details (`repositories.rs:715`).

## Historische Schema-Abfragen reproduzieren

Im Projektverzeichnis ausführen; der Prozess verwendet ausschließlich eine SQLite-Datenbank im Speicher, das historische Schema bis Migration 0031 und die damaligen SQL-Abfragen. Das reproduziert die historischen Schemafehler, nicht die heutigen Detailabfragen:

```sh
python3 - <<'PY'
import sqlite3
from pathlib import Path

db = sqlite3.connect(':memory:')
files = [p for p in sorted(Path('src-tauri/migrations').glob('*.sql')) if int(p.name[:4]) <= 31]
assert [p.name[:4] for p in files] == [f'{n:04}' for n in range(22, 32)]
for file in files:
    db.executescript(file.read_text())
queries = {
    'transaction': 'SELECT tx_hash_hex as txid, status, raw_tx, account_id, fee FROM AccountTransactions WHERE tx_hash_hex = ?',
    'inputs': 'SELECT prev_tx_hash, prev_vout, script_sig, sequence FROM TransactionInputs WHERE tx_hash_hex = ? ORDER BY input_index',
    'label': 'SELECT label FROM TransactionLabels WHERE tx_hash_hex = ?',
    'outputs': "SELECT value, COALESCE(script_pubkey, '') AS script_pubkey FROM TransactionOutputs WHERE tx_hash = ? ORDER BY tx_index",
}
for name, query in queries.items():
    try:
        db.execute(query, (bytes(32) if name == 'outputs' else '0' * 64,)).fetchall()
        print(f'{name}: OK')
    except sqlite3.OperationalError as error:
        print(f'{name}: {error}')
PY
```

Für diese historischen Abfragen lautet die Ausgabe:

```text
transaction: no such column: tx_hash_hex
inputs: no such table: TransactionInputs
label: no such table: TransactionLabels
outputs: OK
```

`outputs: OK` belegt nur die Ausführbarkeit der Abfrage auf leerem Schema, nicht Vollständigkeit oder fachliche Richtigkeit ihrer Daten.

## Nacharbeit und Nachweise

Die aktuelle Detailabfrage begrenzt den Zugriff auf das aktive Konto und liest Inputs und sämtliche Outputs aus einer anhand der TXID geprüften Rohtransaktion. Fehlen Rohdaten, liefert sie ausdrücklich unvollständige Details. Die History berechnet Deltas aus Ein- und Ausgängen samt verfügbaren Vortransaktionen; fehlende Vortransaktionen ergeben einen unbekannten Wert. Migration 0032 kennzeichnet Altdeltas als unbekannt, und der gesammelte Datenbank-Snapshot wird atomar gespeichert.

Der synthetische Test `resolver_fetch_snapshot_history_detail_integration` prüft Produktionsresolver, Snapshot, History und Details einschließlich internem Transfer, fehlender und später verfügbarer Vortransaktion sowie Fehlerpfaden. `migration_32_marks_legacy_deltas_unknown`, `sync_history_known_and_unknown_roundtrip` und `detail_requires_account_and_preserves_unknown_raw` decken Migration und Detailgrenzen ab. Die GUI-Tests prüfen unter anderem unbekannt gegenüber echter Null sowie vollständige und fehlende Details. Diese Tests bestanden im aktuellen Linux-Testlauf; die Gesamtzahlen stehen in der [README](../README.md#testing).

Serverdaten werden über mehrere Anfragen gesammelt und bilden keine atomare Chain-Momentaufnahme. Serverauslassungen, Höhenangaben und unabhängige Chainvalidierung bleiben Grenzen; Live-Netzwerkbetrieb und Eignung für echte Guthaben sind nicht nachgewiesen.
