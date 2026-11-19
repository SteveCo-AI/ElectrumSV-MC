# P2: Recovery- und Commitgrenzen – Arbeitsnotiz

Stand: Arbeitsbaum vom 19.11.2026; Rust-Quell-/Test-/Migrationsbäume SHA-256 `634e526f878e4855629e86df5cc664cc1d89cbbc8fe0949a2fba545d1087a65b` (sortierte Dateihashes der drei Bäume, siehe Befehl unten). Dies ist ein Prüfbericht, keine Release- oder Sicherheitsaudit-Abnahme.

## Änderung und Grenzen

- `src-tauri/src/commands/wallet.rs`: Legacy-TOTP-Deaktivierung aktualisiert Recoveryliste und TOTP-Zeile in einer SQLite-Transaktion; vor einem möglichen Commit wird die aktive Session gesperrt und nur nach eindeutigem Erfolg wiederhergestellt. Der registrierte Legacy-Recoveryadapter verwendet denselben zentralen Recoverykern.
- `src-tauri/src/db/repositories.rs`: Recoveryprüfung und bedingte Änderungen können in der aufrufereigenen Transaktion ausgeführt werden; der bestehende eigenständige Repoaufruf behält seine atomare Commitgrenze.
- `src-tauri/src/services/wallet_security.rs`: Legacy-Recovery verwirft Session und Pending-Setup vor dem Commit. Ein Commitfehler meldet einen ungewissen Ausgang und fordert erneutes Öffnen. Das zuvor mögliche Cancellation-Risiko ist quellenbasiert; ein Vorher-Reproduktionstest dafür wurde nicht ausgeführt.
- Die GUI-Nacharbeit wird separat geprüft. Der Verlust einer bereits committed Codegenerierungsantwort bleibt ein ungewisses Ergebnis: neue Codes lassen sich daraus nicht rekonstruieren. Ein Abbruch mitten im SQLite-Commit wird nicht durch die Grenztests nachgewiesen.

## Ausgeführte Prüfungen

Arbeitsverzeichnis für Cargo: `/run/media/system/Spiele/Projekte/electrumsv-mc/src-tauri`. Alle Fixtures und Codes waren synthetisch; es gab keine echten Netzwerkaktionen.

1. Vor dem Fix: `env ELECTRUMSV_DATA_DIR=/tmp/wallet-recovery-p2 CARGO_HOME=/tmp/w2-wallet-cargo-home CARGO_BUILD_JOBS=4 cargo test --locked --offline --no-default-features --lib legacy_disable_failure_preserves_totp_and_recovery_codes` – Session 50612, Exit 101. Der injizierte Fehler beim TOTP-DELETE ließ TOTP aktiv, löschte aber die Recoveryliste. Dieselbe Regression nach dem Fix: Session 74792, Exit 0, 1/1.
2. `env ELECTRUMSV_DATA_DIR=/tmp/wallet-recovery-p2 CARGO_HOME=/tmp/w2-wallet-cargo-home CARGO_BUILD_JOBS=4 cargo test --locked --offline --no-default-features --lib commands::wallet::tests::legacy_ -- --test-threads=2` – Session 93282, Exit 0, 3/3. Prüft SQL-Fehler sowie Future-Abbruch an Commitgrenzen von Legacy-Disable und Legacy-Recovery mit erneut geöffnetem DB-Zustand.
3. `env ELECTRUMSV_DATA_DIR=/tmp/wallet-recovery-p2 CARGO_HOME=/tmp/w2-wallet-cargo-home CARGO_BUILD_JOBS=4 cargo test --locked --offline --no-default-features --lib killed_recovery_process_preserves_atomic_code_state` – Session 70970, Exit 0, 1/1 Rust-Test mit zehn echten Kindprozessfällen: Legacy33-Disable, Legacy33-/Schema34-Recovery und Legacy33-/Schema34-Codegenerierung, jeweils vor und nach Commit. Nach OS-Kill werden Wallet und Datenbank neu geöffnet und TOTP-/Recoveryzustand geprüft. Bei Generierungs-Antwortverlust wird kein Zugriff auf ausgegebene Klartextcodes behauptet.
4. `git diff --check` – Exit 0.

Ein vorangegangener Compileversuch Session 12334 endete mit Exit 101 wegen eines inzwischen korrigierten Lifetime-Fehlers in einem parallel hinzugefügten Payment-Test; dabei liefen keine Recoverytests. Es wurden keine separaten Testlogdateien angelegt; die Sessions sind die ausgeführten Toolresultate.

Hashbefehl im Projektverzeichnis: `find src-tauri/src src-tauri/tests src-tauri/migrations -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum`. GUI, Dokumentation und Konfiguration sind davon nicht umfasst.
