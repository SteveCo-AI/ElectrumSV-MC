# Private Wry payment test

This ignored Linux test runs the production App and SendView through real Wry/Tauri IPC. A test-only entry initializes the already-open synthetic schema 34 wallet and navigates the actual view with DOM input events and button clicks; it does not invoke payment commands directly. A public RFC test TOTP secret is installed in the unlocked in-memory bundle only. Wallet state and temporary data must be on a private tmpfs. This does not test GUI login, TOTP policy persistence, GUI network connection, or a live server.

Build separate assets and the debug test executable offline:

```sh
./gui/node_modules/.bin/vite build --config tools/wry-payment/vite.config.mjs
cd src-tauri
env CARGO_HOME=/tmp/w2-wallet-cargo-home CARGO_BUILD_JOBS=4 cargo test --locked --offline --no-default-features --lib --no-run
```

Run only `--exact wry_payment_test::real_wry_send_payment_with_local_tls --ignored --nocapture` as a separate child in a private network namespace with loopback enabled, private Xvfb, and a fresh private tmpfs directory. Set `WALLET_WRY_PAYMENT_ASSET_DIR` and `WALLET_WRY_PAYMENT_DATA_DIR` to the in-namespace asset and fresh data directories. Enforce an outer timeout covering setup. Success requires exit zero, exactly one test and `WRY_PAYMENT_PASS sync prepare wrong_totp sign eof unknown retry broadcast`. The internal 90-second watchdog and a stage-specific `WRY_PAYMENT_FAIL` signal failure.

Funding arrives via the production sync history/raw-transaction/UTXO path from the loopback TLS fixture. The fixture verifies the captured broadcast transaction against its prevout using the SDK script VM, checks recipient, actual fee and byte-identical retry. After the first EOF the test checks real client disconnection, persistent reservation and plan state, observes a bounded no-retry interval, and reconnects via a test-only seam before the GUI retry. The reconnect does not perform a payment action. This is a test fixture, not evidence that a remote server accepted a transaction.
