# Private Wry IPC gate

This is an ignored, Linux-only test host, excluded from the production binary. Its Vite entry imports the production `gui/src/api.ts` and calls `getAppVersion`; the host registers the existing read-only `get_app_version` Tauri command. Test assets are read at runtime and are separate from `gui/dist`. No wallet, funding, network backend, broadcast or mock IPC command is involved.

From the project root, build the isolated assets and compile the test executable offline:

```sh
./gui/node_modules/.bin/vite build --config tools/wry-gate/vite.config.mjs
cd src-tauri
env CARGO_HOME=/tmp/w2-wallet-cargo-home CARGO_BUILD_JOBS=4 cargo test --locked --offline --no-default-features --lib --no-run
```

Run the resulting `electrumsv_mc_lib-*` test executable in a **separate child process** with a private display and network namespace. Mount the two generated assets into that namespace and set `WALLET_WRY_GATE_ASSET_DIR` to their in-namespace directory. Select only:

```text
--exact wry_gate_test::real_wry_production_api_to_readonly_command --ignored --nocapture
```

A valid result requires exit code 0 **and** `WRY_GATE_PASS production_api_getAppVersion real_tauri_command` in stdout. The test has a 30-second watchdog; a missing asset, missing marker, timeout, unexpected version, failed IPC, or premature window close is a failure. Navigation to `wallet-gate.invalid` is intercepted and cancelled by the host; the private network namespace supplies a second boundary. This gate does not establish payment or wallet correctness.
