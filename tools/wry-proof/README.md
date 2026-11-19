# Private Wry proof IPC gate

This ignored Linux-only test host runs the production `api.verifyTransactionProof` wrapper through real Wry/Tauri IPC to the registered `verify_transaction_proof` command. It uses a temporary genesis HeaderStore and a preconnected ElectrumX client against a localhost TLS mock with the repository's public test-only CA. The GUI does not establish the connection, and the test does not establish consensus or proof against a live server.

From the project root build separate frontend assets, then compile the test executable offline:

```sh
./gui/node_modules/.bin/vite build --config tools/wry-proof/vite.config.mjs
cd src-tauri
env CARGO_HOME=/tmp/w2-wallet-cargo-home CARGO_BUILD_JOBS=4 cargo test --locked --offline --no-default-features --lib --no-run
```

Execute only `--exact wry_gate_test::real_wry_production_proof_api_with_local_tls --ignored --nocapture` in a separate child with private Xvfb and a private network namespace. Mount generated assets and set `WALLET_WRY_PROOF_ASSET_DIR` to their in-namespace path. Loopback `IFF_UP` is required inside that namespace; a failed bind is a failed setup, never a reason to use the host network. A valid gate requires exit 0 and `WRY_PROOF_GATE_PASS true false invalid_argument missing_header rpc_count_3`. The outer runner must enforce a timeout, including setup before the internal watchdog starts.

The page checks a genesis inclusion and a mismatching transaction against the known genesis merkle root, rejects an invalid argument, and requires an IPC error for a missing header. The mock confirms exactly three expected Merkle requests. This shows no extra mock-network call for the invalid argument; the RPC counter alone does not independently prove that no IPC occurred. This fixture does not test a GUI-initiated server connection, payment, broadcast or actual chain consensus.

The independently executed private run completed with exit 0, one test and `WRY_PROOF_PRIVATE_PASS`; its host reported `true false invalid_argument missing_header rpc_count_3`. The separate test executable had SHA-256 `a9dfd04a21ac85bf106e1e8e985789a6ba5c7fbf7d5a3e16d8dbc3a0dfd78963`; runner `/tmp/wallet-wry-proof-private/run_v2.sh` had SHA-256 `23708f867089f801fbced19b45913ab8abb737c4412ce6845625c361665d19ae`. Assets were built separately. Release `18e1b1cd…` remained unchanged.
