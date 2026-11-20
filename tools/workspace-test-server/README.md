# Workspace scenario server and wallet client

This optional check runs the wallet's real ElectrumX client against the workspace `local_test_server.py` using public test certificates and an explicit ordered scenario. It exercises TLS, protocol negotiation, typed balance/history/UTXO parsing and an RPC error. It does not exercise the wallet database, transactions, production trust roots, GUI or a real server, and does not replace the existing wallet-specific TLS, concurrency or Wry fixtures.

Compile the library test binary offline, then run `python3 -B tools/workspace-test-server/check_wallet_client.py --test-binary PATH_TO_TEST_BINARY` in an isolated network namespace. The workspace scenario server and the test certificates are defaults; `--server` and `--cert-dir` override them. Require an isolated loopback network and private temporary data. The Rust test is ignored unless the launcher explicitly selects it.
