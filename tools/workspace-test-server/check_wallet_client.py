#!/usr/bin/env python3
"""Check the wallet's ElectrumX client against the workspace TLS scenario server."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

PROJECT = Path(__file__).resolve().parent.parent.parent
WORKSPACE = PROJECT.parent
TEST_NAME = "agent::agent_tls_test::workspace_scenario_server_with_wallet_client"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, default=WORKSPACE / ".tools/workspace-optimization/local_test_server.py")
    parser.add_argument("--cert-dir", type=Path, default=PROJECT / "src-tauri/tests/fixtures/tls")
    parser.add_argument("--test-binary", type=Path, required=True)
    args = parser.parse_args()
    target, txid = "ab" * 32, "11" * 32
    scenario = [
        {"method":"server.version", "params":["ElectrumSV-Mc 0.1.0", ["1.4", "1.4"]], "result":["workspace-fixture", "1.4"]},
        {"method":"blockchain.scripthash.get_balance", "params":[target], "result":{"confirmed":50000,"unconfirmed":-5}},
        {"method":"blockchain.scripthash.get_history", "params":[target], "result":[{"tx_hash":txid,"height":123}]},
        {"method":"blockchain.scripthash.listunspent", "params":[target], "result":[{"tx_hash":txid,"tx_pos":1,"value":50000,"height":123}]},
        {"method":"test.error", "params":[], "error":{"code":-1,"message":"fixture failure"}},
        {"method":"server.ping", "params":[], "result":None},
    ]
    with tempfile.TemporaryDirectory(prefix="wallet-scenario-") as directory:
        path = Path(directory) / "scenario.json"
        path.write_text(json.dumps(scenario), encoding="utf-8")
        server = subprocess.Popen([sys.executable, "-B", str(args.server), "--mode", "electrum", "--scenario", str(path),
                                   "--cert", str(args.cert_dir / "server.pem"), "--key", str(args.cert_dir / "server-key.pem"), "--timeout", "30"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            line = server.stdout.readline()
            if not line:
                raise RuntimeError("scenario server did not start")
            ready = json.loads(line)
            if ready.get("event") != "ready" or ready.get("host") != "127.0.0.1":
                raise RuntimeError("invalid server readiness response")
            env = os.environ.copy()
            env["WS_WALLET_TEST_PORT"] = str(ready["port"])
            result = subprocess.run([str(args.test_binary), "--exact", TEST_NAME, "--ignored", "--nocapture"],
                                    env=env, capture_output=True, text=True, timeout=60)
            if result.returncode or "test result: ok. 1 passed; 0 failed;" not in result.stdout:
                raise RuntimeError(f"wallet client test failed: {result.stdout} {result.stderr}")
            output, error = server.communicate(timeout=5)
            finished = json.loads(output)
            if server.returncode or finished.get("event") != "finished" or finished.get("error") is not None or finished.get("completed") != len(scenario):
                raise RuntimeError(f"scenario server failed: {output} {error}")
            print("PASS wallet ElectrumX client: TLS, version, balance, history, UTXO, RPC error and ping")
            return 0
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
            print(f"workspace-wallet-client: {exc}", file=sys.stderr)
            return 1
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate()


if __name__ == "__main__":
    sys.exit(main())
