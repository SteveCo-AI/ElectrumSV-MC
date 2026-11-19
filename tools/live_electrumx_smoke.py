#!/usr/bin/env python3
"""Read-only ElectrumX smoke against a public deterministic test wallet."""
import argparse
import hashlib
import json
import select
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / 'src-tauri/target/release/electrumsv-mc'
EXPECTED_SHA256 = '45659e194a4b6836981f48ac7d47c99bc3304d054e6c156f722dd64a8d3ed121'
# Public BIP39 test vector: never use this wallet for funds.
MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True, help='explicit ElectrumX TLS hostname')
    parser.add_argument('--port', required=True, type=int, help='explicit TLS port')
    parser.add_argument('--timeout', type=int, default=120, help='maximum seconds per RPC (default: 120)')
    args = parser.parse_args()
    if not args.server or not 1 <= args.port <= 65535 or not 1 <= args.timeout <= 600:
        parser.error('invalid server, port or timeout')
    if hashlib.sha256(BINARY.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError('unexpected release binary hash')
    with tempfile.TemporaryDirectory(prefix='electrumsv-live-smoke-') as directory:
        error_log = tempfile.TemporaryFile(mode='w+b')
        child = subprocess.Popen([str(BINARY), '--agent', '--data-dir', directory, '--allow-network'],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error_log,
                                 text=True, bufsize=1)
        def classify(data):
            data = data.lower()
            for needle, category in ((b'could not automatically determine the process-level cryptoprovider', 'rustls-crypto-provider'),
                                     (b'permission denied', 'permission-denied'),
                                     (b'operation not permitted', 'permission-denied'),
                                     (b'failed to lookup address', 'dns-failure'),
                                     (b'name or service not known', 'dns-failure'),
                                     (b'certificate', 'tls-certificate'),
                                     (b'connection refused', 'connection-refused'),
                                     (b'timed out', 'timeout')):
                if needle in data:
                    return category
            return 'other' if data else 'empty'

        def classify_stderr():
            error_log.flush()
            error_log.seek(0)
            return classify(error_log.read(65536))

        def call(number, method, params):
            try:
                child.stdin.write(json.dumps({'jsonrpc':'2.0','id':number,'method':method,'params':params}) + '\n')
                child.stdin.flush()
            except BrokenPipeError:
                raise RuntimeError(f'{method}: broken pipe; exit={child.poll()}; stderr={classify_stderr()}') from None
            if not select.select([child.stdout], [], [], args.timeout)[0]:
                raise RuntimeError(f'{method}: timeout; exit={child.poll()}; stderr={classify_stderr()}')
            line = child.stdout.readline()
            if not line:
                try:
                    child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
                raise RuntimeError(f'{method}: empty response; exit={child.poll()}; stderr={classify_stderr()}')
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                raise RuntimeError(f'{method}: invalid JSON response; exit={child.poll()}; stderr={classify_stderr()}') from None
            if response.get('id') != number or 'error' in response or 'result' not in response:
                error = response.get('error', {})
                code = error.get('code', 'invalid-response')
                category = classify(str(error.get('message', '')).encode())
                raise RuntimeError(f'{method}: RPC error {code}; exit={child.poll()}; category={category}')
            return response['result']
        try:
            capabilities = call(1, 'get_capabilities', {})
            if capabilities != {'payments': False, 'network': True, 'broadcast': False, 'wallet_maintenance': False}:
                raise RuntimeError('unexpected capabilities')
            call(2, 'create_wallet', {'name':'public-fixture','password':'test-only-password','mnemonic':MNEMONIC})
            call(3, 'get_receive_address', {})
            call(4, 'connect_server', {'host':args.server,'port':args.port})
            synced = call(5, 'sync_wallet', {})
            if not synced.get('synced') or synced.get('server_host') != args.server:
                raise RuntimeError('sync did not complete against requested server')
            balance = call(6, 'get_balance', {})
            if any(balance.get(field) != 0 for field in ('confirmed','unconfirmed','total','reserved','available')):
                raise RuntimeError('public fixture has nonzero or invalid balance; aborted')
            history = call(7, 'get_history', {'limit':500,'offset':0})
            if not isinstance(history, list) or any(not isinstance(entry, dict) or not isinstance(entry.get('tx_hash'), str) for entry in history):
                raise RuntimeError('get_history: invalid response')
            call(8, 'disconnect_server', {})
            child.stdin.close()
            if child.wait(timeout=15) != 0:
                raise RuntimeError('agent exited with error')
            print(f'PASS explicit_tls_connect sync zero_balance history disconnect eof; history_count={len(history)}')
            print('binary_sha256=' + EXPECTED_SHA256)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            error_log.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f'FAIL {exc}', file=sys.stderr)
        sys.exit(1)
