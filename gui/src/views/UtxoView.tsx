// UTXO view — unspent transaction outputs (detailed table)
import { useEffect, useRef, useState } from 'react';
import { api, type UtxoEntry } from '../api';
import { useStore } from '../store';

type Result = { key: string; generation: number; attempt: number; status: 'ready'; outputs: UtxoEntry[]; total: number }
  | { key: string; generation: number; attempt: number; status: 'error' };

function validateOutputs(value: unknown): { outputs: UtxoEntry[]; total: number } {
  if (!Array.isArray(value)) throw new Error('Invalid UTXO response');
  const seen = new Set<string>();
  let total = 0;
  for (const item of value) {
    if (!item || typeof item !== 'object' || typeof item.tx_hash !== 'string' || !/^[0-9a-f]{64}$/i.test(item.tx_hash) ||
        !Number.isSafeInteger(item.tx_index) || item.tx_index < 0 || item.tx_index > 0xffffffff ||
        !Number.isSafeInteger(item.value) || item.value < 0 ||
        !Number.isSafeInteger(item.keyinstance_id) ||
        typeof item.is_coinbase !== 'boolean' || typeof item.script_pubkey !== 'string' || !/^(?:[0-9a-f]{2})*$/i.test(item.script_pubkey)) {
      throw new Error('Invalid UTXO');
    }
    const outpoint = `${item.tx_hash.toLowerCase()}:${item.tx_index}`;
    if (seen.has(outpoint)) throw new Error('Duplicate UTXO');
    seen.add(outpoint);
    total += item.value;
    if (!Number.isSafeInteger(total)) throw new Error('UTXO total overflow');
  }
  return { outputs: value as UtxoEntry[], total };
}

export function UtxoView() {
  const { activeAccountId, activeWalletPath, walletInstanceToken } = useStore();
  const key = JSON.stringify([activeWalletPath, walletInstanceToken, activeAccountId]);
  const context = useRef({ key, generation: 0 });
  if (context.current.key !== key) context.current = { key, generation: context.current.generation + 1 };
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<Result | null>(null);
  const ready = activeAccountId !== null && !!activeWalletPath && !!walletInstanceToken;

  useEffect(() => {
    const generation = ++context.current.generation;
    let active = true;
    const current = () => active && context.current.generation === generation;
    if (ready && activeAccountId !== null) {
      api.getUtxos(activeAccountId).then(validateOutputs).then(data => {
        if (current()) setResult({ key, generation, attempt, status: 'ready', ...data });
      }).catch(() => {
        if (current()) setResult({ key, generation, attempt, status: 'error' });
      });
    }
    return () => { active = false; };
  }, [activeAccountId, activeWalletPath, walletInstanceToken, key, ready, attempt]);

  if (!ready) return <div className="p-4 text-gray-400">Select an active wallet and account to view UTXOs.</div>;
  if (!result || result.key !== key || result.generation !== context.current.generation || result.attempt !== attempt) return <div className="p-4 text-gray-400">Loading UTXOs…</div>;
  if (result.status === 'error') return <div className="p-4 text-gray-400" role="alert">UTXOs unavailable. <button onClick={() => setAttempt(n => n + 1)}>Retry UTXOs</button></div>;
  if (!result.outputs.length) return <div className="p-4 text-gray-400">No unspent outputs.</div>;

  return (
    <div className="p-4">
      <h2 className="text-lg font-semibold mb-3 text-accent">Unspent Outputs (UTXOs)</h2>
      <div className="text-sm text-gray-400 mb-3">{result.outputs.length} UTXOs — Total: {result.total.toLocaleString()} sat</div>
      <div className="bg-void-900 rounded-lg border border-void-700 overflow-hidden">
        <div className="flex border-b border-void-700 px-4 py-2 text-xs text-gray-400 font-medium">
          <div className="flex-1">TX Hash</div>
          <div className="w-16 text-right">Vout</div>
          <div className="w-24 text-right">Value</div>
          <div className="w-20 text-right">Type</div>
        </div>
        {result.outputs.map(u => (
          <div key={`${u.tx_hash.toLowerCase()}:${u.tx_index}`} className="flex px-4 py-2 border-b border-void-800 hover:bg-void-800 transition-colors">
            <div className="flex-1 text-sm font-mono text-gray-300 truncate">{u.tx_hash.slice(0, 32)}…</div>
            <div className="w-16 text-right text-sm text-gray-300">{u.tx_index}</div>
            <div className="w-24 text-right text-sm text-gray-100">{u.value} sat</div>
            <div className="w-20 text-right text-xs text-gray-400">{u.is_coinbase ? 'coinbase' : 'unknown'}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
