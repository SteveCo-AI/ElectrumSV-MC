// History view — transaction history list with TX detail panel
// Enhanced: decodes on-chain data (Ordinals, OP_RETURN, STAS tokens)
import { useEffect, useRef, useState } from 'react';
import { api, type DecodedOutput, type HistoryEntry, type TransactionDetail } from '../api';
import { useStore } from '../store';

export function HistoryView() {
  const { activeAccountId, activeWalletPath, walletInstanceToken, setError, historyRefreshKey } = useStore();
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [historyError, setHistoryError] = useState(false);
  const [retry, setRetry] = useState(0);
  const [loadedKey, setLoadedKey] = useState<string | null>(null);
  const historyKey = JSON.stringify([activeWalletPath, walletInstanceToken, activeAccountId]);
  const detailGeneration = useRef(0);
  const detailContext = useRef(historyKey);
  if (detailContext.current !== historyKey) { detailContext.current = historyKey; detailGeneration.current++; }
  const [selectedTx, setSelectedTx] = useState<TransactionDetail | null>(null);
  const [txLoading, setTxLoading] = useState(false);
  const [txLabel, setTxLabel] = useState('');
  const [labelSaved, setLabelSaved] = useState(false);
  const [decodedOutputs, setDecodedOutputs] = useState<DecodedOutput[]>([]);
  const [decoding, setDecoding] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setHistory([]);
    detailGeneration.current++;
    setSelectedTx(null);
    setDecodedOutputs([]);
    setTxLoading(false);
    setDecoding(false);
    setHistoryError(false);
    setLoadedKey(null);
    if (activeAccountId === null) { setLoading(false); return () => { cancelled = true; detailGeneration.current++; }; }
    setLoading(true);
    api.getHistory(activeAccountId)
      .then(result => { if (!Array.isArray(result) || result.some(tx => !tx || typeof tx.tx_hash !== 'string' || !(tx.value_delta === null || Number.isSafeInteger(tx.value_delta)) || !(tx.block_height === null || Number.isSafeInteger(tx.block_height)))) throw new Error('Invalid history'); if (!cancelled) { setHistory(result); setLoadedKey(historyKey); } })
      .catch(() => { if (!cancelled) setHistoryError(true); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; detailGeneration.current++; };
  }, [activeAccountId, activeWalletPath, walletInstanceToken, historyRefreshKey, retry]);

  const handleTxClick = async (txHash: string) => {
    const generation = ++detailGeneration.current;
    const context = historyKey;
    const current = () => detailGeneration.current === generation && detailContext.current === context;
    setTxLoading(true);
    setSelectedTx(null);
    setDecodedOutputs([]);
    setDecoding(false);
    setLabelSaved(false);
    try {
      const detail = await api.getTransaction(txHash);
      if (!current()) return;
      setSelectedTx(detail);
      setTxLabel(detail.label ?? '');

      if (detail.detail_complete && detail.raw_tx !== null && detail.inputs !== null && detail.outputs !== null && detail.outputs.length > 0) {
        setDecoding(true);
        try {
          const decoded = await api.decodeTxOutputs(detail.outputs);
          if (current()) setDecodedOutputs(decoded);
        } catch (e) {
          if (current()) console.error('Decode failed:', e);
        } finally {
          if (current()) setDecoding(false);
        }
      }
    } catch (e: unknown) {
      if (current()) setError(`TX detail: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      if (current()) setTxLoading(false);
    }
  };

  const handleSaveTxLabel = async () => {
    if (!selectedTx) return;
    try {
      await api.setTxLabel(selectedTx.txid, txLabel);
      setLabelSaved(true);
      setTimeout(() => setLabelSaved(false), 2000);
    } catch (e: any) {
      setError(`TX label: ${e.message}`);
    }
  };

  // Render decoded output badge
  const renderDecodedBadge = (decoded: DecodedOutput | undefined) => {
    if (!decoded || decoded.kind.type === 'plain') return null;
    const k = decoded.kind;
    const badges: Record<string, { icon: string; label: string; color: string }> = {
      ordinal: { icon: '🖼', label: k.content_type || 'Ordinal', color: 'text-purple-400' },
      op_return_protocol: { icon: '📎', label: k.protocol || 'OP_RETURN', color: 'text-blue-400' },
      stas_token: { icon: '🪙', label: k.symbol || 'Token', color: 'text-yellow-400' },
    };
    const badge = badges[k.type];
    if (!badge) return null;
    return (
      <span className={`text-xs ${badge.color} ml-2`}>
        {badge.icon} {badge.label}
      </span>
    );
  };

  // Render decoded output detail
  const renderDecodedDetail = (decoded: DecodedOutput) => {
    const k = decoded.kind;
    switch (k.type) {
      case 'ordinal':
        return (
          <div className="mt-2 bg-void-700 p-2 rounded">
            <div className="text-xs text-purple-400 mb-1">
              🖼 1Sat Ordinal — {k.protocol}
            </div>
            <div className="text-xs text-gray-400">
              Type: {k.content_type}
            </div>
            {k.content_text && (
              <div className="text-xs text-gray-300 mt-1 break-all">
                {k.content_text}
              </div>
            )}
          </div>
        );
      case 'op_return_protocol':
        return (
          <div className="mt-2 bg-void-700 p-2 rounded">
            <div className="text-xs text-blue-400 mb-1">
              📎 {k.protocol} Protocol
            </div>
            <div className="text-xs text-gray-400 font-mono break-all">
              {JSON.stringify(k.data)}
            </div>
          </div>
        );
      case 'stas_token':
        return (
          <div className="mt-2 bg-void-700 p-2 rounded">
            <div className="text-xs text-yellow-400 mb-1">
              🪙 STAS Token — {k.symbol || 'Unknown'}
            </div>
            <div className="text-xs text-gray-400">
              {k.amount != null ? `${k.amount} units` : 'Amount unknown'}
            </div>
            {k.contract_txid && (
              <div className="text-xs font-mono text-gray-500 truncate mt-1">
                Contract: {k.contract_txid.slice(0, 24)}...
              </div>
            )}
          </div>
        );
      default:
        return null;
    }
  };

  const hasCompleteDetails = selectedTx !== null && selectedTx.detail_complete && selectedTx.raw_tx !== null && selectedTx.inputs !== null && selectedTx.outputs !== null;

  if (activeAccountId === null) return <div className="p-4 text-gray-400">Select an account to view history.</div>;
  if (loading || (!historyError && loadedKey !== historyKey)) return <div className="p-4 text-gray-400">Loading history...</div>;
  if (historyError) return <div className="p-4" role="alert">History unavailable. <button onClick={() => setRetry(n => n + 1)}>Retry history</button></div>;
  if (!history.length) return <div className="p-4 text-gray-400">No transactions yet.</div>;

  return (
    <div className="flex h-full">
      {/* History table */}
      <div className={`p-4 ${selectedTx ? 'flex-1' : 'w-full'}`}>
        <h2 className="text-lg font-semibold mb-3 text-accent">Transaction History</h2>
        <div className="bg-void-900 rounded-lg border border-void-700 overflow-hidden">
          {/* Table header */}
          <div className="flex border-b border-void-700 px-4 py-2 text-xs text-gray-400 font-medium">
            <div className="flex-1">Date</div>
            <div className="flex-1">TX Hash</div>
            <div className="w-24 text-right">Amount</div>
            <div className="w-36 text-right">Status</div>
          </div>
          {/* Rows */}
          {history.map((tx, i) => {
            const isIncoming = tx.value_delta !== null && tx.value_delta > 0;
            const isConfirmed = tx.block_height !== null && tx.block_height > 0;
            const status = isConfirmed ? 'Server: confirmed' : 'Pending';
            const date = isConfirmed ? `Block ${tx.block_height}` : 'Pending';
            return (
              <div
                key={i}
                onClick={() => handleTxClick(tx.tx_hash)}
                className={`flex px-4 py-2.5 border-b border-void-800 hover:bg-void-800 transition-colors cursor-pointer ${
                  selectedTx?.txid === tx.tx_hash ? 'bg-void-800 border-l-2 border-accent' : ''
                }`}
              >
                <div className="flex-1 text-sm text-gray-400">{date}</div>
                <div className="flex-1 text-sm font-mono text-gray-300 truncate">
                  {tx.tx_hash?.slice(0, 24) || 'unknown'}...
                </div>
                <div className={`w-24 text-right text-sm font-medium ${tx.value_delta === null || tx.value_delta === 0 ? 'text-gray-400' : isIncoming ? 'text-success' : 'text-danger'}`}>
                  {tx.value_delta === null ? 'Unknown' : `${isIncoming ? '+' : ''}${tx.value_delta} sat`}
                </div>
                <div className="w-36 text-right">
                  <span title={isConfirmed ? "Reported by server; chain validation is not guaranteed" : undefined} className={`text-xs px-2 py-0.5 rounded-full ${
                    isConfirmed ? 'bg-success/20 text-success' : 'bg-warning/20 text-warning'
                  }`}>
                    {status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* TX Detail Panel */}
      {selectedTx && (
        <div className="w-96 border-l border-void-700 bg-void-900 p-4 overflow-y-auto">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-sm font-semibold text-accent">Transaction Details</h3>
            <button
              onClick={() => { detailGeneration.current++; setSelectedTx(null); setDecodedOutputs([]); setTxLoading(false); setDecoding(false); }}
              className="text-gray-400 hover:text-gray-100 text-sm"
            >
              Close
            </button>
          </div>

          {txLoading ? (
            <div className="text-gray-400 text-sm">Loading...</div>
          ) : selectedTx.status === 'not_found' ? (
            <div className="text-gray-400 text-sm">Transaction not found in wallet.</div>
          ) : (
            <div className="space-y-4">
              {/* TXID */}
              <div>
                <div className="text-xs text-gray-400 mb-1">Transaction ID</div>
                <div className="font-mono text-xs text-gray-300 break-all bg-void-800 p-2 rounded">
                  {selectedTx.txid}
                </div>
              </div>

              {/* TX Label */}
              <div>
                <div className="text-xs text-gray-400 mb-1">Label</div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={txLabel}
                    onChange={(e) => setTxLabel(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleSaveTxLabel(); }}
                    placeholder="— add label —"
                    className="flex-1 bg-void-800 border border-void-700 rounded px-2 py-1.5 text-xs text-gray-100 focus:border-accent outline-none"
                  />
                  <button
                    onClick={handleSaveTxLabel}
                    className="bg-accent text-white rounded px-3 py-1.5 text-xs font-medium"
                  >
                    {labelSaved ? '✓' : 'Set'}
                  </button>
                </div>
              </div>

              {/* Status */}
              <div>
                <div className="text-xs text-gray-400 mb-1">Status</div>
                <span title={selectedTx.status === 'confirmed' ? "Reported by server; chain validation is not guaranteed" : undefined} className="text-xs px-2 py-0.5 rounded-full bg-success/20 text-success">
                  {selectedTx.status === 'confirmed' ? 'Server: confirmed' : selectedTx.status}
                </span>
              </div>

              {/* Account */}
              {selectedTx.account_id !== null && (
                <div>
                  <div className="text-xs text-gray-400 mb-1">Account</div>
                  <div className="text-sm text-gray-300">#{selectedTx.account_id}</div>
                </div>
              )}

              {/* Fee */}
              {selectedTx.fee !== null && (
                <div>
                  <div className="text-xs text-gray-400 mb-1">Fee</div>
                  <div className="text-sm text-gray-300">{selectedTx.fee.toLocaleString()} sat</div>
                </div>
              )}

              {!hasCompleteDetails && (
                <div className="text-sm text-warning">Transaction details are incomplete: full transaction data is unavailable.</div>
              )}

              {/* Inputs */}
              {hasCompleteDetails && selectedTx.inputs !== null && (
                <div>
                  <div className="text-xs text-gray-400 mb-1">Inputs ({selectedTx.inputs.length})</div>
                  {selectedTx.inputs.map((inp, i) => (
                    <div key={i} className="bg-void-800 p-2 rounded mb-1 text-xs">
                      <div className="font-mono text-gray-400 truncate">{inp.prev_tx_hash?.slice(0, 32) || 'unknown'}...</div>
                      <div className="text-gray-400">vout: {inp.prev_vout}</div>
                    </div>
                  ))}
                </div>
              )}

              {/* Outputs with decoded data */}
              {hasCompleteDetails && selectedTx.outputs !== null && (
                <div>
                  <div className="text-xs text-gray-400 mb-1">
                    Outputs ({selectedTx.outputs.length})
                    {decoding && <span className="ml-2 text-accent">decoding...</span>}
                  </div>
                  {selectedTx.outputs.map((out, i) => {
                    const decoded = decodedOutputs[i];
                    return (
                      <div key={i} className="bg-void-800 p-2 rounded mb-1 text-xs">
                        <div className="flex items-center">
                          <div className="text-gray-300">{out.value.toLocaleString()} sat</div>
                          {renderDecodedBadge(decoded)}
                        </div>
                        <div className="font-mono text-gray-400 truncate mt-1">
                          {out.script_pubkey.slice(0, 40)}...
                        </div>
                        {decoded && renderDecodedDetail(decoded)}
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Raw TX */}
              {selectedTx.raw_tx && (
                <div>
                  <div className="text-xs text-gray-400 mb-1">Raw Transaction</div>
                  <div className="font-mono text-xs text-gray-400 bg-void-800 p-2 rounded break-all max-h-32 overflow-y-auto">
                    {selectedTx.raw_tx.length > 500
                      ? selectedTx.raw_tx.slice(0, 500) + '...'
                      : selectedTx.raw_tx}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}