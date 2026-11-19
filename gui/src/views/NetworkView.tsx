// Network view — network status, server list, connect/disconnect, sync, network switching
import { useEffect, useState, useCallback, useRef } from 'react';
import { api } from '../api';
import { useStore } from '../store';

type HeaderSyncProgress = { synced: number; new_tip: number; server_tip: number; message: string };

function parseHeaderProgress(value: unknown): HeaderSyncProgress {
  if (!value || typeof value !== 'object') throw new Error('Invalid header sync response');
  const result = value as Record<string, unknown>;
  const isHeight = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
  if (!isHeight(result.synced) || !isHeight(result.new_tip) || !isHeight(result.server_tip)
      || result.new_tip > result.server_tip || result.synced > result.new_tip
      || (result.synced === 0 && result.new_tip < result.server_tip)
      || typeof result.message !== 'string' || !result.message.trim()) {
    throw new Error('Invalid header sync response');
  }
  return result as HeaderSyncProgress;
}

export function NetworkView() {
  const { activeWalletPath, walletInstanceToken, activeAccountId, triggerHistoryRefresh, triggerBalanceRefresh } = useStore();
  const context = useRef({ wallet: activeWalletPath, token: walletInstanceToken, account: activeAccountId, generation: 0 });
  if (context.current.wallet !== activeWalletPath || context.current.token !== walletInstanceToken || context.current.account !== activeAccountId) {
    context.current = { wallet: activeWalletPath, token: walletInstanceToken, account: activeAccountId, generation: context.current.generation + 1 };
  }
  const scanInFlight = useRef(false);
  const [scanEnd, setScanEnd] = useState('100');
  const [scanMessage, setScanMessage] = useState<{ generation: number; text: string; error: boolean } | null>(null);
  const [info, setInfo] = useState<any>(null);
  const [servers, setServers] = useState<any[]>([]);
  const [networks, setNetworks] = useState<{ id: string; name: string }[]>([]);
  const [activeNetwork, setActiveNetwork] = useState('mainnet');
  const [headerStore, setHeaderStore] = useState<any>(null);
  const [headerProgress, setHeaderProgress] = useState<HeaderSyncProgress | null>(null);
  const [chainInfo, setChainInfo] = useState<any>(null);
  const [connecting, setConnecting] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [netInfo, srvResult, netList, hdrStore] = await Promise.all([
        api.getNetworkInfo().catch(() => null),
        api.getServers().catch(() => null),
        api.listNetworks().catch(() => []),
        api.getHeaderStoreInfo().catch(() => null),
      ]);
      if (netInfo) setInfo(netInfo);
      if (srvResult) setServers(srvResult);
      if (netList) setNetworks(netList as any[]);
      if (hdrStore) setHeaderStore(hdrStore);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleConnect = async (host: string) => {
    setConnecting(true);
    setHeaderProgress(null);
    setError(null);
    setSuccess(null);
    try {
      const serverInfo = servers.find((server) => server.host === host);
      const port = serverInfo?.ssl_port || 50002;
      await api.connectServer(host, port);
      setSuccess(`Connected to ${host}`);
      await loadData();
    } catch (e: any) {
      setError(e.message || `Failed to connect to ${host}`);
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    setConnecting(true);
    setHeaderProgress(null);
    setError(null);
    try {
      await api.disconnectServer();
      setSuccess('Disconnected');
      await loadData();
    } catch (e: any) {
      setError(e.message || 'Disconnect failed');
    } finally {
      setConnecting(false);
    }
  };

  const handleSyncWallet = async () => {
    setSyncing(true);
    setError(null);
    try {
      const result = await api.syncWallet();
      if (!result.synced) throw new Error(result.message);
      setSuccess(result.message);
    } catch (e: any) {
      setError(e.message || 'Sync failed');
    } finally {
      setSyncing(false);
    }
  };

  const handleAddressScan = async () => {
    const end = Number(scanEnd);
    if (scanInFlight.current || !activeWalletPath || !walletInstanceToken || activeAccountId === null) return;
    if (!/^\d+$/.test(scanEnd) || !Number.isSafeInteger(end) || end < 1 || end > 1000) {
      setScanMessage({ generation: context.current.generation, text: 'Enter a whole number from 1 to 1000.', error: true });
      return;
    }
    const generation = context.current.generation;
    const isCurrent = () => {
      const current = useStore.getState();
      return context.current.generation === generation && current.activeWalletPath === activeWalletPath &&
        current.walletInstanceToken === walletInstanceToken && current.activeAccountId === activeAccountId;
    };
    scanInFlight.current = true;
    setSyncing(true);
    setScanMessage(null);
    try {
      const result = await api.scanAddressRange(activeAccountId, walletInstanceToken, end);
      if (!isCurrent()) return;
      if (!result || result.start_index !== 0 || result.end_index_exclusive !== end ||
          !Number.isSafeInteger(result.new_keys) || result.new_keys < 0 || result.new_keys > end * 2 ||
          typeof result.server_host !== 'string' || !result.server_host.trim()) {
        throw new Error('Invalid scan response');
      }
      triggerHistoryRefresh();
      triggerBalanceRefresh();
      setScanMessage({ generation, text: `Scanned indices 0–${end - 1} on both branches using ${result.server_host}. ${result.new_keys} new keys found.`, error: false });
    } catch (e: unknown) {
      if (!isCurrent()) return;
      const detail = typeof e === 'string' ? e : e instanceof Error ? e.message : 'Scan failed';
      setScanMessage({ generation, text: `${detail}. If the connection or application stopped during saving, the outcome may be unknown; inspect the wallet before retrying.`, error: true });
    } finally {
      scanInFlight.current = false;
      setSyncing(false);
    }
  };

  const handleSyncHeaders = async () => {
    setSyncing(true);
    setError(null);
    setSuccess(null);
    setHeaderProgress(null);
    try {
      const result = parseHeaderProgress(await api.syncHeaders());
      setHeaderProgress(result);
      await loadData();
    } catch (e: any) {
      setError(e.message || 'Header sync failed');
    } finally {
      setSyncing(false);
    }
  };

  const handleBanServer = async (host: string) => {
    setError(null);
    try {
      await api.banServer(host);
      setSuccess(`Banned ${host}`);
      await loadData();
    } catch (e: any) {
      setError(e.message || `Failed to ban ${host}`);
    }
  };

  const handleSwitchNetwork = async (networkId: string) => {
    setConnecting(true);
    setError(null);
    setHeaderProgress(null);
    try {
      await api.switchNetwork(networkId);
      setActiveNetwork(networkId);
      setSuccess(`Switched to ${networkId}`);
      await loadData();
    } catch (e: any) {
      setError(e.message || `Failed to switch to ${networkId}`);
    } finally {
      setConnecting(false);
    }
  };

  const handleFetchChainInfo = async () => {
    setError(null);
    try {
      const info = await api.wocGetChainInfo();
      setChainInfo(info);
    } catch (e: any) {
      setError(e.message || 'Failed to fetch chain info');
    }
  };

  return (
    <div className="p-4">
      <h2 className="text-lg font-semibold mb-4 text-accent">Network</h2>
      <div className="space-y-4 max-w-2xl">
        {/* Status + actions */}
        <div className="bg-void-900 rounded-lg p-4">
          <div className="text-sm text-gray-400 mb-2">Status</div>
          <div className="flex items-center gap-2 mb-3">
            <span className={`w-2 h-2 rounded-full ${info?.connected ? 'bg-success' : 'bg-danger'}`} />
            <span className="text-sm text-gray-100">
              {info?.connected ? 'Connected' : 'Disconnected'} — {activeNetwork}
            </span>
          </div>
          {info && (
            <div className="text-sm text-gray-400 mt-1">
              Tip: block {info.tip_height ?? 0}
            </div>
          )}
          {headerStore && (
            <div className="text-xs text-gray-500 mt-1">
              Headers: {headerStore.header_count ?? '?'} | Stored height: {headerStore.tip_height ?? '?'}
            </div>
          )}
          <div className="flex gap-2 mt-3">
            <button
              onClick={handleSyncWallet}
              disabled={syncing || connecting}
              className="bg-accent hover:bg-accent-hover text-white rounded-lg px-3 py-1.5 text-xs font-medium disabled:opacity-50 transition-colors"
            >
              {syncing ? 'Syncing…' : 'Sync Wallet'}
            </button>
            <button
              onClick={handleSyncHeaders}
              disabled={syncing || connecting}
              className="bg-void-800 hover:bg-void-700 text-gray-100 rounded-lg px-3 py-1.5 text-xs font-medium border border-void-700 disabled:opacity-50 transition-colors"
            >
              {headerProgress && headerProgress.new_tip < headerProgress.server_tip ? 'Continue Header Sync' : 'Sync Headers'}
            </button>
            {info?.connected && (
              <button
                onClick={handleDisconnect}
                disabled={connecting || syncing}
                className="text-danger hover:text-red-400 rounded-lg px-3 py-1.5 text-xs font-medium border border-danger/30 transition-colors"
              >
                {connecting ? '…' : 'Disconnect'}
              </button>
            )}
          </div>
          {headerProgress && (
            <div role="status" className="text-xs text-gray-400 mt-2">
              <div>Stored header tip: {headerProgress.new_tip}; server-reported tip: {headerProgress.server_tip}.</div>
              <div>{headerProgress.new_tip < headerProgress.server_tip ? 'Partial progress. Continue header sync to request more headers.' : 'Header sync reached the server-reported height.'}</div>
              <div>Server agreement does not establish independent chain consensus.</div>
            </div>
          )}
        </div>

        <div className="bg-void-900 rounded-lg p-4">
          <div className="text-sm text-gray-400 mb-2">Extended address discovery</div>
          <p className="text-xs text-gray-400 mb-2">Search both receiving and change branches from index 0 up to the number entered, excluding that number. The connected server sees the queried address script hashes, which can reveal and link wallet activity. Results depend on that server and cannot establish a complete balance.</p>
          <label className="text-xs text-gray-300" htmlFor="scan-end">End index (exclusive, 1–1000)</label>
          <div className="flex gap-2 mt-2">
            <input id="scan-end" type="number" min="1" max="1000" step="1" value={scanEnd} onChange={e => setScanEnd(e.target.value)} disabled={syncing || connecting} className="bg-void-800 text-gray-100 rounded-lg px-3 py-1.5 text-xs" />
            <button onClick={handleAddressScan} disabled={syncing || connecting || !info?.connected || !activeWalletPath || !walletInstanceToken || activeAccountId === null} className="bg-void-800 hover:bg-void-700 text-gray-100 rounded-lg px-3 py-1.5 text-xs font-medium border border-void-700 disabled:opacity-50">
              {scanInFlight.current ? 'Scanning…' : 'Scan addresses'}
            </button>
          </div>
          {scanMessage?.generation === context.current.generation && <div role="status" className={`text-xs mt-2 ${scanMessage.error ? 'text-danger' : 'text-success'}`}>{scanMessage.text}</div>}
        </div>

        {/* Network switching */}
        <div className="bg-void-900 rounded-lg p-4">
          <div className="text-sm text-gray-400 mb-2">Network</div>
          <div className="flex gap-2">
            {networks.map((net) => (
              <button
                key={net.id}
                onClick={() => handleSwitchNetwork(net.id)}
                disabled={syncing || connecting}
                className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${
                  activeNetwork === net.id
                    ? 'bg-accent text-white border-accent'
                    : 'bg-void-800 text-gray-300 border-void-700 hover:border-accent'
                }`}
              >
                {net.name}
              </button>
            ))}
            {networks.length === 0 && (
              <span className="text-xs text-gray-400">Loading networks…</span>
            )}
          </div>
        </div>

        {/* Server list */}
        <div className="bg-void-900 rounded-lg p-4">
          <div className="text-sm text-gray-400 mb-2">ElectrumX Servers</div>
          <div className="space-y-1">
            {servers.map((srvInfo) => (
              <div key={srvInfo.host} className="text-sm text-gray-300 font-mono flex items-center justify-between">
                <span>{srvInfo.host} <span className="text-gray-400">: {srvInfo.ssl_port}</span></span>
                <div className="flex gap-2">
                  <button
                    onClick={() => handleConnect(srvInfo.host)}
                    disabled={connecting || syncing}
                    className="text-xs text-accent hover:text-accent-hover disabled:opacity-50"
                  >
                    Connect
                  </button>
                  <button
                    onClick={() => handleBanServer(srvInfo.host)}
                    className="text-xs text-danger hover:text-red-400"
                  >
                    Ban
                  </button>
                </div>
              </div>
            ))}
            {!servers.length && <div className="text-gray-400">No servers loaded.</div>}
          </div>
        </div>

        {/* WhatsOnChain chain info */}
        <div className="bg-void-900 rounded-lg p-4">
          <div className="text-sm text-gray-400 mb-2">WhatsOnChain</div>
          <button
            onClick={handleFetchChainInfo}
            className="bg-void-800 hover:bg-void-700 text-gray-100 rounded-lg px-3 py-1.5 text-xs font-medium border border-void-700 transition-colors"
          >
            Fetch Chain Info
          </button>
          {chainInfo && (
            <pre className="mt-2 text-xs text-gray-400 font-mono overflow-x-auto">
              {JSON.stringify(chainInfo, null, 2)}
            </pre>
          )}
        </div>

        {error && <div className="text-sm text-danger p-3 bg-danger/10 rounded-lg">{error}</div>}
        {success && <div className="text-sm text-success p-3 bg-success/10 rounded-lg">{success}</div>}
      </div>
    </div>
  );
}
