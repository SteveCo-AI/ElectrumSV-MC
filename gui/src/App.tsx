// Main App — ElectrumSV-Mc GUI
// ElectrumSV-Original-Layout: MenuBar (top) → TabBar → Content (with left sidebar) → StatusBar (bottom)
// View routing: landing → login → main, Quit returns to landing

import { useEffect, useState } from 'react';
import { useStore } from './store';
import { api } from './api';
import { MenuBar } from './components/MenuBar';
import { StatusBar } from './components/StatusBar';
import { LandingPage } from './views/LandingPage';
import { LoginScreen } from './views/LoginScreen';
import { HistoryView } from './views/HistoryView';
import { SendView } from './views/SendView';
import { ReceiveView } from './views/ReceiveView';
import { ContactsView } from './views/ContactsView';
import { UtxoView } from './views/UtxoView';
import { SecurityView } from './views/SecurityView';
import { NetworkView } from './views/NetworkView';
import { ConsoleView } from './views/ConsoleView';
import { OrdinalsView } from './views/OrdinalsView';
import { TokensView } from './views/TokensView';
import { ServicesView } from './views/ServicesView';
// useDaemonLifecycle removed — Tauri mode has no daemon

function getTabs(t: ReturnType<typeof useTranslation>['t']) {
  return [
    { id: 'history', label: t.tabs.history, icon: '📋' },
    { id: 'send', label: t.tabs.send, icon: '📤' },
    { id: 'receive', label: t.tabs.receive, icon: '📥' },
    { id: 'contacts', label: t.tabs.contacts, icon: '👥' },
    { id: 'utxos', label: t.tabs.utxos, icon: '💰' },
    { id: 'ordinals', label: t.tabs.ordinals, icon: '🖼' },
    { id: 'tokens', label: t.tabs.tokens, icon: '🪙' },
    { id: 'services', label: t.tabs.services, icon: '🔧' },
    { id: 'security', label: t.tabs.security, icon: '🔒' },
    { id: 'network', label: t.tabs.network, icon: '🌐' },
    { id: 'console', label: t.tabs.console, icon: '🖥' },
  ];
}

import { useTranslation } from './i18n';

function AccountSidebar({ balanceStatus, retryBalance }: { balanceStatus: 'loading' | 'error' | 'ready'; retryBalance: () => void }) {
  const { walletName, balances, activeAccountId, accounts, setActiveAccount } = useStore();
  const { t } = useTranslation();
  const known = balanceStatus === 'ready' && accounts.length > 0 && accounts.every(a => balances[String(a.id)]);
  const totalBalance = known ? accounts.reduce((n, a) => n + balances[String(a.id)].total, 0) : null;
  const confirmedBalance = known ? accounts.reduce((n, a) => n + balances[String(a.id)].confirmed, 0) : null;
  const unconfirmedBalance = known ? accounts.reduce((n, a) => n + balances[String(a.id)].unconfirmed, 0) : null;
  const balanceValues = accounts.map(a => balances[String(a.id)]);
  const reservedBalance = known && balanceValues.length && balanceValues.every(b => b?.reserved != null) ? balanceValues.reduce((sum, b) => sum + b.reserved!, 0) : null;
  const availableBalance = known && balanceValues.length && balanceValues.every(b => b?.available != null) ? balanceValues.reduce((sum, b) => sum + b.available!, 0) : null;
  const [fiatTotal, setFiatTotal] = useState<number | null>(null);
  const [fiatCurrency, setFiatCurrency] = useState('USD');

  // Fetch exchange rate and show fiat equivalent
  useEffect(() => {
    if (totalBalance === null || totalBalance === 0) { setFiatTotal(null); return; }
    let cancelled = false;
    setFiatTotal(null);
    api.satoshisToFiat(totalBalance, fiatCurrency)
      .then(value => { if (!cancelled) setFiatTotal(value); })
      .catch(() => { if (!cancelled) setFiatTotal(null); });
    return () => { cancelled = true; };
  }, [totalBalance, fiatCurrency]);

  return (
    <div className="w-56 bg-void-900 h-full flex flex-col border-r border-void-700 overflow-y-auto">
      {/* Wallet name */}
      <div className="p-3 border-b border-void-700">
        <div className="text-sm font-semibold text-accent truncate">{walletName || t.sidebar.noWallet}</div>
        <div className="text-xs text-gray-400 mt-1">{t.sidebar.account} #{activeAccountId ?? '-'}</div>
      </div>

      {/* Balance summary */}
      <div className="p-3 border-b border-void-700">
        <div className="text-xs text-gray-400 mb-1">{t.sidebar.totalBalance}</div>
        <div className="text-lg font-semibold text-yellow-400">{totalBalance === null ? (balanceStatus === 'error' ? 'Balance unavailable' : 'Balance loading...') : `${totalBalance.toLocaleString()} sat`}</div>
        {balanceStatus === 'error' && <button onClick={retryBalance}>Retry balance</button>}
        <div className="text-xs text-gray-400">Last synced balance; refresh by syncing the wallet.</div>
        {fiatTotal !== null && (
          <div className="text-xs text-gray-400 mt-0.5">
            ≈ {fiatTotal.toFixed(2)} {fiatCurrency}
          </div>
        )}
        <div className="mt-2 space-y-1">
          <div className="flex justify-between text-xs"><span>Reserved</span><span>{reservedBalance == null ? 'unknown' : `${reservedBalance.toLocaleString()} sat`}</span></div>
          <div className="flex justify-between text-xs"><span>Available</span><span>{availableBalance == null ? 'unknown' : `${availableBalance.toLocaleString()} sat`}</span></div>
          <div className="flex justify-between text-xs">
            <span className="text-gray-400">{t.sidebar.confirmed}</span>
            <span className="text-success">{confirmedBalance === null ? 'unknown' : confirmedBalance.toLocaleString()}</span>
          </div>
          <div className="flex justify-between text-xs">
            <span className="text-gray-400">{t.sidebar.unconfirmed}</span>
            <span className="text-warning">{unconfirmedBalance === null ? 'unknown' : unconfirmedBalance.toLocaleString()}</span>
          </div>
        </div>
      </div>

      {/* Account list */}
      <div className="p-3 border-b border-void-700">
        <div className="text-xs text-gray-400 mb-2">{t.sidebar.accounts}</div>
        {accounts.map((acc) => {
          const isActive = acc.id === activeAccountId;
          const bal = balances[String(acc.id)];
          return (
            <button
              key={acc.id}
              onClick={() => setActiveAccount(acc.id)}
              className={`w-full text-left py-1.5 px-2 rounded text-sm transition-colors ${
                isActive
                  ? 'bg-void-800 text-accent border-l-2 border-accent'
                  : 'text-gray-300 hover:bg-void-800 border-l-2 border-transparent'
              }`}
            >
              <div className="flex justify-between items-center">
                <span>#{acc.id} {acc.name || acc.type}</span>
                {bal && (
                  <span className="text-xs text-gray-400">{bal.total.toLocaleString()}</span>
                )}
              </div>
            </button>
          );
        })}
      </div>

      {/* Spacer */}
      <div className="flex-1 p-3">
        <div className="text-xs text-gray-400 mb-2">{t.sidebar.activeTab}</div>
      </div>
    </div>
  );
}

function MainView() {
  const {
    activeTab, setActiveTab,
    setNetworkInfo, setWalletInfo, setAccounts, setActiveAccount,
    updateBalance, activeAccountId, activeWalletPath, walletInstanceToken, isAuthenticated, setError, migrationMessage,
    triggerHistoryRefresh, balanceRefreshKey,
  } = useStore();
  const { t } = useTranslation();
  const TABS = getTabs(t);
  const [balanceAttempt, setBalanceAttempt] = useState(0);
  const [balanceState, setBalanceState] = useState<{ path: string | null; token: string | null; status: 'loading' | 'error' | 'ready' }>({ path: null, token: null, status: 'loading' });
  const balanceStatus = balanceState.path === activeWalletPath && balanceState.token === walletInstanceToken ? balanceState.status : 'loading';

  // Load data on mount
  useEffect(() => {
    if (!isAuthenticated) return;
    let cancelled = false;

    api.getNetworkInfo()
      .then((info: any) => {
        if (cancelled) return;
        setNetworkInfo({
          connected: info.connected ?? false,
          network: useStore.getState().network,
          blockHeight: info.tip_height ?? 0,
        });
      })
      .catch((e: Error) => { if (!cancelled) setError(`Network info: ${e.message}`); });

    api.getWalletInfo()
      .then((r: any) => {
        if (!cancelled) setWalletInfo({ walletName: r.wallet_name ?? '', walletLoaded: true });
      })
      .catch((e: Error) => { if (!cancelled) setError(`Wallet info: ${e.message}`); });

    return () => { cancelled = true; };
  }, [isAuthenticated, activeWalletPath, walletInstanceToken]);

  useEffect(() => {
    if (!isAuthenticated) return;
    let cancelled = false;
    setBalanceState({ path: activeWalletPath, token: walletInstanceToken, status: 'loading' });
    useStore.setState({ balances: {} });
    (async () => {
      try {
        const result: any = await api.getAccounts();
        const list = Array.isArray(result) ? result : result.accounts;
        if (!Array.isArray(list) || !list.length) throw new Error('No accounts');
        const mapped = list.map((a: any) => ({ id: a.account_id ?? a.id, name: a.account_name ?? a.name ?? '', type: 'standard' }));
        if (mapped.some((a: any) => !Number.isSafeInteger(a.id)) || new Set(mapped.map((a: any) => a.id)).size !== mapped.length) throw new Error('Invalid account');
        const entries = await Promise.all(mapped.map(async (a: any) => {
          const bal = await api.getBalance(a.id);
          if (![bal.total, bal.confirmed, bal.unconfirmed].every(Number.isSafeInteger) ||
              [bal.reserved, bal.available].some(v => v != null && !Number.isSafeInteger(v))) throw new Error('Invalid balance');
          return [String(a.id), { ...bal, unmatured: 0 }] as const;
        }));
        for (const field of ['total', 'confirmed', 'unconfirmed', 'reserved', 'available'] as const) {
          const values = entries.map(([, b]) => b[field]);
          if (values.every(v => v != null) && !Number.isSafeInteger(values.reduce<number>((sum, v) => sum + v!, 0))) throw new Error('Invalid aggregate');
        }
        if (cancelled || useStore.getState().activeWalletPath !== activeWalletPath || useStore.getState().walletInstanceToken !== walletInstanceToken || !useStore.getState().isAuthenticated) return;
        setAccounts(mapped);
        const selected = useStore.getState().activeAccountId;
        setActiveAccount(mapped.some((a: any) => a.id === selected) ? selected! : mapped[0].id);
        useStore.setState({ balances: Object.fromEntries(entries) });
        setBalanceState({ path: activeWalletPath, token: walletInstanceToken, status: 'ready' });
      } catch {
        if (!cancelled) setBalanceState({ path: activeWalletPath, token: walletInstanceToken, status: 'error' });
      }
    })();
    return () => { cancelled = true; };
  }, [isAuthenticated, activeWalletPath, walletInstanceToken, balanceAttempt, balanceRefreshKey]);

  // Tauri Events: Live updates (replaces SSE/EventSource)
  useEffect(() => {
    if (!isAuthenticated) return;

    let cancelled = false;
    let unlistenFns: (() => void)[] = [];

    (async () => {
      const { listen } = await import('@tauri-apps/api/event');
      if (cancelled) return;

      const unlisten1 = await listen('new_transaction', (event) => {
        if (cancelled) return;
        const data = event.payload as any;
        triggerHistoryRefresh();
        if (data.account_id !== undefined) setBalanceAttempt(n => n + 1);
      });

      const unlisten2 = await listen('balance_changed', (event) => {
        if (!cancelled && event.payload) setBalanceAttempt(n => n + 1);
      });

      const unlisten3 = await listen('new_block', (event) => {
        if (cancelled) return;
        const data = event.payload as any;
        setNetworkInfo({
          connected: true,
          network: useStore.getState().network,
          blockHeight: data.height ?? 0,
        });
      });

      unlistenFns = [unlisten1, unlisten2, unlisten3];
      if (cancelled) unlistenFns.forEach(fn => fn());
    })().catch(() => {
      // Tauri event listener setup failed — non-fatal
    });

    return () => {
      cancelled = true;
      unlistenFns.forEach((fn) => fn());
    };
  }, [isAuthenticated, activeWalletPath, walletInstanceToken]);

  const handleQuit = async () => {
    // Close the active wallet before returning to landing
    const { activeWalletPath, resetToLanding } = useStore.getState();
    if (activeWalletPath) {
      try {
        await api.closeWallet(activeWalletPath);
      } catch {
        // Wallet might already be closed — ignore
      }
    }
    resetToLanding();
  };

  return (
    <div className="flex flex-col h-screen bg-void-950 text-gray-100">
      {migrationMessage && <div className="p-2 text-sm text-warning" role="status">{migrationMessage}</div>}
      {/* Menu bar (top) */}
      <MenuBar onQuit={handleQuit} />

      {/* Tab bar (horizontal tabs like ElectrumSV) */}
      <div className="flex bg-void-900 border-b border-void-700">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2.5 text-sm flex items-center gap-2 border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-accent text-accent bg-void-800'
                : 'border-transparent text-gray-400 hover:text-gray-100 hover:bg-void-800'
            }`}
          >
            <span>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Main content area: sidebar + view */}
      <div className="flex flex-1 overflow-hidden">
        <AccountSidebar balanceStatus={balanceStatus} retryBalance={() => setBalanceAttempt(n => n + 1)} />
        <main className="flex-1 overflow-auto">
          {activeTab === 'history' && <HistoryView />}
          {activeTab === 'send' && <SendView />}
          {activeTab === 'receive' && <ReceiveView />}
          {activeTab === 'contacts' && <ContactsView />}
          {activeTab === 'utxos' && <UtxoView />}
          {activeTab === 'ordinals' && <OrdinalsView />}
          {activeTab === 'tokens' && <TokensView />}
          {activeTab === 'services' && <ServicesView />}
          {activeTab === 'security' && <SecurityView />}
          {activeTab === 'network' && <NetworkView />}
          {activeTab === 'console' && <ConsoleView />}
        </main>
      </div>

      {/* Status bar (bottom) */}
      <StatusBar />
    </div>
  );
}

function MigrationGate() {
  const { migrationGate, migrationMessage, resetToLanding } = useStore();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const closeAndReturn = async () => {
    setBusy(true); setError(null);
    try {
      const status = await api.getWalletInfo();
      if (typeof status?.is_open !== 'boolean') throw new Error('Wallet state unavailable');
      if (status.is_open) await api.closeWallet('');
      resetToLanding();
    } catch (e: any) { setError(e?.message || String(e)); }
    finally { setBusy(false); }
  };
  if (migrationGate === 'pending') return <div className="p-6 text-warning" role="status">Migration in progress. Do not close the application.</div>;
  return <div className="p-6 space-y-4" role="alert">
    <p>{migrationMessage}</p>
    <p>Close and reopen the wallet to check its status before using it. Do not retry the operation until its outcome is known.</p>
    {error && <p className="text-danger">{error}</p>}
    <button disabled={busy} onClick={closeAndReturn} className="text-accent">Close wallet and return to wallet list</button>
  </div>;
}

function MigrationReopenCheck() {
  const { activeWalletPath, migrationVerificationPath, migrationExpectedFormat, migrationNeedsTotpCheck, clearMigrationVerification, resetToLanding } = useStore();
  const [differentFormat, setDifferentFormat] = useState<33 | 34 | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    api.getWalletInfo().then(async status => {
      if (!active) return;
      if (status?.is_open !== true || status.is_unlocked !== true || (status.wallet_format !== 33 && status.wallet_format !== 34)) {
        setError('Wallet format or unlocked state is unknown. Close the wallet and check again.'); return;
      }
      let protection = '';
      if (migrationNeedsTotpCheck) {
        const totp = await api.getTotpStatus();
        if (!active) return;
        if (typeof totp.enabled !== 'boolean') { setError('2FA status is unknown. Close the wallet and check again.'); return; }
        protection = totp.enabled ? ' 2FA is enabled.' : ' 2FA is disabled; set it up again before signing transactions.';
      }
      if (activeWalletPath !== migrationVerificationPath) {
        if (migrationNeedsTotpCheck) {
          setDifferentFormat(null);
          setError('A different wallet was opened. Reopen the original wallet to check its 2FA status.');
        } else {
          setDifferentFormat(status.wallet_format);
          setError('A different wallet was opened. Reopen the migrated wallet or explicitly continue with this different wallet.');
        }
        return;
      }
      if (migrationExpectedFormat !== null && status.wallet_format !== migrationExpectedFormat) {
        setError('The reopened format does not match the migration outcome. Close the wallet and investigate before continuing.'); return;
      }
      clearMigrationVerification(`Reopened wallet reports format ${status.wallet_format}. The format marker is not an authentication proof.${protection}`);
    }).catch(() => { if (active) setError('Could not check wallet status. Close the wallet and check again.'); });
    return () => { active = false; };
  }, [activeWalletPath, migrationVerificationPath, migrationExpectedFormat, migrationNeedsTotpCheck, clearMigrationVerification]);
  const closeAndReturn = async () => {
    setBusy(true); setError(null);
    try { await api.closeWallet(''); resetToLanding(); }
    catch (e: any) { setError(e?.message || String(e)); }
    finally { setBusy(false); }
  };
  return <div className="p-6 space-y-4" role="status">
    <p>Checking the reopened wallet before use.</p>
    {error && <p className="text-warning">{error}</p>}
    {differentFormat !== null && <button onClick={() => clearMigrationVerification(`A different wallet was explicitly selected; it reports format ${differentFormat}.`)} className="text-accent">Continue with this different wallet</button>}
    <button disabled={busy} onClick={closeAndReturn} className="text-accent">Close wallet and return to wallet list</button>
  </div>;
}

function App() {
  const { view, isAuthenticated, migrationGate, migrationVerificationPath, migrationNeedsTotpCheck } = useStore();
  // useDaemonLifecycle removed — Tauri mode has no daemon

  if (migrationGate && migrationGate !== 'idle') return <MigrationGate />;
  if (view === 'landing') return <LandingPage />;
  if (view === 'login' || !isAuthenticated) return <LoginScreen />;
  if (migrationVerificationPath || migrationNeedsTotpCheck) return <MigrationReopenCheck />;
  return <MainView />;
}

export default App;