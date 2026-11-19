import { create } from 'zustand';

export interface BalanceInfo {
  confirmed: number;
  unconfirmed: number;
  unmatured: number;
  total: number;
  reserved?: number;
  available?: number;
}

export interface WalletEntry {
  name: string;
  filename: string;
}

type AppView = 'landing' | 'login' | 'main';

interface WalletState {
  // View routing
  view: AppView;
  // Auth
  authToken: string | null;
  sessionToken: string | null; // Bearer token from TOTP login
  isAuthenticated: boolean;
  // Selected wallet (for login)
  selectedWallet: string | null;
  // Active wallet path (after open)
  activeWalletPath: string | null;
  walletInstanceToken: string | null;

  // Connection
  connected: boolean;
  network: string;
  blockHeight: number;
  server: string;

  // Wallet
  walletName: string;
  walletLoaded: boolean;
  accounts: Account[];
  activeAccountId: number | null;
  balances: Record<string, BalanceInfo>;

  // Wallet list (landing page)
  walletList: WalletEntry[];
  apiAvailable: boolean;

  // AUD-008: plan_id handle for the server-side TX plan (3-stage send workflow).
  // The full TxPlan stays server-side; the renderer only holds this id.
  planId: string | null;

  migrationGate: 'idle' | 'pending' | 'reopen_success' | 'reopen_not_committed' | 'reopen_unknown';
  migrationMessage: string | null;
  migrationVerificationPath: string | null;
  migrationExpectedFormat: 33 | 34 | null;
  migrationNeedsTotpCheck: boolean;
  requireWalletReopen: (message: string, walletPath?: string | null) => void;
  clearMigrationVerification: (message: string) => void;
  setMigrationGate: (gate: WalletState['migrationGate'], message?: string | null) => void;

  // UI state
  activeTab: string;
  loading: boolean;
  error: string | null;
  // History refresh trigger (incremented on SSE new_transaction)
  historyRefreshKey: number;
  balanceRefreshKey: number;

  // Actions
  setView: (v: AppView) => void;
  setAuthToken: (token: string | null) => void;
  setSessionToken: (token: string | null) => void;
  setAuthenticated: (v: boolean) => void;
  setSelectedWallet: (name: string | null) => void;
  setActiveWalletPath: (path: string | null) => void;
  setActiveWalletIdentity: (path: string, token: string | null) => void;
  setActiveTab: (tab: string) => void;
  setActiveAccount: (id: number) => void;
  setPlanId: (planId: string | null) => void;
  triggerHistoryRefresh: () => void;
  triggerBalanceRefresh: () => void;
  setLoading: (v: boolean) => void;
  setError: (e: string | null) => void;
  updateBalance: (accountId: string, info: BalanceInfo) => void;
  setAccounts: (accounts: Account[]) => void;
  setNetworkInfo: (info: { connected: boolean; network: string; blockHeight: number; server?: string }) => void;
  setWalletInfo: (info: { walletName: string; walletLoaded?: boolean }) => void;
  setWalletList: (w: WalletEntry[]) => void;
  setApiAvailable: (v: boolean) => void;
  resetToLanding: () => void;
}

export interface Account {
  id: number;
  name: string;
  type: string;
}

export const useStore = create<WalletState>((set) => ({
  view: 'landing',
  authToken: null,
  sessionToken: null,
  isAuthenticated: false,
  selectedWallet: null,
  activeWalletPath: null,
  walletInstanceToken: null,

  connected: false,
  network: 'mainnet',
  blockHeight: 0,
  server: '',

  walletName: '',
  walletLoaded: false,
  accounts: [],
  activeAccountId: null,
  balances: {},

  walletList: [],
  apiAvailable: false,

  planId: null,

  migrationGate: 'idle',
  migrationMessage: null,
  migrationVerificationPath: null,
  migrationExpectedFormat: null,
  migrationNeedsTotpCheck: false,
  requireWalletReopen: (migrationMessage, walletPath) => set(s => ({ migrationGate: 'reopen_unknown', migrationMessage, migrationVerificationPath: walletPath ?? s.activeWalletPath, migrationExpectedFormat: null, migrationNeedsTotpCheck: true })),
  clearMigrationVerification: (migrationMessage) => set({ migrationVerificationPath: null, migrationExpectedFormat: null, migrationNeedsTotpCheck: false, migrationMessage }),
  setMigrationGate: (migrationGate, migrationMessage = null) => set(s => ({ migrationGate, migrationMessage, migrationVerificationPath: migrationGate === 'pending' ? s.activeWalletPath : migrationGate === 'idle' ? null : s.migrationVerificationPath, migrationNeedsTotpCheck: migrationGate === 'pending' || migrationGate === 'idle' ? false : s.migrationNeedsTotpCheck, migrationExpectedFormat: migrationGate === 'reopen_success' ? 34 : migrationGate === 'reopen_not_committed' ? 33 : migrationGate === 'reopen_unknown' || migrationGate === 'idle' ? null : s.migrationExpectedFormat })),
  activeTab: 'history',
  loading: false,
  error: null,
  historyRefreshKey: 0,
  balanceRefreshKey: 0,

  setView: (v) => set({ view: v }),
  setAuthToken: (token) => set({ authToken: token, isAuthenticated: token !== null }),
  setSessionToken: (token) => set({ sessionToken: token }),
  setAuthenticated: (v) => set({ isAuthenticated: v }),
  setSelectedWallet: (name) => set({ selectedWallet: name }),
  setActiveWalletPath: (path) => set(s => s.activeWalletPath === path ? { activeWalletPath: path } : { activeWalletPath: path, walletInstanceToken: null, balances: {}, accounts: [], activeAccountId: null }),
  setActiveWalletIdentity: (path, token) => set(s => ({ activeWalletPath: path, walletInstanceToken: typeof token === 'string' && token.length > 0 ? token : null, ...(s.activeWalletPath !== path || s.walletInstanceToken !== token ? { balances: {}, accounts: [], activeAccountId: null } : {}) })),
  setActiveTab: (tab) => set({ activeTab: tab }),
  setActiveAccount: (id) => set({ activeAccountId: id }),
  setLoading: (v) => set({ loading: v }),
  setError: (e) => set({ error: e }),
  updateBalance: (accountId, info) =>
    set((s) => ({ balances: { ...s.balances, [accountId]: info } })),
  setAccounts: (accounts) => set({ accounts }),
  setNetworkInfo: (info) => set(info),
  setWalletInfo: (info) => set(info),
  setWalletList: (w) => set({ walletList: w }),
  setApiAvailable: (v) => set({ apiAvailable: v }),
  setPlanId: (planId) => set({ planId }),
  triggerHistoryRefresh: () => set((s) => ({ historyRefreshKey: s.historyRefreshKey + 1 })),
  triggerBalanceRefresh: () => set((s) => ({ balanceRefreshKey: s.balanceRefreshKey + 1 })),
  resetToLanding: () => set({
    view: 'landing',
    migrationGate: 'idle',
    migrationMessage: null,
    authToken: null,
    sessionToken: null,
    isAuthenticated: false,
    selectedWallet: null,
    activeWalletPath: null,
    walletInstanceToken: null,
      walletName: '',
    walletLoaded: false,
    accounts: [],
    activeAccountId: null,
    balances: {},
    activeTab: 'history',
    planId: null,
    historyRefreshKey: 0,
    balanceRefreshKey: 0,
    error: null,
  }),
}));