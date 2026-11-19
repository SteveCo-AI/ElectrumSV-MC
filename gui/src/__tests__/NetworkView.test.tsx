import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { NetworkView } from '../views/NetworkView';
import { useStore } from '../store';

vi.mock('../api', () => ({ api: {
  getNetworkInfo: vi.fn(), getServers: vi.fn(), listNetworks: vi.fn(), getHeaderStoreInfo: vi.fn(), syncHeaders: vi.fn(), syncWallet: vi.fn(), scanAddressRange: vi.fn(),
} }));
import { api } from '../api';

beforeEach(() => {
  vi.resetAllMocks();
  useStore.getState().resetToLanding();
  vi.mocked(api.getNetworkInfo).mockResolvedValue({ connected: false } as any);
  vi.mocked(api.getServers).mockResolvedValue([]);
  vi.mocked(api.listNetworks).mockResolvedValue([]);
  vi.mocked(api.getHeaderStoreInfo).mockResolvedValue({ header_count: 3, tip_height: 2 });
});

describe('wallet synchronization', () => {
  beforeEach(() => {
    useStore.setState({ activeWalletPath: '/wallet', walletInstanceToken: 'instance', activeAccountId: 3 });
    vi.mocked(api.getNetworkInfo).mockResolvedValue({ connected: true } as any);
  });

  it('binds sync to the wallet session and refreshes wallet data on success', async () => {
    vi.mocked(api.syncWallet).mockResolvedValue({ synced: true, account_id: 3, server_host: 'test-server', message: 'Sync complete' });
    render(<NetworkView />);
    await screen.findByText(/Connected —/);
    fireEvent.click(screen.getByText('Sync Wallet'));
    await screen.findByText('Sync complete');
    expect(api.syncWallet).toHaveBeenCalledWith(3, 'instance');
    expect(useStore.getState().historyRefreshKey).toBe(1);
    expect(useStore.getState().balanceRefreshKey).toBe(1);
  });

  it('ignores a result from an earlier wallet instance', async () => {
    let finish!: (value: any) => void;
    vi.mocked(api.syncWallet).mockReturnValue(new Promise(resolve => { finish = resolve; }));
    render(<NetworkView />);
    await screen.findByText(/Connected —/);
    fireEvent.click(screen.getByText('Sync Wallet'));
    act(() => useStore.setState({ walletInstanceToken: 'new-instance' }));
    await act(async () => finish({ synced: true, account_id: 3, server_host: 'test-server', message: 'Sync complete' }));
    expect(screen.queryByText('Sync complete')).not.toBeInTheDocument();
    expect(useStore.getState().historyRefreshKey).toBe(0);
    expect(useStore.getState().balanceRefreshKey).toBe(0);
  });

  it('reports the actual error without keeping an earlier success', async () => {
    vi.mocked(api.syncWallet).mockResolvedValueOnce({ synced: true, account_id: 3, server_host: 'test-server', message: 'Sync complete' })
      .mockRejectedValueOnce('wallet changed');
    render(<NetworkView />);
    await screen.findByText(/Connected —/);
    fireEvent.click(screen.getByText('Sync Wallet'));
    await screen.findByText('Sync complete');
    fireEvent.click(screen.getByText('Sync Wallet'));
    await screen.findByText('wallet changed');
    expect(screen.queryByText('Sync complete')).not.toBeInTheDocument();
    expect(useStore.getState().historyRefreshKey).toBe(1);
  });
});

describe('explicit address discovery', () => {
  beforeEach(() => {
    useStore.setState({ activeWalletPath: '/wallet', walletInstanceToken: 'instance', activeAccountId: 3 });
    vi.mocked(api.getNetworkInfo).mockResolvedValue({ connected: true } as any);
  });

  it('requires an explicit scan and refreshes the active wallet on success', async () => {
    vi.mocked(api.scanAddressRange).mockResolvedValue({ start_index: 0, end_index_exclusive: 26, new_keys: 2, server_host: 'test-server' });
    render(<NetworkView />);
    await screen.findByText(/Connected —/);
    expect(api.scanAddressRange).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText(/End index/), { target: { value: '26' } });
    fireEvent.click(screen.getByText('Scan addresses'));
    await screen.findByText(/2 new keys found/);
    expect(api.scanAddressRange).toHaveBeenCalledWith(3, 'instance', 26);
    expect(useStore.getState().historyRefreshKey).toBe(1);
    expect(useStore.getState().balanceRefreshKey).toBe(1);
    expect(screen.getByText(/server sees the queried address script hashes/)).toBeInTheDocument();
  });

  it('rejects invalid ranges and ignores an old wallet result', async () => {
    let finish!: (value: any) => void;
    vi.mocked(api.scanAddressRange).mockReturnValue(new Promise(resolve => { finish = resolve; }));
    render(<NetworkView />);
    await screen.findByText(/Connected —/);
    fireEvent.change(screen.getByLabelText(/End index/), { target: { value: '1001' } });
    fireEvent.click(screen.getByText('Scan addresses'));
    expect(screen.getByText(/whole number from 1 to 1000/)).toBeInTheDocument();
    expect(api.scanAddressRange).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText(/End index/), { target: { value: '26' } });
    fireEvent.click(screen.getByText('Scan addresses'));
    act(() => useStore.setState({ walletInstanceToken: 'new-instance' }));
    await act(async () => finish({ start_index: 0, end_index_exclusive: 26, new_keys: 2, server_host: 'test-server' }));
    expect(screen.queryByText(/2 new keys found/)).not.toBeInTheDocument();
    expect(useStore.getState().historyRefreshKey).toBe(0);
    expect(useStore.getState().balanceRefreshKey).toBe(0);
  });

  it('reports scan failures without claiming that saving was impossible', async () => {
    vi.mocked(api.scanAddressRange).mockRejectedValue('scan conflict');
    render(<NetworkView />);
    await screen.findByText(/Connected —/);
    fireEvent.click(screen.getByText('Scan addresses'));
    await screen.findByText(/scan conflict.*outcome may be unknown/);
    expect(useStore.getState().historyRefreshKey).toBe(0);
    expect(useStore.getState().balanceRefreshKey).toBe(0);
  });
});

describe('header synchronization status', () => {
  it('shows partial progress and continues only on explicit action', async () => {
    vi.mocked(api.syncHeaders).mockResolvedValueOnce({ synced: 2, new_tip: 2, server_tip: 5, message: 'partial progress' })
      .mockResolvedValueOnce({ synced: 3, new_tip: 5, server_tip: 5, message: 'reached tip' });
    render(<NetworkView />);
    await screen.findByText(/Headers: 3.*Stored height: 2/);
    fireEvent.click(screen.getByText('Sync Headers'));
    await screen.findByText(/Stored header tip: 2; server-reported tip: 5/);
    expect(screen.getByText(/Partial progress/)).toBeInTheDocument();
    expect(screen.getByText(/does not establish independent chain consensus/)).toBeInTheDocument();
    expect(api.syncHeaders).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByText('Continue Header Sync'));
    await screen.findByText(/Stored header tip: 5; server-reported tip: 5/);
    expect(screen.getByText(/reached the server-reported height/)).toBeInTheDocument();
    expect(api.syncHeaders).toHaveBeenCalledTimes(2);
  });

  it.each([null, {}, {synced: 1, new_tip: 4, server_tip: 3, message: 'bad'}, {synced: -1, new_tip: 2, server_tip: 3, message: 'bad'}, {synced: 0, new_tip: 2, server_tip: 3, message: 'bad'}, {synced: 0, new_tip: 2, server_tip: 3}])('rejects malformed response %#', async (response) => {
    vi.mocked(api.syncHeaders).mockResolvedValue(response as any);
    render(<NetworkView />);
    fireEvent.click(screen.getByText('Sync Headers'));
    await waitFor(() => expect(screen.getByText('Invalid header sync response')).toBeInTheDocument());
    expect(screen.queryByText(/Partial progress/)).not.toBeInTheDocument();
    expect(screen.queryByText(/reached the server-reported height/)).not.toBeInTheDocument();
  });
});
