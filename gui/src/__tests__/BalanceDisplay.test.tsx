import { beforeEach, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import App from '../App';
import { useStore } from '../store';
vi.mock('../api', () => ({ api: {
  getNetworkInfo: vi.fn().mockResolvedValue({}), getWalletInfo: vi.fn().mockResolvedValue({}),
  getAccounts: vi.fn().mockResolvedValue([{ account_id: 1, account_name: 'Account' }]),
  getBalance: vi.fn().mockRejectedValue(new Error('offline')), satoshisToFiat: vi.fn().mockResolvedValue(1),
} }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn().mockResolvedValue(() => {}) }));
vi.mock('../views/HistoryView', () => ({ HistoryView: () => <div>History</div> }));
vi.mock('../components/MenuBar', () => ({ MenuBar: () => null }));
vi.mock('../components/StatusBar', () => ({ StatusBar: () => null }));
beforeEach(() => { vi.clearAllMocks(); useStore.getState().resetToLanding(); useStore.setState({ view: 'main', isAuthenticated: true, activeWalletPath: '/wallet-a' }); });
it('does not invent a zero balance after a request fails', async () => {
  render(<App />);
  expect(await screen.findByText('Balance unavailable')).toBeInTheDocument();
  expect(screen.queryByText('0 sat')).not.toBeInTheDocument();
});

it('retries explicitly and renders a real zero balance', async () => {
  const { api } = await import('../api');
  vi.mocked(api.getBalance).mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce({ total: 0, confirmed: 0, unconfirmed: 0, reserved: 0, available: 0 });
  const { fireEvent } = await import('@testing-library/react');
  render(<App />);
  fireEvent.click(await screen.findByText('Retry balance'));
  expect((await screen.findAllByText('0 sat')).length).toBeGreaterThan(0);
});

it('ignores an old wallet balance response with the same account id', async () => {
  const { api } = await import('../api');
  let resolveOld!: (value: any) => void;
  vi.mocked(api.getBalance).mockReturnValueOnce(new Promise(resolve => { resolveOld = resolve; })).mockResolvedValueOnce({ total: 7, confirmed: 7, unconfirmed: 0 });
  render(<App />);
  await vi.waitFor(() => expect(resolveOld).toBeDefined());
  act(() => useStore.getState().setActiveWalletPath('/wallet-b'));
  expect(await screen.findByText('7 sat')).toBeInTheDocument();
  await act(async () => resolveOld({ total: 99, confirmed: 99, unconfirmed: 0 }));
  await vi.waitFor(() => expect(screen.queryByText('99 sat')).not.toBeInTheDocument());
});

 it('rejects incomplete balances rather than fabricating zeros', async () => {
  const { api } = await import('../api');
  vi.mocked(api.getBalance).mockResolvedValueOnce({ total: 10, confirmed: 10 } as any);
  render(<App />);
  expect(await screen.findByText('Balance unavailable')).toBeInTheDocument();
  expect(screen.queryByText('10 sat')).not.toBeInTheDocument();
});

it('rejects duplicate account identifiers instead of double counting', async () => {
  const { api } = await import('../api');
  vi.mocked(api.getAccounts).mockResolvedValueOnce([{ account_id: 1 }, { account_id: 1 }] as any);
  render(<App />);
  expect(await screen.findByText('Balance unavailable')).toBeInTheDocument();
  expect(api.getBalance).not.toHaveBeenCalled();
});

it('ignores the old instance response after reopening the same wallet path', async () => {
  const { api } = await import('../api');
  let resolveOld!: (value: any) => void;
  vi.mocked(api.getBalance).mockReturnValueOnce(new Promise(resolve => { resolveOld = resolve; })).mockResolvedValueOnce({ total: 7, confirmed: 7, unconfirmed: 0 });
  useStore.setState({ walletInstanceToken: 'old-instance' });
  render(<App />);
  await vi.waitFor(() => expect(resolveOld).toBeDefined());
  act(() => useStore.getState().setActiveWalletIdentity('/wallet-a', 'new-instance'));
  expect(await screen.findByText('7 sat')).toBeInTheDocument();
  await act(async () => resolveOld({ total: 99, confirmed: 99, unconfirmed: 0 }));
  expect(screen.queryByText('99 sat')).not.toBeInTheDocument();
});
