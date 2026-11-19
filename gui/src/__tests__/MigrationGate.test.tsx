import { beforeEach, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import App from '../App';
const mocks = vi.hoisted(() => ({ state: { view: 'main', isAuthenticated: true, migrationGate: 'pending', migrationMessage: '', migrationVerificationPath: null as string | null, migrationExpectedFormat: null as 33 | 34 | null, migrationNeedsTotpCheck: false, activeWalletPath: '/test/wallet', clearMigrationVerification: vi.fn(), resetToLanding: vi.fn() }, status: vi.fn(), totp: vi.fn(), close: vi.fn() }));
vi.mock('../store', () => ({ useStore: () => mocks.state }));
vi.mock('../api', () => ({ api: { getWalletInfo: mocks.status, getTotpStatus: mocks.totp, closeWallet: mocks.close } }));
beforeEach(() => { vi.clearAllMocks(); mocks.state.migrationGate = 'pending'; mocks.state.migrationMessage = ''; mocks.state.migrationVerificationPath = null; mocks.state.migrationExpectedFormat = null; mocks.state.migrationNeedsTotpCheck = false; mocks.state.activeWalletPath = '/test/wallet'; });
it('blocks navigation while a migration is pending', () => {
  render(<App />);
  expect(screen.getByText('Migration in progress. Do not close the application.')).toBeInTheDocument();
  expect(screen.queryByText('Close wallet and return to wallet list')).not.toBeInTheDocument();
});
it('requires a known closed wallet or successful close before leaving an unknown outcome', async () => {
  mocks.state.migrationGate = 'reopen_unknown'; mocks.state.migrationMessage = 'Migration outcome is unknown.';
  mocks.status.mockResolvedValueOnce({}).mockResolvedValueOnce({ is_open: true });
  mocks.close.mockRejectedValueOnce(new Error('close failed')).mockResolvedValueOnce(undefined);
  render(<App />);
  fireEvent.click(screen.getByText('Close wallet and return to wallet list'));
  await screen.findByText('Wallet state unavailable');
  expect(mocks.state.resetToLanding).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText('Close wallet and return to wallet list'));
  await screen.findByText('close failed');
  expect(mocks.state.resetToLanding).not.toHaveBeenCalled();
  mocks.status.mockResolvedValueOnce({ is_open: true });
  fireEvent.click(screen.getByText('Close wallet and return to wallet list'));
  await waitFor(() => expect(mocks.state.resetToLanding).toHaveBeenCalledTimes(1));
});

it('automatically releases the same reopened wallet only after the expected format is checked', async () => {
  mocks.state.migrationGate = 'idle'; mocks.state.migrationVerificationPath = '/test/wallet'; mocks.state.migrationExpectedFormat = 34;
  mocks.status.mockResolvedValue({ is_open: true, is_unlocked: true, wallet_format: 34 });
  render(<App />);
  await waitFor(() => expect(mocks.state.clearMigrationVerification).toHaveBeenCalledWith(expect.stringContaining('format 34')));
  expect(screen.queryByText('Continue with this wallet')).not.toBeInTheDocument();
});
it('blocks mismatched or unknown format after reopening', async () => {
  mocks.state.migrationGate = 'idle'; mocks.state.migrationVerificationPath = '/test/wallet'; mocks.state.migrationExpectedFormat = 34;
  mocks.status.mockResolvedValue({ is_open: true, is_unlocked: true, wallet_format: 33 });
  render(<App />);
  await screen.findByText(/does not match the migration outcome/);
  expect(mocks.state.clearMigrationVerification).not.toHaveBeenCalled();
});
it('requires explicit choice to continue with a different wallet', async () => {
  mocks.state.migrationGate = 'idle'; mocks.state.migrationVerificationPath = '/test/wallet'; mocks.state.activeWalletPath = '/test/other';
  mocks.status.mockResolvedValue({ is_open: true, is_unlocked: true, wallet_format: 33 });
  render(<App />);
  fireEvent.click(await screen.findByText('Continue with this different wallet'));
  expect(mocks.state.clearMigrationVerification).toHaveBeenCalledWith(expect.stringContaining('different wallet'));
});

it('keeps an uncertain 2FA update blocked if reopened protection status is unknown', async () => {
  mocks.state.migrationGate = 'idle'; mocks.state.migrationVerificationPath = '/test/wallet'; mocks.state.migrationNeedsTotpCheck = true;
  mocks.status.mockResolvedValue({ is_open: true, is_unlocked: true, wallet_format: 33 });
  mocks.totp.mockResolvedValue({ enabled: null });
  render(<App />);
  await screen.findByText('2FA status is unknown. Close the wallet and check again.');
  expect(mocks.state.clearMigrationVerification).not.toHaveBeenCalled();
});
it('releases only after reopened wallet and known 2FA status are checked', async () => {
  mocks.state.migrationGate = 'idle'; mocks.state.migrationVerificationPath = '/test/wallet'; mocks.state.migrationNeedsTotpCheck = true;
  mocks.status.mockResolvedValue({ is_open: true, is_unlocked: true, wallet_format: 33 });
  mocks.totp.mockResolvedValue({ enabled: false });
  render(<App />);
  await waitFor(() => expect(mocks.state.clearMigrationVerification).toHaveBeenCalledWith(expect.stringContaining('2FA is disabled')));
});

it('does not clear an uncertain 2FA outcome when a different wallet is opened', async () => {
  mocks.state.migrationGate = 'idle'; mocks.state.migrationVerificationPath = '/test/wallet'; mocks.state.migrationNeedsTotpCheck = true; mocks.state.activeWalletPath = '/test/other';
  mocks.status.mockResolvedValue({ is_open: true, is_unlocked: true, wallet_format: 33 });
  mocks.totp.mockResolvedValue({ enabled: true });
  const view = render(<App />);
  await screen.findByText('A different wallet was opened. Reopen the original wallet to check its 2FA status.');
  expect(screen.queryByText('Continue with this different wallet')).not.toBeInTheDocument();
  expect(mocks.state.clearMigrationVerification).not.toHaveBeenCalled();
  mocks.state.activeWalletPath = '/test/wallet';
  mocks.totp.mockResolvedValue({ enabled: null });
  view.rerender(<App />);
  await screen.findByText('2FA status is unknown. Close the wallet and check again.');
  expect(mocks.state.clearMigrationVerification).not.toHaveBeenCalled();
  mocks.totp.mockResolvedValue({ enabled: true });
  view.unmount();
  render(<App />);
  await waitFor(() => expect(mocks.state.clearMigrationVerification).toHaveBeenCalledWith(expect.stringContaining('2FA is enabled')));
});
