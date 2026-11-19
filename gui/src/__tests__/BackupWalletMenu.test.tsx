import { beforeEach, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MenuBar } from '../components/MenuBar';
import { useStore } from '../store';

const mock = vi.hoisted(() => ({ backup: vi.fn() }));
vi.mock('../api', () => ({ api: { backupWallet: mock.backup } }));
beforeEach(() => { vi.resetAllMocks(); useStore.getState().resetToLanding(); useStore.setState({ activeWalletPath: '/wallet', walletInstanceToken: 'instance-a', walletName: 'synthetic' }); });
function openBackup() {
  fireEvent.click(screen.getByRole('button', { name: 'Wallet' }));
  fireEvent.click(screen.getByRole('button', { name: 'Backup Wallet…' }));
}
function fill(path = '/data/backup.sqlite', code = '') {
  fireEvent.change(screen.getByPlaceholderText('/path/to/wallet_backup.sqlite'), { target: { value: path } });
  fireEvent.change(screen.getByPlaceholderText('Wallet password'), { target: { value: 'pw-test' } });
  if (code) fireEvent.change(screen.getByPlaceholderText('TOTP code (if enabled)'), { target: { value: code } });
}
it('opens from the wallet menu and sends a password without a TOTP code', async () => {
  mock.backup.mockResolvedValue('/data/backup.sqlite');
  render(<MenuBar />); openBackup(); fill();
  fireEvent.click(screen.getByRole('button', { name: 'Backup' }));
  expect(await screen.findByRole('status')).toHaveTextContent('Wallet backed up to: /data/backup.sqlite');
  expect(mock.backup).toHaveBeenCalledWith('/data/backup.sqlite', 'pw-test', undefined, 'instance-a');
  expect(screen.getByPlaceholderText('Wallet password')).toHaveValue('');
  expect(screen.getByRole('button', { name: 'Backup' })).toBeDisabled();
});
it('allows a known authentication error to be corrected and submits the TOTP code', async () => {
  mock.backup.mockRejectedValueOnce('invalid TOTP code').mockResolvedValueOnce('/data/backup.sqlite');
  render(<MenuBar />); openBackup(); fill('/data/backup.sqlite', '111111');
  fireEvent.click(screen.getByRole('button', { name: 'Backup' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('invalid TOTP code');
  expect(screen.getByPlaceholderText('Wallet password')).toHaveValue('');
  fill('/data/backup.sqlite', '222222');
  fireEvent.click(screen.getByRole('button', { name: 'Backup' }));
  await screen.findByRole('status');
  expect(mock.backup).toHaveBeenNthCalledWith(2, '/data/backup.sqlite', 'pw-test', '222222', 'instance-a');
});
it.each(['destination already exists', 'transport failed'])('treats %s as an unknown outcome and blocks retry', async error => {
  mock.backup.mockRejectedValue(error);
  render(<MenuBar />); openBackup(); fill();
  fireEvent.click(screen.getByRole('button', { name: 'Backup' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('destination may already exist');
  expect(screen.getByRole('button', { name: 'Backup' })).toBeDisabled();
  expect(screen.getByPlaceholderText('Wallet password')).toHaveValue('');
  expect(mock.backup).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Close' }));
  openBackup();
  expect(screen.getByPlaceholderText('Wallet password')).toHaveValue('');
  expect(screen.getByPlaceholderText('/path/to/wallet_backup.sqlite')).toHaveValue('');
});
it('blocks closing and duplicate submission while backup is pending', async () => {
  let resolve!: (path: string) => void;
  mock.backup.mockReturnValue(new Promise<string>(r => { resolve = r; }));
  const { container } = render(<MenuBar />); openBackup(); fill();
  fireEvent.click(screen.getByRole('button', { name: 'Backup' }));
  expect(screen.getByRole('button', { name: 'Close' })).toBeDisabled();
  expect(screen.getByRole('button', { name: '×' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Close' }));
  fireEvent.click(screen.getByRole('button', { name: '×' }));
  fireEvent.click(container.querySelector('.fixed.inset-0.z-50')!);
  fireEvent.keyDown(document, { key: 'Escape' });
  fireEvent.click(screen.getByRole('button', { name: 'Backing up…' }));
  expect(mock.backup).toHaveBeenCalledTimes(1);
  expect(screen.getByText('Backup Wallet')).toBeInTheDocument();
  resolve('/data/backup.sqlite');
  await waitFor(() => expect(screen.getByRole('status')).toBeInTheDocument());
});
it('does not claim success for an invalid response', async () => {
  mock.backup.mockResolvedValue('');
  render(<MenuBar />); openBackup(); fill();
  fireEvent.click(screen.getByRole('button', { name: 'Backup' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('outcome is unknown');
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
});
it('blocks backup and clears credentials after the active wallet changes', async () => {
  const { act } = await import('@testing-library/react');
  render(<MenuBar />); openBackup(); fill('/data/backup.sqlite', '123456');
  act(() => useStore.getState().setActiveWalletPath('/other-wallet'));
  await screen.findByText(/Wallet changed/);
  expect(screen.getByPlaceholderText('Wallet password')).toHaveValue('');
  expect(screen.getByPlaceholderText('TOTP code (if enabled)')).toHaveValue('');
  expect(screen.getByRole('button', { name: 'Backup' })).toBeDisabled();
  expect(mock.backup).not.toHaveBeenCalled();
});
it('does not claim success when the wallet changes during a pending backup', async () => {
  const { act } = await import('@testing-library/react');
  let resolve!: (path: string) => void;
  mock.backup.mockReturnValue(new Promise<string>(r => { resolve = r; }));
  render(<MenuBar />); openBackup(); fill();
  fireEvent.click(screen.getByRole('button', { name: 'Backup' }));
  act(() => useStore.getState().setActiveWalletPath('/other-wallet'));
  await act(async () => resolve('/data/backup.sqlite'));
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  expect(screen.getByText(/Backup outcome is unknown/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Backup' })).toBeDisabled();
});
it('keeps a pending A to B to A wallet switch uncertain', async () => {
  const { act } = await import('@testing-library/react');
  let resolve!: (path: string) => void;
  mock.backup.mockReturnValue(new Promise<string>(r => { resolve = r; }));
  render(<MenuBar />); openBackup(); fill();
  fireEvent.click(screen.getByRole('button', { name: 'Backup' }));
  act(() => { useStore.getState().setActiveWalletPath('/other-wallet'); useStore.getState().setActiveWalletPath('/wallet'); });
  await act(async () => resolve('/data/backup.sqlite'));
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  expect(screen.getByText(/Backup outcome is unknown/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Backup' })).toBeDisabled();
});

it('fails closed when the current instance token is missing', () => {
  useStore.setState({ walletInstanceToken: null });
  render(<MenuBar />);
  fireEvent.click(screen.getByRole('button', { name: 'Wallet' }));
  expect(screen.getByRole('button', { name: 'Backup Wallet…' })).toBeDisabled();
  expect(mock.backup).not.toHaveBeenCalled();
});
it('invalidates the dialog for a new instance at the same path', async () => {
  const { act } = await import('@testing-library/react');
  let resolve!: (path: string) => void;
  mock.backup.mockReturnValue(new Promise<string>(r => { resolve = r; }));
  render(<MenuBar />); openBackup(); fill();
  fireEvent.click(screen.getByRole('button', { name: 'Backup' }));
  act(() => useStore.getState().setActiveWalletIdentity('/wallet', 'instance-b'));
  await act(async () => resolve('/data/backup.sqlite'));
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  expect(screen.getByText(/Backup outcome is unknown/)).toBeInTheDocument();
});
