import { beforeEach, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { LoginScreen } from '../views/LoginScreen';

vi.mock('../store', () => {
  const state = { selectedWallet: null, setAuthenticated: vi.fn(), setWalletInfo: vi.fn(), setAccounts: vi.fn(), setActiveAccount: vi.fn(), setView: vi.fn(), setActiveWalletIdentity: vi.fn(), requireWalletReopen: vi.fn() };
  return { useStore: Object.assign(() => state, { getState: () => state }) };
});
vi.mock('../api', () => ({ isDefiniteTotpAuthFailure: () => false, api: { restoreBip39Wallet: vi.fn(), getWalletInfo: vi.fn(), getAccounts: vi.fn() } }));
import { api } from '../api';
import { useStore } from '../store';

beforeEach(() => vi.resetAllMocks());

it('passes the BIP39 passphrase exactly and clears it after failure', async () => {
  const passphrase = '  Te\u0301st  ';
  expect(Array.from(passphrase, char => char.codePointAt(0))).toEqual([32, 32, 84, 101, 0x301, 115, 116, 32, 32]);
  vi.mocked(api.restoreBip39Wallet).mockRejectedValueOnce(new Error('restore failed'));
  render(<LoginScreen />);
  fireEvent.click(screen.getByText('Restore wallet'));
  fireEvent.click(screen.getByText('Mnemonic Seed'));
  fireEvent.change(screen.getByPlaceholderText('restored_wallet'), { target: { value: 'example' } });
  fireEvent.change(screen.getByPlaceholderText('Enter your seed words...'), { target: { value: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' } });
  fireEvent.change(screen.getByLabelText('BIP39 passphrase (optional)'), { target: { value: passphrase } });
  fireEvent.change(screen.getByLabelText('New wallet password'), { target: { value: 'wallet-password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Restore' }));
  await waitFor(() => expect(api.restoreBip39Wallet).toHaveBeenCalledWith('example', 'wallet-password', 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', passphrase, 'standard_bip39'));
  await screen.findByText('restore failed');
  expect(screen.getByLabelText('BIP39 passphrase (optional)')).toHaveValue('');
});

it('clears the optional passphrase when leaving the restore form', () => {
  const view = render(<LoginScreen />);
  fireEvent.click(screen.getByText('Restore wallet'));
  fireEvent.click(screen.getByText('Mnemonic Seed'));
  expect(screen.getByLabelText('Standard BIP39 (recommended)')).toBeChecked();
  fireEvent.click(screen.getByLabelText('Historical MC Unicode derivation'));
  fireEvent.change(screen.getByLabelText('BIP39 passphrase (optional)'), { target: { value: 'sensitive-test-value' } });
  fireEvent.click(screen.getByText(/←/));
  fireEvent.click(screen.getByText('Mnemonic Seed'));
  expect(screen.getByLabelText('BIP39 passphrase (optional)')).toHaveValue('');
  expect(screen.getByLabelText('Standard BIP39 (recommended)')).toBeChecked();
  view.unmount();
});

it('passes an explicit historical derivation choice without changing the passphrase', async () => {
  vi.mocked(api.restoreBip39Wallet).mockRejectedValueOnce(new Error('test'));
  render(<LoginScreen />);
  fireEvent.click(screen.getByText('Restore wallet'));
  fireEvent.click(screen.getByText('Mnemonic Seed'));
  fireEvent.click(screen.getByLabelText('Historical MC Unicode derivation'));
  fireEvent.change(screen.getByPlaceholderText('restored_wallet'), { target: { value: 'example' } });
  fireEvent.change(screen.getByPlaceholderText('Enter your seed words...'), { target: { value: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' } });
  fireEvent.change(screen.getByLabelText('BIP39 passphrase (optional)'), { target: { value: ' café ' } });
  fireEvent.change(screen.getByLabelText('New wallet password'), { target: { value: 'wallet-password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Restore' }));
  await waitFor(() => expect(api.restoreBip39Wallet).toHaveBeenCalledWith('example', 'wallet-password', expect.any(String), ' café ', 'historical_mc'));
});

it('uses an empty passphrase by default and does not retain it on remount', async () => {
  vi.mocked(api.restoreBip39Wallet).mockResolvedValue({ wallet_path: '/test/example.sqlite', wallet_instance_token: 'instance' });
  vi.mocked(api.getWalletInfo).mockResolvedValue({ wallet_name: 'example' });
  vi.mocked(api.getAccounts).mockResolvedValue([]);
  const view = render(<LoginScreen />);
  fireEvent.click(screen.getByText('Restore wallet'));
  fireEvent.click(screen.getByText('Mnemonic Seed'));
  expect(screen.getByLabelText('BIP39 passphrase (optional)')).toHaveValue('');
  fireEvent.change(screen.getByPlaceholderText('restored_wallet'), { target: { value: 'example' } });
  fireEvent.change(screen.getByPlaceholderText('Enter your seed words...'), { target: { value: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' } });
  fireEvent.change(screen.getByLabelText('New wallet password'), { target: { value: 'wallet-password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Restore' }));
  await waitFor(() => expect(api.restoreBip39Wallet).toHaveBeenCalledWith('example', 'wallet-password', expect.any(String), '', 'standard_bip39'));
  view.unmount();
  render(<LoginScreen />);
  fireEvent.click(screen.getByText('Restore wallet'));
  fireEvent.click(screen.getByText('Mnemonic Seed'));
  expect(screen.getByLabelText('BIP39 passphrase (optional)')).toHaveValue('');
});

it('locks the form and ignores a delayed result after unmount', async () => {
  let finish!: (result: any) => void;
  vi.mocked(api.restoreBip39Wallet).mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const view = render(<LoginScreen />);
  fireEvent.click(screen.getByText('Restore wallet'));
  fireEvent.click(screen.getByText('Mnemonic Seed'));
  fireEvent.change(screen.getByPlaceholderText('restored_wallet'), { target: { value: 'example' } });
  fireEvent.change(screen.getByPlaceholderText('Enter your seed words...'), { target: { value: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' } });
  fireEvent.change(screen.getByLabelText('New wallet password'), { target: { value: 'wallet-password' } });
  const submit = screen.getByRole('button', { name: 'Restore' });
  fireEvent.click(submit);
  expect(screen.getByText('Cancel')).toBeDisabled();
  expect(screen.getByText(/←/)).toBeDisabled();
  expect(screen.getByPlaceholderText('restored_wallet')).toBeDisabled();
  expect(screen.getByLabelText('BIP39 passphrase (optional)')).toBeDisabled();
  expect(screen.getByLabelText('Historical MC Unicode derivation')).toBeDisabled();
  expect(screen.getByLabelText('New wallet password')).toBeDisabled();
  fireEvent.click(submit);
  expect(api.restoreBip39Wallet).toHaveBeenCalledTimes(1);
  view.unmount();
  await act(async () => finish({ wallet_path: '/test/example.sqlite', wallet_instance_token: 'instance' }));
  expect(useStore().setActiveWalletIdentity).not.toHaveBeenCalled();
  expect(useStore().setAuthenticated).not.toHaveBeenCalled();
  expect(api.getWalletInfo).not.toHaveBeenCalled();
});

it('does not publish a restored session if unmounted while accounts are loading', async () => {
  let finish!: (result: any[]) => void;
  vi.mocked(api.restoreBip39Wallet).mockResolvedValue({ wallet_path: '/test/example.sqlite', wallet_instance_token: 'instance' });
  vi.mocked(api.getWalletInfo).mockResolvedValue({ wallet_name: 'example' });
  vi.mocked(api.getAccounts).mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const view = render(<LoginScreen />);
  fireEvent.click(screen.getByText('Restore wallet'));
  fireEvent.click(screen.getByText('Mnemonic Seed'));
  fireEvent.change(screen.getByPlaceholderText('restored_wallet'), { target: { value: 'example' } });
  fireEvent.change(screen.getByPlaceholderText('Enter your seed words...'), { target: { value: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' } });
  fireEvent.change(screen.getByLabelText('New wallet password'), { target: { value: 'wallet-password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Restore' }));
  await waitFor(() => expect(api.getAccounts).toHaveBeenCalled());
  view.unmount();
  await act(async () => finish([]));
  expect(useStore().setActiveWalletIdentity).not.toHaveBeenCalled();
  expect(useStore().setWalletInfo).not.toHaveBeenCalled();
  expect(useStore().setAuthenticated).not.toHaveBeenCalled();
});
