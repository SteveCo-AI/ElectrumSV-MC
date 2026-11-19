import { beforeEach, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { DeleteWalletDialog } from '../components/WalletDialogs';

const mocks = vi.hoisted(() => ({ setError: vi.fn(), deleteWallet: vi.fn() }));
vi.mock('../store', () => ({ useStore: () => ({ setError: mocks.setError }) }));
vi.mock('../api', () => ({ api: { deleteWallet: mocks.deleteWallet } }));

beforeEach(() => vi.clearAllMocks());

it('keeps the dialog and wallet on failed authentication, then sends the corrected code', async () => {
  mocks.deleteWallet.mockRejectedValueOnce('invalid TOTP code').mockResolvedValueOnce(undefined);
  const onDeleted = vi.fn();
  const onClose = vi.fn();
  const { container } = render(<DeleteWalletDialog open walletPath="/test/wallet" walletName="test-wallet" onDeleted={onDeleted} onClose={onClose} />);
  fireEvent.change(screen.getByPlaceholderText('test-wallet'), { target: { value: 'test-wallet' } });
  fireEvent.change(container.querySelector('input[type=password]')!, { target: { value: 'test-password' } });
  fireEvent.change(screen.getByPlaceholderText('TOTP code (if enabled)'), { target: { value: '111111' } });
  fireEvent.click(screen.getByText('Delete Permanently'));
  await waitFor(() => expect(mocks.setError).toHaveBeenCalledWith('invalid TOTP code'));
  expect(onDeleted).not.toHaveBeenCalled();
  expect(onClose).not.toHaveBeenCalled();
  expect(screen.getByText('Delete Wallet')).toBeInTheDocument();
  fireEvent.change(screen.getByPlaceholderText('TOTP code (if enabled)'), { target: { value: '222222' } });
  fireEvent.click(screen.getByText('Delete Permanently'));
  await waitFor(() => expect(onDeleted).toHaveBeenCalledTimes(1));
  expect(mocks.deleteWallet).toHaveBeenNthCalledWith(1, '/test/wallet', 'test-password', '111111');
  expect(mocks.deleteWallet).toHaveBeenNthCalledWith(2, '/test/wallet', 'test-password', '222222');
  expect(onClose).toHaveBeenCalledTimes(1);
});

it('prevents closing the dialog until a pending deletion has completed', async () => {
  let finish!: () => void;
  mocks.deleteWallet.mockReturnValueOnce(new Promise<void>(resolve => { finish = resolve; }));
  const onDeleted = vi.fn();
  const onClose = vi.fn();
  const { container } = render(<DeleteWalletDialog open walletPath="/test/wallet" walletName="test-wallet" onDeleted={onDeleted} onClose={onClose} />);
  fireEvent.change(screen.getByPlaceholderText('test-wallet'), { target: { value: 'test-wallet' } });
  fireEvent.change(container.querySelector('input[type=password]')!, { target: { value: 'test-password' } });
  fireEvent.click(screen.getByText('Delete Permanently'));
  expect(screen.getByText('Cancel')).toBeDisabled();
  expect(screen.getByText('×')).toBeDisabled();
  fireEvent.click(screen.getByText('Cancel'));
  fireEvent.click(screen.getByText('×'));
  fireEvent.click(container.firstElementChild!);
  fireEvent.keyDown(document, { key: 'Escape', code: 'Escape' });
  expect(onClose).not.toHaveBeenCalled();
  expect(onDeleted).not.toHaveBeenCalled();
  expect(mocks.deleteWallet).toHaveBeenCalledTimes(1);
  finish();
  await waitFor(() => expect(onDeleted).toHaveBeenCalledTimes(1));
  expect(onClose).toHaveBeenCalledTimes(1);
});
