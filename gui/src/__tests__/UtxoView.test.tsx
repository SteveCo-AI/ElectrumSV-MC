import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { UtxoView } from '../views/UtxoView';
import { api } from '../api';
import { useStore } from '../store';

vi.mock('../api', () => ({ api: { getUtxos: vi.fn() } }));
vi.mock('../store', () => ({ useStore: vi.fn() }));
const getUtxos = vi.mocked(api.getUtxos);
const store = vi.mocked(useStore);
const output = { tx_hash: 'ab'.repeat(32), tx_index: 4, value: 100, keyinstance_id: 1, is_coinbase: false, script_pubkey: '' };
function context(path = '/a', token = 'one', account: number | null = 1) {
  store.mockReturnValue({ activeWalletPath: path, walletInstanceToken: token, activeAccountId: account } as ReturnType<typeof useStore>);
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}
beforeEach(() => { vi.resetAllMocks(); context(); getUtxos.mockResolvedValue([]); });
afterEach(cleanup);

describe('UTXO session and response handling', () => {
  it('reports failure rather than an empty wallet and supports retry', async () => {
    getUtxos.mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce([]);
    render(<UtxoView />);
    expect(await screen.findByText(/UTXOs unavailable/)).toBeTruthy();
    expect(screen.queryByText('No unspent outputs.')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Retry UTXOs' }));
    expect(await screen.findByText('No unspent outputs.')).toBeTruthy();
  });
  it('discards old wallet results with the same account', async () => {
    const old = deferred<typeof output[]>(); const current = deferred<typeof output[]>();
    getUtxos.mockReturnValueOnce(old.promise).mockReturnValueOnce(current.promise);
    const view = render(<UtxoView />);
    context('/b'); view.rerender(<UtxoView />);
    await act(async () => current.resolve([]));
    expect(await screen.findByText('No unspent outputs.')).toBeTruthy();
    await act(async () => old.resolve([output]));
    expect(screen.queryByText('100 sat')).toBeNull();
  });
  it('rejects duplicate outpoints irrespective of hash case', async () => {
    getUtxos.mockResolvedValueOnce([output, { ...output, tx_hash: output.tx_hash.toUpperCase() }]);
    render(<UtxoView />);
    expect(await screen.findByText(/UTXOs unavailable/)).toBeTruthy();
  });
  it('accepts a legacy empty script and reports an unknown script type', async () => {
    getUtxos.mockResolvedValueOnce([output]); render(<UtxoView />);
    expect(await screen.findByText('100 sat')).toBeTruthy();
    expect(screen.getByText('unknown')).toBeTruthy();
    expect(screen.queryByText('p2pkh')).toBeNull();
  });
  it('shows idle without an account or wallet identity', () => {
    context('/a', 'one', null); const view = render(<UtxoView />);
    expect(screen.getByText(/Select an active wallet/)).toBeTruthy();
    expect(getUtxos).not.toHaveBeenCalled();
    context('/a', '', 1); view.rerender(<UtxoView />);
    expect(screen.getByText(/Select an active wallet/)).toBeTruthy();
    expect(getUtxos).not.toHaveBeenCalled();
  });
  it('hides old data immediately after a wallet or instance change', async () => {
    const next = deferred<typeof output[]>();
    getUtxos.mockResolvedValueOnce([output]).mockReturnValueOnce(next.promise);
    const view = render(<UtxoView />); await screen.findByText('100 sat');
    context('/a', 'two'); view.rerender(<UtxoView />);
    expect(screen.queryByText('100 sat')).toBeNull();
    expect(screen.getByText('Loading UTXOs…')).toBeTruthy();
    await act(async () => next.resolve([]));
    expect(screen.getByText('No unspent outputs.')).toBeTruthy();
  });
  it('discards a pending response across close and reopen at the same path with a new token', async () => {
    const old = deferred<typeof output[]>(); const reopened = deferred<typeof output[]>();
    getUtxos.mockReturnValueOnce(old.promise).mockReturnValueOnce(reopened.promise);
    const view = render(<UtxoView />);
    context('', '', null); view.rerender(<UtxoView />);
    expect(screen.getByText(/Select an active wallet/)).toBeTruthy();
    context('/a', 'two'); view.rerender(<UtxoView />);
    await act(async () => old.resolve([output]));
    expect(screen.getByText('Loading UTXOs…')).toBeTruthy();
    await act(async () => reopened.resolve([]));
    expect(screen.getByText('No unspent outputs.')).toBeTruthy();
  });
  it('ignores a late failure and completion while the replacement request is pending', async () => {
    const old = deferred<typeof output[]>(); const next = deferred<typeof output[]>();
    getUtxos.mockReturnValueOnce(old.promise).mockReturnValueOnce(next.promise);
    const view = render(<UtxoView />); context('/b'); view.rerender(<UtxoView />);
    await act(async () => old.reject(new Error('late')));
    expect(screen.getByText('Loading UTXOs…')).toBeTruthy();
    expect(screen.queryByText(/UTXOs unavailable/)).toBeNull();
    await act(async () => next.resolve([output]));
    expect(screen.getByText('100 sat')).toBeTruthy();
  });
  it('ignores both late success and failure after unmount', async () => {
    const old = deferred<typeof output[]>(); getUtxos.mockReturnValueOnce(old.promise);
    const view = render(<UtxoView />); view.unmount();
    await act(async () => old.resolve([output]));
    const next = deferred<typeof output[]>(); getUtxos.mockReturnValueOnce(next.promise);
    const second = render(<UtxoView />); second.unmount();
    await act(async () => next.reject(new Error('late')));
    expect(screen.queryByText('100 sat')).toBeNull();
    expect(screen.queryByText(/UTXOs unavailable/)).toBeNull();
  });
  it('does not redisplay a prior result on A → B → A before a new response', async () => {
    const pending = deferred<typeof output[]>();
    getUtxos.mockResolvedValueOnce([output]).mockReturnValueOnce(pending.promise).mockReturnValueOnce(pending.promise);
    const view = render(<UtxoView />); await screen.findByText('100 sat');
    context('/b'); view.rerender(<UtxoView />);
    context('/a'); view.rerender(<UtxoView />);
    expect(screen.queryByText('100 sat')).toBeNull();
    expect(screen.getByText('Loading UTXOs…')).toBeTruthy();
  });
  it.each([
    null, {}, [null], [{ ...output, tx_hash: 'short' }], [{ ...output, tx_index: -1 }],
    [{ ...output, tx_index: 0x100000000 }], [{ ...output, tx_index: 1.5 }],
    [{ ...output, value: -1 }], [{ ...output, value: Number.MAX_SAFE_INTEGER + 1 }],
    [{ ...output, keyinstance_id: null }], [{ ...output, keyinstance_id: -1 }],
    [{ ...output, is_coinbase: 0 }], [{ ...output, script_pubkey: 'a' }],
    [{ ...output, script_pubkey: 'xx' }],
    [{ ...output, value: Number.MAX_SAFE_INTEGER }, { ...output, tx_index: 5, value: 1 }],
  ])('rejects malformed or unsafe response %#', async value => {
    getUtxos.mockResolvedValueOnce(value as any); render(<UtxoView />);
    expect(await screen.findByText(/UTXOs unavailable/)).toBeTruthy();
    expect(screen.queryByText('No unspent outputs.')).toBeNull();
  });
  it('accepts safe boundary values and a valid script', async () => {
    getUtxos.mockResolvedValueOnce([{ ...output, tx_index: 0xffffffff, value: Number.MAX_SAFE_INTEGER, keyinstance_id: Number.MAX_SAFE_INTEGER, is_coinbase: true, script_pubkey: '00aF' }]);
    render(<UtxoView />);
    expect(await screen.findByText('coinbase')).toBeTruthy();
    expect(screen.getByText('4294967295')).toBeTruthy();
  });

});
