import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, render, screen, fireEvent, waitFor } from '@testing-library/react';
import { HistoryView } from '../views/HistoryView';

// Mock api
vi.mock('../api', () => ({
  api: {
    getHistory: vi.fn(),
    getTransaction: vi.fn(),
    decodeTxOutputs: vi.fn().mockResolvedValue([]),
  },
}));

// Mock store
vi.mock('../store', () => ({
  useStore: vi.fn(),
}));

import { api } from '../api';
import { useStore } from '../store';

const mockApi = vi.mocked(api);
const mockUseStore = vi.mocked(useStore);

function setupStore(overrides: Record<string, any> = {}) {
  mockUseStore.mockReturnValue({
    activeAccountId: 1,
    setError: vi.fn(),
    ...overrides,
  });
}

const SAMPLE_HISTORY = [
  { tx_hash: 'abc123def456', block_height: 700000, value_delta: 5000, date_created: 0, description: null },
  { tx_hash: 'xyz789ghi012', block_height: 0, value_delta: -2000, date_created: 0, description: null },
];

const SAMPLE_TX_DETAIL = {
  txid: 'abc123def456',
  status: 'found',
  account_id: 1,
  fee: 500,
  inputs: [{ prev_tx_hash: 'prevhash123', prev_vout: 0, script_sig: 'sig', sequence: 0 }],
  outputs: [{ value: 4500, script_pubkey: 'pubkey123' }],
  raw_tx: '01000000...',
  label: null,
  detail_complete: true,
};

// Helper: find the TX row by partial hash text
function findTxRow(hash: string) {
  return screen.getByText(new RegExp(hash)).closest('[class*="cursor-pointer"]');
}

describe('HistoryView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupStore();
    mockApi.getHistory.mockResolvedValue(SAMPLE_HISTORY);
    mockApi.getTransaction.mockResolvedValue(SAMPLE_TX_DETAIL);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('reports an error instead of claiming empty history and retries explicitly', async () => {
    mockApi.getHistory.mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce([]);
    render(<HistoryView />);
    expect(await screen.findByText(/History unavailable/)).toBeTruthy();
    expect(screen.queryByText('No transactions yet.')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Retry history' }));
    expect(await screen.findByText('No transactions yet.')).toBeTruthy();
  });

  it('ignores a previous wallet response even when the account id is the same', async () => {
    let resolveOld!: (value: typeof SAMPLE_HISTORY) => void;
    mockApi.getHistory.mockReturnValueOnce(new Promise(resolve => { resolveOld = resolve; })).mockResolvedValueOnce([]);
    setupStore({ activeWalletPath: '/old' });
    const view = render(<HistoryView />);
    setupStore({ activeWalletPath: '/new' });
    view.rerender(<HistoryView />);
    await screen.findByText('No transactions yet.');
    resolveOld(SAMPLE_HISTORY);
    await waitFor(() => expect(screen.queryByText(/abc123def456/)).toBeNull());
  });

  it.each([{}, null, [{ tx_hash: 'x' }]])('rejects malformed history responses', async result => {
    mockApi.getHistory.mockResolvedValueOnce(result as any);
    render(<HistoryView />);
    expect(await screen.findByText(/History unavailable/)).toBeTruthy();
    expect(screen.queryByText('No transactions yet.')).toBeNull();
  });

  it('ignores a pending detail from a previous wallet instance with the same account', async () => {
    let resolve!: (value: typeof SAMPLE_TX_DETAIL) => void;
    mockApi.getTransaction.mockReturnValueOnce(new Promise(r => { resolve = r; }));
    setupStore({ activeWalletPath: '/same', walletInstanceToken: 'a' });
    const view = render(<HistoryView />);
    await screen.findByText(/abc123def456/);
    fireEvent.click(findTxRow('abc123def456')!);
    setupStore({ activeWalletPath: '/same', walletInstanceToken: 'b' });
    view.rerender(<HistoryView />);
    await act(async () => resolve(SAMPLE_TX_DETAIL));
    expect(screen.queryByText('Transaction Details')).toBeNull();
  });

  it('ignores a pending decode after selecting another transaction', async () => {
    let resolve!: (value: any[]) => void;
    mockApi.decodeTxOutputs.mockReturnValueOnce(new Promise(r => { resolve = r; })).mockResolvedValueOnce([]);
    render(<HistoryView />);
    await screen.findByText(/abc123def456/);
    fireEvent.click(findTxRow('abc123def456')!);
    await screen.findByText('Transaction Details');
    fireEvent.click(findTxRow('xyz789ghi012')!);
    await waitFor(() => expect(mockApi.getTransaction).toHaveBeenCalledTimes(2));
    await act(async () => resolve([{ output_index: 0, value: 4500, script_pubkey_hex: 'old', kind: { type: 'op_return_protocol', protocol: 'OLD', data: 'stale' } }]));
    expect(screen.queryByText(/OLD Protocol/)).toBeNull();
  });

  it('ignores pending decoding after the detail panel is closed', async () => {
    let resolve!: (value: any[]) => void;
    mockApi.decodeTxOutputs.mockReturnValueOnce(new Promise(r => { resolve = r; }));
    render(<HistoryView />);
    await screen.findByText(/abc123def456/);
    fireEvent.click(findTxRow('abc123def456')!);
    await screen.findByText('Transaction Details');
    fireEvent.click(screen.getByText('Close'));
    await act(async () => resolve([{ output_index: 0, value: 4500, script_pubkey_hex: 'old', kind: { type: 'op_return_protocol', protocol: 'OLD', data: 'stale' } }]));
    expect(screen.queryByText('Transaction Details')).toBeNull();
    expect(screen.queryByText(/OLD Protocol/)).toBeNull();
  });

  it('renders transactions after loading', async () => {
    render(<HistoryView />);

    await waitFor(() => {
      expect(screen.getByText(/abc123def456/)).toBeTruthy();
    });
  });

  it('clicking a TX opens detail panel with txid', async () => {
    render(<HistoryView />);

    await waitFor(() => {
      expect(screen.getByText(/abc123def456/)).toBeTruthy();
    });

    const row = findTxRow('abc123def456');
    fireEvent.click(row!);

    await waitFor(() => {
      expect(mockApi.getTransaction).toHaveBeenCalledWith('abc123def456');
    });

    await waitFor(() => {
      expect(screen.getByText('Transaction Details')).toBeTruthy();
    });
  });

  it('detail panel shows inputs and outputs', async () => {
    render(<HistoryView />);

    await waitFor(() => {
      expect(screen.getByText(/abc123def456/)).toBeTruthy();
    });

    const row = findTxRow('abc123def456');
    fireEvent.click(row!);

    await waitFor(() => {
      expect(screen.getByText(/Inputs \(1\)/)).toBeTruthy();
      expect(screen.getByText(/Outputs \(1\)/)).toBeTruthy();
    });
  });

  it('close button closes detail panel', async () => {
    render(<HistoryView />);

    await waitFor(() => {
      expect(screen.getByText(/abc123def456/)).toBeTruthy();
    });

    const row = findTxRow('abc123def456');
    fireEvent.click(row!);

    await waitFor(() => {
      expect(screen.getByText('Transaction Details')).toBeTruthy();
    });

    fireEvent.click(screen.getByText('Close'));

    await waitFor(() => {
      expect(screen.queryByText('Transaction Details')).toBeNull();
    });
  });

  it('distinguishes unknown amounts from an actual zero', async () => {
    mockApi.getHistory.mockResolvedValue([
      { ...SAMPLE_HISTORY[0], tx_hash: 'unknown-amount', value_delta: null },
      { ...SAMPLE_HISTORY[1], tx_hash: 'zero-amount', value_delta: 0 },
    ]);
    render(<HistoryView />);
    await screen.findByText(/unknown-amount/);
    expect(findTxRow('unknown-amount')?.textContent).toContain('Unknown');
    expect(findTxRow('zero-amount')?.textContent).toContain('0 sat');
    expect(screen.getByTitle('Reported by server; chain validation is not guaranteed')).toBeTruthy();
  });

  it('shows complete external and OP_RETURN outputs without replacing scripts', async () => {
    const outputs = [
      { value: 4500, script_pubkey: '76a914external88ac' },
      { value: 0, script_pubkey: '006a0464617461' },
    ];
    mockApi.getTransaction.mockResolvedValue({ ...SAMPLE_TX_DETAIL, outputs });
    mockApi.decodeTxOutputs.mockResolvedValue([
      { output_index: 0, value: 4500, script_pubkey_hex: outputs[0].script_pubkey, kind: { type: 'plain' } },
      { output_index: 1, value: 0, script_pubkey_hex: outputs[1].script_pubkey, kind: { type: 'op_return_protocol', protocol: 'Test', data: 'data' } },
    ]);
    render(<HistoryView />);
    await screen.findByText(/abc123def456/);
    fireEvent.click(findTxRow('abc123def456')!);
    await waitFor(() => expect(mockApi.decodeTxOutputs).toHaveBeenCalledWith(outputs));
    expect(await screen.findByText(/Outputs \(2\)/)).toBeTruthy();
    expect(screen.getByText(/76a914external88ac/)).toBeTruthy();
    expect(screen.getByText(/006a0464617461/)).toBeTruthy();
    expect(await screen.findByText(/Test Protocol/)).toBeTruthy();
  });

  it('shows incomplete details without inventing counts or decoding unknown outputs', async () => {
    mockApi.getTransaction.mockResolvedValue({ ...SAMPLE_TX_DETAIL, raw_tx: null, inputs: null, outputs: null, fee: null, account_id: null, detail_complete: false });
    render(<HistoryView />);
    await screen.findByText(/abc123def456/);
    fireEvent.click(findTxRow('abc123def456')!);
    expect(await screen.findByText(/details are incomplete/)).toBeTruthy();
    expect(screen.queryByText(/Inputs \(/)).toBeNull();
    expect(screen.queryByText(/Outputs \(/)).toBeNull();
    expect(screen.queryByText('Fee')).toBeNull();
    expect(screen.queryByText('Account')).toBeNull();
    expect(mockApi.decodeTxOutputs).not.toHaveBeenCalled();
  });

  it('reports transaction detail errors', async () => {
    const setError = vi.fn();
    setupStore({ setError });
    mockApi.getTransaction.mockRejectedValue('transaction not found');
    render(<HistoryView />);
    await screen.findByText(/abc123def456/);
    fireEvent.click(findTxRow('abc123def456')!);
    await waitFor(() => expect(setError).toHaveBeenCalledWith('TX detail: transaction not found'));
    expect(mockApi.decodeTxOutputs).not.toHaveBeenCalled();
  });

});