import { beforeEach, describe, expect, it, vi } from 'vitest';
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
import { invoke } from '@tauri-apps/api/core';
import { api } from '../api';

const txHash = 'ab'.repeat(32);
const root = 'cd'.repeat(32);
const response = { verified: true, tx_hash: txHash, block_height: 42, merkle_root: root, message: 'matches stored header; consensus is not established' };
beforeEach(() => { vi.resetAllMocks(); });

describe('transaction proof IPC contract', () => {
  it('sends the backend parameter names and returns the actual verification result', async () => {
    vi.mocked(invoke).mockResolvedValueOnce(response);
    expect(await api.verifyTransactionProof(txHash, 42)).toEqual(response);
    expect(invoke).toHaveBeenCalledWith('verify_transaction_proof', { txHash, blockHeight: 42 });
    vi.mocked(invoke).mockResolvedValueOnce({ ...response, verified: false });
    expect((await api.verifyTransactionProof(txHash, 42)).verified).toBe(false);
  });
  it.each([['bad', 42], [txHash, -1], [txHash, 1.5], [txHash, Number.MAX_SAFE_INTEGER + 1]])('rejects invalid parameters without IPC %#', async (hash, height) => {
    await expect(api.verifyTransactionProof(hash, height)).rejects.toThrow('Invalid transaction hash or block height');
    expect(invoke).not.toHaveBeenCalled();
  });
  it.each([null, {}, { ...response, merkle_root: '' }, { ...response, block_height: 43 }, { ...response, tx_hash: 'ef'.repeat(32) }, { ...response, verified: 'true' }])('rejects malformed or mismatched responses %#', async (invalid) => {
    vi.mocked(invoke).mockResolvedValueOnce(invalid);
    await expect(api.verifyTransactionProof(txHash, 42)).rejects.toThrow('Invalid transaction proof response');
  });
  it('propagates backend errors', async () => {
    vi.mocked(invoke).mockRejectedValueOnce(new Error('not connected'));
    await expect(api.verifyTransactionProof(txHash, 42)).rejects.toThrow('not connected');
  });
});
