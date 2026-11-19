import { describe, it, expect, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { NetworkView } from '../views/NetworkView';
import { UtxoView } from '../views/UtxoView';

vi.mock('../store', () => ({ useStore: () => ({ activeAccountId: 1, activeWalletPath: '/wallet', walletInstanceToken: 'instance' }) }));
vi.mock('../api', () => ({ api: {
  getNetworkInfo: vi.fn().mockResolvedValue({ connected: false }),
  getServers: vi.fn().mockResolvedValue([{ host: 'example.org', ssl_port: 50002 }]),
  listNetworks: vi.fn().mockResolvedValue([]),
  getHeaderStoreInfo: vi.fn().mockResolvedValue(null),
  connectServer: vi.fn().mockResolvedValue({}),
  getUtxos: vi.fn().mockResolvedValue([{ tx_hash: 'ab'.repeat(32), tx_index: 4, value: 100, keyinstance_id: 1, is_coinbase: false, script_pubkey: '' }]),
} }));
import { api } from '../api';

describe('backend response contracts', () => {
  it('shows servers and connects on the advertised TLS port', async () => {
    render(<NetworkView />);
    await screen.findByText(/example.org/);
    fireEvent.click(screen.getByText('Connect'));
    await waitFor(() => expect(api.connectServer).toHaveBeenCalledWith('example.org', 50002));
  });
  it('shows unspent outputs and their output index', async () => {
    render(<UtxoView />);
    expect(await screen.findByText('100 sat')).toBeTruthy();
    expect(screen.getByText('4')).toBeTruthy();
  });
});
