import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { NetworkView } from '../views/NetworkView';

vi.mock('../api', () => ({ api: {
  getNetworkInfo: vi.fn(), getServers: vi.fn(), listNetworks: vi.fn(), getHeaderStoreInfo: vi.fn(), syncHeaders: vi.fn(),
} }));
import { api } from '../api';

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.getNetworkInfo).mockResolvedValue({ connected: false } as any);
  vi.mocked(api.getServers).mockResolvedValue([]);
  vi.mocked(api.listNetworks).mockResolvedValue([]);
  vi.mocked(api.getHeaderStoreInfo).mockResolvedValue({ header_count: 3, tip_height: 2 });
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
