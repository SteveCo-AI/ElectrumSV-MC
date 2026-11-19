import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { ReceiveView } from '../views/ReceiveView';

// Mock api
vi.mock('../api', () => ({
  api: {
    getReceiveAddress: vi.fn(),
    listReceiveAddresses: vi.fn().mockResolvedValue([]),
    createPaymentRequest: vi.fn(),
    generateQr: vi.fn().mockResolvedValue({ svg: '<svg></svg>' }),
    parseBip276Uri: vi.fn(),
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
    activeWalletPath: 'wallet-a',
    walletInstanceToken: 'instance-a',
    setError: vi.fn(),
    ...overrides,
  });
}

const SAMPLE_ADDRESS = { address: '1MoGdAdfSdf3456', key_id: 5 };

describe('ReceiveView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupStore();
    mockApi.listReceiveAddresses.mockReset().mockResolvedValue([]);
    mockApi.generateQr.mockReset().mockResolvedValue({ svg: '<svg></svg>' });
    mockApi.getReceiveAddress.mockResolvedValue(SAMPLE_ADDRESS);
    mockApi.createPaymentRequest.mockResolvedValue({ uri: 'bitcoin:1MoGdAdfSdf3456?amount=1000', address: '1MoGdAdfSdf3456', amount: 1000, label: null, paymentrequest_id: 1 });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each(['account', 'wallet', 'instance'])('ignores an old address list after a %s switch', async (kind) => {
    let finish!: (value: any) => void;
    mockApi.listReceiveAddresses.mockReset().mockReturnValueOnce(new Promise(resolve => { finish = resolve; })).mockResolvedValueOnce([{ address: 'new-address', keyinstance_id: 2, derivation_index: 0 }]);
    const { rerender } = render(<ReceiveView />);
    setupStore(kind === 'account' ? { activeAccountId: 2 } : kind === 'wallet' ? { activeWalletPath: 'wallet-b' } : { walletInstanceToken: 'instance-b' });
    rerender(<ReceiveView />);
    await screen.findByText('new-address');
    await act(async () => finish([{ address: 'old-address', keyinstance_id: 1, derivation_index: 0 }]));
    expect(screen.queryByText('old-address')).not.toBeInTheDocument();
    expect(screen.getByText('new-address')).toBeInTheDocument();
  });

  it('ignores QR and payment-request responses from the previous wallet', async () => {
    let finishQr!: (value: any) => void;
    let finishRequest!: (value: any) => void;
    mockApi.listReceiveAddresses.mockReset().mockResolvedValue([{ address: 'old-address', keyinstance_id: 1, derivation_index: 0 }]);
    mockApi.generateQr.mockReturnValueOnce(new Promise(resolve => { finishQr = resolve; })).mockResolvedValueOnce({ svg: '<svg id="new-qr"></svg>' });
    mockApi.createPaymentRequest.mockReturnValueOnce(new Promise(resolve => { finishRequest = resolve; }));
    const { rerender } = render(<ReceiveView />);
    await screen.findByText('old-address');
    fireEvent.click(screen.getByText('Show QR'));
    fireEvent.click(screen.getByText('Request'));
    mockApi.listReceiveAddresses.mockResolvedValue([{ address: 'new-address', keyinstance_id: 2, derivation_index: 0 }]);
    setupStore({ activeWalletPath: 'wallet-b' });
    rerender(<ReceiveView />);
    await screen.findByText('new-address');
    fireEvent.click(screen.getByText('Show QR'));
    await waitFor(() => expect(document.querySelector('#new-qr')).not.toBeNull());
    await act(async () => { finishQr({ svg: '<svg id="old-qr"></svg>' }); finishRequest({ uri: 'bitcoin:old-address', address: 'old-address', amount: 0, label: null, paymentrequest_id: 1 }); });
    expect(screen.queryByText('bitcoin:old-address')).not.toBeInTheDocument();
    expect(document.querySelector('#old-qr')).toBeNull();
    expect(document.querySelector('#new-qr')).not.toBeNull();
  });

  it('ignores an address generated for a previous wallet', async () => {
    let finish!: (value: any) => void;
    mockApi.getReceiveAddress.mockReset().mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    mockApi.listReceiveAddresses.mockResolvedValueOnce([]).mockResolvedValueOnce([{ address: 'new-address', keyinstance_id: 2, derivation_index: 0 }]);
    const { rerender } = render(<ReceiveView />);
    await waitFor(() => expect(mockApi.getReceiveAddress).toHaveBeenCalled());
    setupStore({ activeWalletPath: 'wallet-b' });
    rerender(<ReceiveView />);
    await screen.findByText('new-address');
    await act(async () => finish({ address: 'old-generated', key_id: 1 }));
    expect(screen.queryByText('old-generated')).not.toBeInTheDocument();
  });

  it('rejects invalid request amounts and sends a blank amount as null', async () => {
    render(<ReceiveView />); await screen.findByText('1MoGdAdfSdf3456');
    const input = screen.getByPlaceholderText('Amount (satoshis)');
    for (const invalid of ['1e3', '1.5', '0', '-1', '9007199254740992']) {
      fireEvent.change(input, { target: { value: invalid } }); fireEvent.click(screen.getByText('Request'));
    }
    expect(mockApi.createPaymentRequest).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: '' } }); fireEvent.click(screen.getByText('Request'));
    await waitFor(() => expect(mockApi.createPaymentRequest).toHaveBeenCalledWith(1, null, undefined));
  });

  it('serializes request creation and invalidates a hidden pending QR', async () => {
    let finishQr!: (value: any) => void; let finishRequest!: (value: any) => void;
    mockApi.generateQr.mockReturnValueOnce(new Promise(resolve => { finishQr = resolve; }));
    mockApi.createPaymentRequest.mockReturnValueOnce(new Promise(resolve => { finishRequest = resolve; }));
    render(<ReceiveView />); await screen.findByText('1MoGdAdfSdf3456');
    fireEvent.click(screen.getByText('Show QR')); fireEvent.click(screen.getByText('Hide QR'));
    await act(async () => finishQr({ svg: '<svg id="hidden-qr"></svg>' }));
    expect(document.querySelector('#hidden-qr')).toBeNull();
    fireEvent.click(screen.getByText('Request')); fireEvent.click(screen.getByText('Request'));
    expect(mockApi.createPaymentRequest).toHaveBeenCalledTimes(1);
    expect(screen.getByPlaceholderText('Amount (satoshis)')).toBeDisabled();
    expect(screen.getByPlaceholderText('Label (optional)')).toBeDisabled();
    await act(async () => finishRequest({ uri: 'bitcoin:test', address: 'test', amount: null, label: null, paymentrequest_id: 1 }));
    expect(screen.getByPlaceholderText('Amount (satoshis)')).not.toBeDisabled();
  });

  it('invalidates a pending address QR when parsing a BIP276 URI', async () => {
    let finishQr!: (value: any) => void;
    mockApi.generateQr.mockReturnValueOnce(new Promise(resolve => { finishQr = resolve; }));
    mockApi.parseBip276Uri.mockResolvedValue({ valid: true, prefix: 'bitcoin-script', version: 1, network: 1, data_hex: 'deadbeef', error: null });
    render(<ReceiveView />); await screen.findByText('1MoGdAdfSdf3456');
    fireEvent.click(screen.getByText('Show QR'));
    fireEvent.change(screen.getByPlaceholderText('bitcoin-script://...'), { target: { value: 'bitcoin-script://test' } });
    fireEvent.click(screen.getByText('Parse'));
    await screen.findByText('deadbeef');
    await act(async () => finishQr({ svg: '<svg id="stale-qr"></svg>' }));
    expect(document.querySelector('#stale-qr')).toBeNull();
  });

  it('New Address button calls getReceiveAddress', async () => {
    render(<ReceiveView />);

    await waitFor(() => {
      expect(mockApi.getReceiveAddress).toHaveBeenCalledWith(1);
    });
  });

  it('address is rendered after loading', async () => {
    render(<ReceiveView />);

    await waitFor(() => {
      expect(screen.getByText('1MoGdAdfSdf3456')).toBeTruthy();
    });
  });

  it('Show QR button generates QR code', async () => {
    render(<ReceiveView />);

    await waitFor(() => {
      expect(screen.getByText('1MoGdAdfSdf3456')).toBeTruthy();
    });

    const showQrButton = screen.getByText('Show QR');
    fireEvent.click(showQrButton);

    // QR code area should now show SVG content (dangerouslySetInnerHTML)
    await waitFor(() => {
      const qrContainer = document.querySelector('.bg-white.p-1');
      expect(qrContainer).toBeTruthy();
    });
  });

  it('Copy button calls clipboard.writeText', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: { writeText },
    });

    render(<ReceiveView />);

    await waitFor(() => {
      expect(screen.getByText('1MoGdAdfSdf3456')).toBeTruthy();
    });

    const copyButton = screen.getByText('Copy');
    fireEvent.click(copyButton);

    expect(writeText).toHaveBeenCalledWith('1MoGdAdfSdf3456');
  });

  it('BIP276 Parse button calls parseBip276Uri and shows decoded data', async () => {
    const sampleUri = 'bitcoin-script://1234567890';
    mockApi.parseBip276Uri.mockResolvedValue({
      valid: true,
      prefix: 'bitcoin-script',
      version: 1,
      network: 1,
      data_hex: '76a91400112233445566778899aabbccddeeff',
      error: null,
    });

    render(<ReceiveView />);

    await waitFor(() => {
      expect(screen.getByText('1MoGdAdfSdf3456')).toBeTruthy();
    });

    const input = screen.getByPlaceholderText('bitcoin-script://...') as HTMLInputElement;
    fireEvent.change(input, { target: { value: sampleUri } });

    const parseButton = screen.getByText('Parse');
    fireEvent.click(parseButton);

    await waitFor(() => {
      expect(mockApi.parseBip276Uri).toHaveBeenCalledWith(sampleUri);
    });

    await waitFor(() => {
      expect(screen.getByText('76a91400112233445566778899aabbccddeeff')).toBeTruthy();
      expect(screen.getByText(/Mainnet/)).toBeTruthy();
    });
  });

  it('BIP276 parse shows error in red on invalid URI', async () => {
    mockApi.parseBip276Uri.mockResolvedValue({
      valid: false,
      prefix: null,
      version: null,
      network: null,
      data_hex: null,
      error: 'bad checksum',
    });

    render(<ReceiveView />);

    await waitFor(() => {
      expect(screen.getByText('1MoGdAdfSdf3456')).toBeTruthy();
    });

    const input = screen.getByPlaceholderText('bitcoin-script://...') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'bitcoin-script://bad' } });

    fireEvent.click(screen.getByText('Parse'));

    await waitFor(() => {
      const err = screen.getByText('bad checksum');
      expect(err.className).toContain('red');
    });
  });

  it('BIP276 Show QR button generates QR code for the URI', async () => {
    const sampleUri = 'bitcoin-script://abc123';
    mockApi.parseBip276Uri.mockResolvedValue({
      valid: true,
      prefix: 'bitcoin-script',
      version: 1,
      network: 2,
      data_hex: 'deadbeef',
      error: null,
    });

    render(<ReceiveView />);

    await waitFor(() => {
      expect(screen.getByText('1MoGdAdfSdf3456')).toBeTruthy();
    });

    const input = screen.getByPlaceholderText('bitcoin-script://...') as HTMLInputElement;
    fireEvent.change(input, { target: { value: sampleUri } });
    fireEvent.click(screen.getByText('Parse'));

    await waitFor(() => {
      expect(screen.getByText('deadbeef')).toBeTruthy();
    });

    // Two "Show QR" buttons exist (one for address, one for BIP276).
    // The BIP276 section is after the address list, so click the last match.
    const showQrButtons = screen.getAllByText('Show QR');
    fireEvent.click(showQrButtons[showQrButtons.length - 1]);

    await waitFor(() => {
      expect(mockApi.generateQr).toHaveBeenCalledWith(sampleUri, expect.anything());
    });
  });
});
