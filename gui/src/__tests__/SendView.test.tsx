import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { SendView } from '../views/SendView';

vi.mock('../store', () => ({ useStore: () => ({ activeAccountId: 1, setPlanId: vi.fn(), updateBalance: vi.fn() }) }));
vi.mock('../api', () => ({ api: {
  getContacts: vi.fn(), getTotpStatus: vi.fn(), getMultisigConfig: vi.fn(), getMapiFeeQuote: vi.fn(),
  listSpendPlans: vi.fn(), getSpendPlanStatus: vi.fn(), cancelSpendPlan: vi.fn(),
  prepareTx: vi.fn(), signTx: vi.fn(), broadcastSpendPlan: vi.fn(), getBalance: vi.fn(), estimateFee: vi.fn(),
} }));
import { api } from '../api';

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.getContacts).mockResolvedValue([]);
  vi.mocked(api.getTotpStatus).mockResolvedValue({ enabled: true, scope: '', recovery_codes_remaining: 0 });
  vi.mocked(api.getMultisigConfig).mockResolvedValue(null);
  vi.mocked(api.getMapiFeeQuote).mockRejectedValue('offline');
  vi.mocked(api.listSpendPlans).mockResolvedValue([]);
  vi.mocked(api.getBalance).mockResolvedValue({ confirmed: 10000, unconfirmed: 0, total: 10000, reserved: 10000, available: 0 });
  vi.mocked(api.estimateFee).mockResolvedValue({ fee: 100, num_inputs: 1, num_outputs: 2, fee_rate: 1 });
});

describe('payment plans', () => {
  it('blocks payment preparation for a multisig account', async () => {
    vi.mocked(api.getMultisigConfig).mockResolvedValue({ account_id: 1, threshold: 2, num_keys: 3, public_keys: [] });
    render(<SendView />);
    fireEvent.change(screen.getByPlaceholderText(/1A1z/), { target: { value: 'recipient' } });
    fireEvent.change(screen.getByPlaceholderText('1000'), { target: { value: '1000' } });
    await screen.findByText('Multisig signing is not supported in this test build.');
    expect(screen.getByText('Prepare Transaction')).toBeDisabled();
    fireEvent.click(screen.getByText('Prepare Transaction'));
    expect(api.prepareTx).not.toHaveBeenCalled();
  });

  it('keeps the prepared plan after a wrong TOTP and explicitly retries the same unknown transaction', async () => {
    vi.mocked(api.prepareTx).mockResolvedValue({ plan_id: 'plan1', fee: 100, total_input: 10000, total_output: 1000, change: 8900, num_inputs: 1, num_outputs: 2 });
    vi.mocked(api.signTx).mockRejectedValueOnce('wrong code').mockResolvedValueOnce({ txid: 'tx1', signed_tx_hex: 'aabb' });
    vi.mocked(api.getSpendPlanStatus).mockResolvedValueOnce({ plan_id: 'plan1', state: 'PREPARED', txid: null }).mockResolvedValueOnce({ plan_id: 'plan1', state: 'BROADCAST_UNKNOWN', txid: 'tx1' });
    vi.mocked(api.broadcastSpendPlan).mockRejectedValueOnce('timeout').mockResolvedValueOnce('tx1');
    render(<SendView />);
    await screen.findByText('Prepare Transaction');
    fireEvent.change(screen.getByPlaceholderText(/1A1z/), { target: { value: 'recipient' } });
    fireEvent.change(screen.getByPlaceholderText('1000'), { target: { value: '1000' } });
    await waitFor(() => expect(screen.getByText('Prepare Transaction')).not.toBeDisabled());
    fireEvent.click(screen.getByText('Prepare Transaction'));
    await screen.findByText('Transaction Preview');
    fireEvent.change(screen.getByPlaceholderText('6-digit TOTP code'), { target: { value: '123456' } });
    fireEvent.click(screen.getByText('Sign Transaction'));
    await screen.findByText(/Signing failed/);
    fireEvent.click(screen.getByText('Sign Transaction'));
    await screen.findByText('Broadcast Transaction');
    fireEvent.click(screen.getByText('Broadcast Transaction'));
    await screen.findByText(/transaction may already have been sent/i);
    expect(api.broadcastSpendPlan).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByText('Retry sending this same transaction'));
    await screen.findByText('✓ Transaction Broadcast');
    expect(vi.mocked(api.signTx).mock.calls.map(c => c[0])).toEqual(['plan1', 'plan1']);
    expect(vi.mocked(api.broadcastSpendPlan).mock.calls).toEqual([['plan1', 'tx1', false], ['plan1', 'tx1', true]]);
  });

  it('shows SIGNED after a definite preflight failure and does not offer unknown retry', async () => {
    vi.mocked(api.listSpendPlans).mockResolvedValue([{ plan_id: 'signed', state: 'SIGNED', txid: 'tx3' }]);
    vi.mocked(api.broadcastSpendPlan).mockRejectedValue('preflight');
    vi.mocked(api.getSpendPlanStatus).mockResolvedValue({ plan_id: 'signed', state: 'SIGNED', txid: 'tx3' });
    render(<SendView />);
    fireEvent.click(await screen.findByText('Broadcast signed transaction'));
    await screen.findByText(/Plan status: SIGNED/);
    expect(screen.queryByText('Retry sending this same transaction')).not.toBeInTheDocument();
    expect(screen.getByText('Broadcast signed transaction')).toBeInTheDocument();
    expect(api.broadcastSpendPlan).toHaveBeenCalledWith('signed', 'tx3', false);
  });

  it('does not claim a broadcast or offer sending when sign status cannot be read', async () => {
    vi.mocked(api.prepareTx).mockResolvedValue({ plan_id: 'plan1', fee: 100, total_input: 10000, total_output: 1000, change: 8900, num_inputs: 1, num_outputs: 2 });
    vi.mocked(api.signTx).mockRejectedValue('sign error');
    vi.mocked(api.getSpendPlanStatus).mockRejectedValue('offline');
    render(<SendView />);
    fireEvent.change(screen.getByPlaceholderText(/1A1z/), { target: { value: 'recipient' } });
    fireEvent.change(screen.getByPlaceholderText('1000'), { target: { value: '1000' } });
    await waitFor(() => expect(screen.getByText('Prepare Transaction')).not.toBeDisabled());
    fireEvent.click(screen.getByText('Prepare Transaction'));
    await screen.findByText('Transaction Preview');
    fireEvent.change(screen.getByPlaceholderText('6-digit TOTP code'), { target: { value: '123456' } });
    fireEvent.click(screen.getByText('Sign Transaction'));
    await screen.findByText(/Plan status unknown/);
    expect(screen.getByText('Plan status: unknown')).toBeInTheDocument();
    expect(screen.queryByText('Broadcast Transaction')).not.toBeInTheDocument();
    expect(screen.queryByText('Retry sending this same transaction')).not.toBeInTheDocument();
    expect(screen.queryByText(/transaction may already have been sent/i)).not.toBeInTheDocument();
    expect(api.broadcastSpendPlan).not.toHaveBeenCalled();
  });

  it('keeps the current prepared plan visible if cancellation fails', async () => {
    vi.mocked(api.prepareTx).mockResolvedValue({ plan_id: 'keep', fee: 100, total_input: 10000, total_output: 1000, change: 8900, num_inputs: 1, num_outputs: 2 });
    vi.mocked(api.cancelSpendPlan).mockRejectedValue('database unavailable');
    render(<SendView />);
    fireEvent.change(screen.getByPlaceholderText(/1A1z/), { target: { value: 'recipient' } });
    fireEvent.change(screen.getByPlaceholderText('1000'), { target: { value: '1000' } });
    await waitFor(() => expect(screen.getByText('Prepare Transaction')).not.toBeDisabled());
    fireEvent.click(screen.getByText('Prepare Transaction'));
    await screen.findByText('Transaction Preview');
    fireEvent.click(screen.getByText('Cancel prepared plan'));
    await screen.findByText(/Could not cancel plan/);
    expect(screen.getByText('Transaction Preview')).toBeInTheDocument();
    expect(api.cancelSpendPlan).toHaveBeenCalledWith('keep');
  });

  it('recovers unknown plans without automatic sending and cancels only on explicit action', async () => {
    vi.mocked(api.listSpendPlans).mockResolvedValue([
      { plan_id: 'old', state: 'PREPARED', txid: null },
      { plan_id: 'uncertain', state: 'BROADCAST_UNKNOWN', txid: 'tx2' },
    ]);
    vi.mocked(api.cancelSpendPlan).mockResolvedValue();
    render(<SendView />);
    await screen.findByText('old');
    expect(api.broadcastSpendPlan).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText('Cancel prepared plan and release inputs'));
    await waitFor(() => expect(api.cancelSpendPlan).toHaveBeenCalledWith('old'));
    expect(api.cancelSpendPlan).toHaveBeenCalledTimes(1);
    expect(screen.getByText('Retry sending this same transaction')).toBeInTheDocument();
  });
});
