import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MigrationPanel } from '../components/MigrationPanel';

const mocks = vi.hoisted(() => ({ gate: vi.fn(), info: vi.fn(), preview: vi.fn(), commit: vi.fn() }));
vi.mock('../store', () => ({ useStore: () => ({ setMigrationGate: mocks.gate, migrationMessage: null, activeWalletPath: '/test/wallet' }) }));
vi.mock('../api', () => ({ api: { getWalletInfo: mocks.info, previewMigration: mocks.preview, migrateWallet: mocks.commit } }));
const preview = { from_version: 33, to_version: 34, policy: { legacy_totp_enabled: true, legacy_wallet_scope: 'login', legacy_record_scope: 'tx', target_policy_id: 'totp-reauth-backup-change-delete-v1', newly_require_totp: ['backup', 'change_password', 'delete_wallet'] }, confirmation_token: 'test-token', expires_in_seconds: 300 };
beforeEach(() => { vi.resetAllMocks(); mocks.info.mockResolvedValue({ is_open: true, wallet_format: 33 }); mocks.preview.mockResolvedValue(preview); });
async function prepare() {
  render(<MigrationPanel />);
  fireEvent.click(await screen.findByText('Review migration'));
  fireEvent.change(screen.getByPlaceholderText('Migration password'), { target: { value: 'test-password' } });
  fireEvent.change(screen.getByPlaceholderText('TOTP code if enabled'), { target: { value: '123456' } });
  fireEvent.change(screen.getByPlaceholderText('New backup path inside wallet data directory'), { target: { value: '/test/backup.sqlite' } });
  fireEvent.click(screen.getByText('Authenticate and review'));
  await screen.findByText(/Target policy:/);
}

describe('wallet migration UI', () => {
  it.each([34, null, 99])('does not offer migration for format %s', async format => {
    mocks.info.mockResolvedValue({ is_open: true, wallet_format: format });
    render(<MigrationPanel />);
    await waitFor(() => expect(mocks.info).toHaveBeenCalled());
    expect(screen.queryByText('Review migration')).not.toBeInTheDocument();
  });
  it('requires explicit confirmation and gates all actions while commit is pending', async () => {
    let finish!: (v: unknown) => void;
    mocks.commit.mockReturnValue(new Promise(resolve => { finish = resolve; }));
    await prepare();
    expect(screen.getByText(/migration does not securely erase these remnants/)).toBeInTheDocument();
    expect(screen.getByText('Migrate wallet')).toBeDisabled();
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByText('Migrate wallet'));
    expect(mocks.gate).toHaveBeenCalledWith('pending');
    expect(mocks.commit).toHaveBeenCalledTimes(1);
    expect(mocks.commit).toHaveBeenCalledWith('test-password', '123456', '/test/backup.sqlite', 'test-token');
    await act(async () => finish({ from_version: 33, to_version: 34, backup_path: '/test/backup.sqlite', reopen_required: true }));
    expect(mocks.gate).toHaveBeenLastCalledWith('reopen_success', expect.stringContaining('/test/backup.sqlite'));
  });
  it('fails closed on malformed preview', async () => {
    mocks.preview.mockResolvedValue({ ...preview, expires_in_seconds: 0 });
    render(<MigrationPanel />);
    fireEvent.click(await screen.findByText('Review migration'));
    fireEvent.change(screen.getByPlaceholderText('Migration password'), { target: { value: 'pw' } });
    fireEvent.change(screen.getByPlaceholderText('New backup path inside wallet data directory'), { target: { value: '/test/backup' } });
    fireEvent.click(screen.getByText('Authenticate and review'));
    await screen.findByText('Invalid migration preview');
    expect(screen.queryByText('Migrate wallet')).not.toBeInTheDocument();
  });
  it('treats malformed success as unknown without claiming migration', async () => {
    mocks.commit.mockResolvedValue({ from_version: 33, to_version: 34, backup_path: '/test/backup.sqlite', reopen_required: false });
    await prepare(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByText('Migrate wallet'));
    await waitFor(() => expect(mocks.gate).toHaveBeenLastCalledWith('reopen_unknown', expect.stringContaining('outcome is unknown')));
    expect(mocks.commit).toHaveBeenCalledTimes(1);
  });
  it('treats transport errors and malformed success as unknown without retry', async () => {
    mocks.commit.mockRejectedValue(new Error('response lost'));
    await prepare(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByText('Migrate wallet'));
    await waitFor(() => expect(mocks.gate).toHaveBeenLastCalledWith('reopen_unknown', expect.stringContaining('outcome is unknown')));
    expect(mocks.commit).toHaveBeenCalledTimes(1);
  });
  it('allows an explicitly reauthenticated second commit after a known-not-committed result', async () => {
    let reject!: (reason: object) => void;
    mocks.commit.mockReturnValueOnce(new Promise((_resolve, fail) => { reject = fail; })).mockResolvedValueOnce({ from_version: 33, to_version: 34, backup_path: '/test/backup.sqlite', reopen_required: true });
    await prepare(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByText('Migrate wallet'));
    expect(mocks.commit).toHaveBeenCalledTimes(1);
    await act(async () => reject({ phase: 'authentication', outcome: 'not_committed', reopen_required: false, backup_outcome: 'not_created' }));
    fireEvent.change(screen.getByPlaceholderText('Migration password'), { target: { value: 'test-password' } });
    fireEvent.change(screen.getByPlaceholderText('TOTP code if enabled'), { target: { value: '123456' } });
    fireEvent.click(screen.getByText('Authenticate and review'));
    await screen.findByText(/Target policy:/);
    fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByText('Migrate wallet'));
    await waitFor(() => expect(mocks.commit).toHaveBeenCalledTimes(2));
    expect(mocks.gate).toHaveBeenLastCalledWith('reopen_success', expect.stringContaining('/test/backup.sqlite'));
  });
  it('permits a fresh preview after a structured known-not-committed error', async () => {
    mocks.commit.mockRejectedValue({ phase: 'authentication', outcome: 'not_committed', reopen_required: false, backup_outcome: 'not_created' });
    await prepare(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByText('Migrate wallet'));
    await waitFor(() => expect(mocks.gate).toHaveBeenLastCalledWith('idle', expect.stringContaining('not committed')));
    expect(mocks.commit).toHaveBeenCalledTimes(1);
  });
});
