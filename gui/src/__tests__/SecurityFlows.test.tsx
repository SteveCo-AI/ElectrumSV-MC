import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { SecurityView } from '../views/SecurityView';
import { LoginScreen } from '../views/LoginScreen';

vi.mock('../store', () => {
  const state = { selectedWallet: 'test.wallet', setAuthenticated: vi.fn(), setWalletInfo: vi.fn(), setAccounts: vi.fn(), setActiveAccount: vi.fn(), setView: vi.fn(), setActiveWalletPath: vi.fn(), setActiveWalletIdentity: vi.fn(), requireWalletReopen: vi.fn() };
  return { useStore: Object.assign(() => state, { getState: () => state }) };
});
vi.mock('../api', () => ({ isDefiniteTotpAuthFailure: (e: unknown) => ['incorrect password', 'wallet authentication failed', 'invalid TOTP code', 'TOTP code required', 'invalid recovery code'].includes(typeof e === 'string' ? e : e instanceof Error ? e.message : ''), api: {
  getTotpStatus: vi.fn(), getHardwareWalletStatus: vi.fn(), generateQr: vi.fn(), totpEnable: vi.fn(), confirmTotpSetup: vi.fn(), cancelTotpSetup: vi.fn(), generateTotpRecoveryCodes: vi.fn(), totpDisable: vi.fn(),
  openWallet: vi.fn(), unlockWalletWithTOTP: vi.fn(), totpRecover: vi.fn(), getWalletInfo: vi.fn(), getAccounts: vi.fn(),
} }));
import { api } from '../api';
import { useStore } from '../store';

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.getTotpStatus).mockResolvedValue({ enabled: false, scope: 'tx', recovery_codes_remaining: 0, scope_editable: false });
  vi.mocked(api.getHardwareWalletStatus).mockResolvedValue(false);
  vi.mocked(api.getWalletInfo).mockResolvedValue({ is_open: true, wallet_format: 34 });
  vi.mocked(api.generateQr).mockResolvedValue({ svg: '<svg></svg>' });
  vi.mocked(api.totpEnable).mockResolvedValue({ secret_base32: 'TESTSECRET', otpauth_url: 'otpauth://test' });
  vi.mocked(api.cancelTotpSetup).mockResolvedValue();
});

describe('security flows', () => {
  it('identifies the existing-wallet mode, login group and password in English and German', () => {
    try {
      for (const [language, mode, password, submit] of [
        ['en', 'Existing Wallet', 'Wallet password', 'Unlock Wallet'],
        ['de', 'Vorhandene Wallet', 'Wallet-Passwort', 'Wallet entsperren'],
      ]) {
        localStorage.setItem('electrumsv-mc-language', language);
        const view = render(<LoginScreen />);
        expect(screen.getByRole('button', { name: mode })).toBeInTheDocument();
        const group = screen.getByRole('group', { name: mode });
        expect(within(group).getByLabelText(password)).toBeInTheDocument();
        expect(within(group).getByRole('button', { name: submit })).toBeDisabled();
        view.unmount();
      }
    } finally {
      localStorage.removeItem('electrumsv-mc-language');
    }
  });

  it('labels recovery and disable controls within distinct accessible groups', async () => {
    vi.mocked(api.getTotpStatus).mockResolvedValue({ enabled: true, scope: 'tx', recovery_codes_remaining: 0, scope_editable: false });
    vi.mocked(api.generateTotpRecoveryCodes).mockResolvedValue(['TEST-CODE']);
    render(<SecurityView />);
    const recovery = await screen.findByRole('group', { name: 'Recovery Codes' });
    const disable = screen.getByRole('group', { name: 'Disable 2FA' });
    const recoveryPassword = within(recovery).getByLabelText('Wallet password for recovery codes');
    const recoveryCode = within(recovery).getByLabelText('Authenticator code for recovery codes');
    const disablePassword = within(disable).getByLabelText('Wallet password for disabling 2FA');
    const disableCode = within(disable).getByLabelText('Authenticator code for disabling 2FA');
    expect(new Set([recoveryPassword.id, recoveryCode.id, disablePassword.id, disableCode.id]).size).toBe(4);
    expect(within(recovery).queryByLabelText('Authenticator code for disabling 2FA')).toBeNull();
    fireEvent.change(recoveryPassword, { target: { value: 'test-password' } });
    fireEvent.change(recoveryCode, { target: { value: '123456' } });
    fireEvent.click(within(recovery).getByRole('button', { name: 'Generate Recovery Codes' }));
    await waitFor(() => expect(api.generateTotpRecoveryCodes).toHaveBeenCalledWith('test-password', '123456'));
  });

  it('keeps setup pending on incorrect code and enables only after confirmation', async () => {
    vi.mocked(api.confirmTotpSetup).mockRejectedValueOnce(new Error('Invalid code')).mockResolvedValueOnce();
    vi.mocked(api.getTotpStatus).mockResolvedValueOnce({ enabled: false, scope: 'tx', recovery_codes_remaining: 0 }).mockResolvedValueOnce({ enabled: false, scope: 'tx', recovery_codes_remaining: 0 }).mockResolvedValueOnce({ enabled: true, scope: 'tx', recovery_codes_remaining: 0 });
    render(<SecurityView />);
    await screen.findByText('Set up 2FA');
    fireEvent.change(screen.getByPlaceholderText('Wallet password'), { target: { value: 'test-password' } });
    fireEvent.click(screen.getByText('Set up 2FA'));
    await screen.findByText('Scan QR Code');
    expect(screen.getByText(/Password only/)).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText('Enter 6-digit code from your app'), { target: { value: '111111' } });
    fireEvent.click(screen.getByText('Verify & Enable'));
    await screen.findByText('Invalid code');
    expect(screen.getByText('Scan QR Code')).toBeInTheDocument();
    expect(screen.getByText(/Password only/)).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText('Enter 6-digit code from your app'), { target: { value: '222222' } });
    fireEvent.click(screen.getByText('Verify & Enable'));
    await screen.findByText('2FA enabled successfully.');
    expect(api.confirmTotpSetup).toHaveBeenNthCalledWith(1, 'test-password', '111111');
    expect(api.confirmTotpSetup).toHaveBeenNthCalledWith(2, 'test-password', '222222');
  });

  it('disables cancellation while confirmation is in flight and reloads the resulting status', async () => {
    let finish!: () => void;
    vi.mocked(api.confirmTotpSetup).mockReturnValue(new Promise<void>(resolve => { finish = resolve; }));
    vi.mocked(api.getTotpStatus).mockResolvedValueOnce({ enabled: false, scope: 'tx', recovery_codes_remaining: 0 }).mockResolvedValueOnce({ enabled: true, scope: 'tx', recovery_codes_remaining: 0 });
    render(<SecurityView />);
    await screen.findByText('Set up 2FA');
    fireEvent.change(screen.getByPlaceholderText('Wallet password'), { target: { value: 'test-password' } });
    fireEvent.click(screen.getByText('Set up 2FA'));
    await screen.findByText('Scan QR Code');
    fireEvent.change(screen.getByPlaceholderText('Enter 6-digit code from your app'), { target: { value: '111111' } });
    fireEvent.click(screen.getByText('Verify & Enable'));
    expect(screen.getByText('Cancel')).toBeDisabled();
    fireEvent.click(screen.getByText('Cancel'));
    expect(api.cancelTotpSetup).not.toHaveBeenCalled();
    await act(async () => finish());
    await screen.findByText('2FA enabled successfully.');
    expect(api.getTotpStatus).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('Scan QR Code')).not.toBeInTheDocument();
  });

  it('discards a QR response after the view is unmounted', async () => {
    let finish!: (value: { svg: string }) => void;
    vi.mocked(api.generateQr).mockReturnValue(new Promise(resolve => { finish = resolve; }));
    const view = render(<SecurityView />);
    await screen.findByText('Set up 2FA');
    fireEvent.change(screen.getByPlaceholderText('Wallet password'), { target: { value: 'test-password' } });
    fireEvent.click(screen.getByText('Set up 2FA'));
    await waitFor(() => expect(api.generateQr).toHaveBeenCalled());
    view.unmount();
    await act(async () => finish({ svg: '<svg></svg>' }));
    expect(api.cancelTotpSetup).toHaveBeenCalledTimes(1);
    expect(screen.queryByText('Scan QR Code')).not.toBeInTheDocument();
  });

  it('cancels an unconfirmed setup when leaving the view', async () => {
    const view = render(<SecurityView />);
    await screen.findByText('Set up 2FA');
    fireEvent.change(screen.getByPlaceholderText('Wallet password'), { target: { value: 'test-password' } });
    fireEvent.click(screen.getByText('Set up 2FA'));
    await screen.findByText('Scan QR Code');
    view.unmount();
    await waitFor(() => expect(api.cancelTotpSetup).toHaveBeenCalledTimes(1));
  });

  it('treats unavailable protection status as unknown and disables setup', async () => {
    vi.mocked(api.getTotpStatus).mockRejectedValue(new Error('locked'));
    render(<SecurityView />);
    await screen.findByText('Unable to determine 2FA status.');
    expect(screen.getByText(/2FA status unknown/)).toBeInTheDocument();
    expect(screen.queryByText('Set up 2FA')).not.toBeInTheDocument();
  });

  it('shows null protection status as unknown', async () => {
    vi.mocked(api.getTotpStatus).mockResolvedValue({ enabled: null, scope: 'tx', recovery_codes_remaining: 0 });
    render(<SecurityView />);
    await waitFor(() => expect(api.getTotpStatus).toHaveBeenCalled());
    expect(screen.getByText(/2FA status unknown/)).toBeInTheDocument();
    expect(screen.queryByText('Set up 2FA')).not.toBeInTheDocument();
  });

  it('explains recovery and the signing requirement in security settings', async () => {
    vi.mocked(api.getTotpStatus).mockResolvedValue({ enabled: true, scope: 'tx', recovery_codes_remaining: 1, scope_editable: false });
    render(<SecurityView />);
    expect(await screen.findByText(/Recovering access from the login screen disables 2FA and all recovery codes/)).toHaveTextContent('After unlocking with your password, set up 2FA again before signing transactions.');
  });

  it('warns before generation, preserves all long codes and retains the form on failure', async () => {
    vi.mocked(api.getTotpStatus).mockResolvedValue({ enabled: true, scope: 'tx', recovery_codes_remaining: 1, scope_editable: false });
    const codes = Array.from({ length: 10 }, (_, i) => `ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345-AAA${"ABCDEFGHJK"[i]}`);
    vi.mocked(api.generateTotpRecoveryCodes).mockRejectedValueOnce(new Error('generation failed')).mockResolvedValueOnce(codes);
    render(<SecurityView />);
    await screen.findByText('Generating a new set replaces all previous recovery codes.');
    expect(api.generateTotpRecoveryCodes).not.toHaveBeenCalled();
    fireEvent.change(screen.getAllByPlaceholderText('Wallet password').slice(-1)[0], { target: { value: 'test-password' } });
    fireEvent.change(screen.getAllByPlaceholderText('Current 6-digit TOTP code').slice(-1)[0], { target: { value: '123456' } });
    fireEvent.click(screen.getByText('Generate Recovery Codes'));
    await screen.findByText(/Recovery code generation outcome is unknown/);
    expect(screen.queryByText(codes[0])).not.toBeInTheDocument();
    fireEvent.change(screen.getAllByPlaceholderText('Wallet password').slice(-1)[0], { target: { value: 'test-password' } });
    fireEvent.change(screen.getAllByPlaceholderText('Current 6-digit TOTP code').slice(-1)[0], { target: { value: '123456' } });
    fireEvent.click(screen.getByText('Generate Recovery Codes'));
    await screen.findByText(codes[0]);
    for (const code of codes) {
      expect(code).toHaveLength(39);
      const item = screen.getByText(code);
      expect(item.textContent).toBe(code);
      expect(item.className).toContain('select-all');
      expect(item.className).toContain('overflow-x-auto');
    }
  });

  it('does not display old codes or retry automatically when a generation response is lost', async () => {
    let reject!: (reason: Error) => void;
    vi.mocked(api.getTotpStatus).mockResolvedValue({ enabled: true, scope: 'tx', recovery_codes_remaining: 1, scope_editable: false });
    vi.mocked(api.generateTotpRecoveryCodes).mockResolvedValueOnce(['TEST-CODE']).mockReturnValueOnce(new Promise((_resolve, fail) => { reject = fail; }));
    render(<SecurityView />);
    await screen.findByText('Generating a new set replaces all previous recovery codes.');
    const fill = () => {
      fireEvent.change(screen.getAllByPlaceholderText('Wallet password').slice(-1)[0], { target: { value: 'test-password' } });
      fireEvent.change(screen.getAllByPlaceholderText('Current 6-digit TOTP code').slice(-1)[0], { target: { value: '123456' } });
    };
    fill(); fireEvent.click(screen.getByText('Generate Recovery Codes'));
    await screen.findByText('TEST-CODE');
    fireEvent.click(screen.getByText("I've saved my codes — dismiss"));
    fill(); fireEvent.click(screen.getByText('Generate Recovery Codes'));
    expect(screen.queryByText('TEST-CODE')).not.toBeInTheDocument();
    expect(screen.getByText('Generating…')).toBeDisabled();
    await act(async () => reject(new Error('response lost')));
    expect(await screen.findByText(/Previous codes may have been replaced/)).toBeInTheDocument();
    expect(screen.queryByText('TEST-CODE')).not.toBeInTheDocument();
    expect(api.generateTotpRecoveryCodes).toHaveBeenCalledTimes(2);
  });

  it('binds the token returned by open to the selected wallet path', async () => {
    vi.mocked(api.openWallet).mockResolvedValue({ wallet_path: 'test.wallet', wallet_instance_token: 'instance-a' });
    vi.mocked(api.unlockWalletWithTOTP).mockRejectedValue('incorrect password');
    render(<LoginScreen />);
    fireEvent.change(screen.getByPlaceholderText('Wallet password'), { target: { value: 'test-password' } });
    fireEvent.click(screen.getByRole('button', { name: 'Unlock Wallet' }));
    await screen.findByText('incorrect password');
    expect(useStore().setActiveWalletIdentity).toHaveBeenCalledWith('test.wallet', 'instance-a');
  });

  it('passes old and long recovery inputs byte-for-byte without case or hyphen changes', async () => {
    vi.mocked(api.openWallet).mockResolvedValue({ wallet_path: 'test.wallet' });
    vi.mocked(api.totpRecover).mockRejectedValue(new Error('invalid recovery code'));
    render(<LoginScreen />);
    fireEvent.change(screen.getByPlaceholderText('Wallet password'), { target: { value: 'test-password' } });
    fireEvent.click(screen.getByText('Use a recovery code'));
    expect(screen.getByText(/exactly as shown, including case and hyphens/)).toBeInTheDocument();
    const field = screen.getByPlaceholderText('Recovery code');
    expect(field).not.toHaveAttribute('maxLength');
    expect(field).toHaveAttribute('autocapitalize', 'none');
    const oldCode = 'aBcD-2345';
    const longCode = 'aBCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345-AAAA';
    for (const code of [oldCode, longCode]) {
      fireEvent.change(field, { target: { value: code } });
      fireEvent.click(screen.getByText('Recover 2FA access'));
      await waitFor(() => expect(api.totpRecover).toHaveBeenLastCalledWith('test-password', code));
      await screen.findByText('invalid recovery code');
      expect(screen.queryByText(/Recovery completed/)).not.toBeInTheDocument();
    }
    expect(api.totpRecover).toHaveBeenCalledTimes(2);
  });

  it.each(['TOTP update outcome unknown; reopen wallet', 'wallet update failed; reopen wallet', 'transport lost'])('requires reopen on uncertain disable: %s', async failure => {
    vi.mocked(api.getTotpStatus).mockResolvedValue({ enabled: true, scope: 'tx', recovery_codes_remaining: 1, scope_editable: false });
    vi.mocked(api.totpDisable).mockRejectedValue(failure);
    render(<SecurityView />);
    await screen.findByRole('button', { name: 'Disable 2FA' });
    fireEvent.change(screen.getAllByPlaceholderText('Wallet password').slice(-2)[0], { target: { value: 'test-password' } });
    fireEvent.change(screen.getAllByPlaceholderText('Current 6-digit TOTP code')[0], { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }));
    await waitFor(() => expect(useStore().requireWalletReopen).toHaveBeenCalledWith(expect.stringContaining('outcome is unknown')));
    expect(screen.getByText(/2FA status unknown/)).toBeInTheDocument();
    expect(screen.queryByText('2FA disabled.')).not.toBeInTheDocument();
    expect(api.totpDisable).toHaveBeenCalledTimes(1);
  });

  it('allows a known invalid TOTP to be retried without falsely reporting success', async () => {
    vi.mocked(api.getTotpStatus).mockResolvedValue({ enabled: true, scope: 'tx', recovery_codes_remaining: 1, scope_editable: false });
    vi.mocked(api.totpDisable).mockRejectedValue('invalid TOTP code');
    render(<SecurityView />);
    await screen.findByRole('button', { name: 'Disable 2FA' });
    fireEvent.change(screen.getAllByPlaceholderText('Wallet password').slice(-2)[0], { target: { value: 'test-password' } });
    fireEvent.change(screen.getAllByPlaceholderText('Current 6-digit TOTP code')[0], { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }));
    await screen.findByText('invalid TOTP code');
    expect(useStore().requireWalletReopen).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Disable 2FA' })).not.toBeDisabled();
  });

  it.each(['TOTP recovery outcome unknown; reopen wallet', 'wallet update failed; reopen wallet', 'transport lost'])('requires reopening after uncertain recovery: %s', async failure => {
    vi.mocked(api.openWallet).mockResolvedValue({ wallet_path: 'test.wallet' });
    vi.mocked(api.totpRecover).mockRejectedValue(failure);
    render(<LoginScreen />);
    fireEvent.change(screen.getByPlaceholderText('Wallet password'), { target: { value: 'test-password' } });
    fireEvent.click(screen.getByText('Use a recovery code'));
    fireEvent.change(screen.getByPlaceholderText('Recovery code'), { target: { value: 'TEST-CODE' } });
    fireEvent.click(screen.getByText('Recover 2FA access'));
    await waitFor(() => expect(useStore().requireWalletReopen).toHaveBeenCalledWith(expect.stringContaining('outcome is unknown'), 'test.wallet'));
    expect(screen.queryByText(/Recovery completed/)).not.toBeInTheDocument();
    expect(api.totpRecover).toHaveBeenCalledTimes(1);
  });

  it('recovers a locked wallet without reopening it and requires a fresh unlock', async () => {
    vi.mocked(api.openWallet).mockResolvedValue({ wallet_path: 'test.wallet' });
    vi.mocked(api.unlockWalletWithTOTP).mockRejectedValueOnce(new Error('TOTP code required')).mockResolvedValueOnce(undefined);
    vi.mocked(api.totpRecover).mockRejectedValueOnce(new Error('invalid recovery code')).mockResolvedValueOnce(undefined);
    vi.mocked(api.getWalletInfo).mockResolvedValue({ wallet_name: 'test' });
    vi.mocked(api.getAccounts).mockResolvedValue([{ account_id: 1, account_name: 'account' }]);
    render(<LoginScreen />);
    fireEvent.change(screen.getByPlaceholderText('Wallet password'), { target: { value: 'test-password' } });
    fireEvent.click(screen.getByRole('button', { name: 'Unlock Wallet' }));
    await screen.findByPlaceholderText(/6-digit/);
    fireEvent.click(screen.getByText('Use a recovery code'));
    fireEvent.change(screen.getByPlaceholderText('Recovery code'), { target: { value: 'bad' } });
    fireEvent.click(screen.getByText('Recover 2FA access'));
    await screen.findByText('invalid recovery code');
    expect(screen.queryByText(/Recovery completed/)).not.toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText('Recovery code'), { target: { value: 'valid-test' } });
    fireEvent.click(screen.getByText('Recover 2FA access'));
    await screen.findByText('Recovery completed. 2FA and all recovery codes were removed. Unlock with your password and set up 2FA again before signing transactions.');
    expect(api.openWallet).toHaveBeenCalledTimes(1);
    expect(api.unlockWalletWithTOTP).toHaveBeenCalledTimes(1);
    expect(api.totpRecover).toHaveBeenLastCalledWith('test-password', 'valid-test');
    fireEvent.change(screen.getByPlaceholderText('Wallet password'), { target: { value: 'test-password' } });
    fireEvent.click(screen.getByRole('button', { name: 'Unlock Wallet' }));
    await waitFor(() => expect(api.unlockWalletWithTOTP).toHaveBeenCalledTimes(2));
    expect(api.openWallet).toHaveBeenCalledTimes(1);
  });
});
