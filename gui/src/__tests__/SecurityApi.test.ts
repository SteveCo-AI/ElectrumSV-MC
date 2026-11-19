import { describe, expect, it, vi } from 'vitest';
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn().mockResolvedValue(null) }));
import { invoke } from '@tauri-apps/api/core';
import { api, isDefiniteTotpAuthFailure } from '../api';

it('passes BIP39 restore passphrases without trimming and keeps the default empty', async () => {
  vi.mocked(invoke).mockClear();
  await api.restoreBip39Wallet('example', 'wallet-password', 'valid mnemonic', '  Te\u0301st  ', 'standard_bip39');
  await api.createWallet('wallet-password', 'example', 'valid mnemonic');
  expect(vi.mocked(invoke).mock.calls).toEqual([
    ['restore_bip39_wallet', { name: 'example', password: 'wallet-password', mnemonic: 'valid mnemonic', passphrase: '  Te\u0301st  ', mode: 'standard_bip39' }],
    ['create_wallet', { name: 'example', password: 'wallet-password', mnemonic: 'valid mnemonic', passphrase: null }],
  ]);
  vi.mocked(invoke).mockClear();
});

describe('security IPC contract', () => {
  it('uses two-stage setup, locked recovery and scoped reauthentication arguments', async () => {
    await api.totpEnable('test-password');
    await api.confirmTotpSetup('test-password', '123456');
    await api.cancelTotpSetup();
    await api.totpRecover('test-password', 'test-code');
    await api.backupWallet('/test/path', 'test-password', '123456', 'instance-a');
    await api.changePassword('old-test', 'new-test', '123456');
    await api.deleteWallet('/test/wallet', 'test-password', '123456');
    await api.deleteWallet('/test/legacy', 'test-password');
    expect(vi.mocked(invoke).mock.calls).toEqual([
      ['begin_totp_setup', { password: 'test-password' }],
      ['confirm_totp_setup', { password: 'test-password', code: '123456' }],
      ['cancel_totp_setup'],
      ['recover_totp', { password: 'test-password', recoveryCode: 'test-code' }],
      ['backup_wallet', { backupPath: '/test/path', password: 'test-password', totpCode: '123456', expectedInstanceToken: 'instance-a' }],
      ['change_password', { oldPassword: 'old-test', newPassword: 'new-test', totpCode: '123456' }],
      ['delete_wallet', { walletPath: '/test/wallet', password: 'test-password', totpCode: '123456' }],
      ['delete_wallet', { walletPath: '/test/legacy', password: 'test-password', totpCode: null }],
    ]);
  });
});

it('classifies only exact known precommit TOTP authentication errors as safe', () => {
  expect(isDefiniteTotpAuthFailure('invalid recovery code')).toBe(true);
  expect(isDefiniteTotpAuthFailure(new Error('incorrect password'))).toBe(true);
  expect(isDefiniteTotpAuthFailure('invalid recovery code; response lost')).toBe(false);
  expect(isDefiniteTotpAuthFailure('TOTP recovery outcome unknown; reopen wallet')).toBe(false);
  expect(isDefiniteTotpAuthFailure('transport lost')).toBe(false);
});
