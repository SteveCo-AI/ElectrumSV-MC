import { expect, it } from 'vitest';
import { useStore } from '../store';

it('preserves an uncertain 2FA outcome until the reopened wallet status is checked', () => {
  useStore.setState({ activeWalletPath: '/test/wallet', migrationGate: 'idle', migrationNeedsTotpCheck: false, migrationVerificationPath: null });
  useStore.getState().requireWalletReopen('2FA outcome unknown');
  expect(useStore.getState()).toMatchObject({ migrationGate: 'reopen_unknown', migrationVerificationPath: '/test/wallet', migrationNeedsTotpCheck: true });
  useStore.getState().resetToLanding();
  expect(useStore.getState()).toMatchObject({ migrationGate: 'idle', migrationVerificationPath: '/test/wallet', migrationNeedsTotpCheck: true });
  useStore.getState().clearMigrationVerification('2FA status checked');
  expect(useStore.getState()).toMatchObject({ migrationVerificationPath: null, migrationNeedsTotpCheck: false });
});

it('keeps the instance token with its path and clears it on wallet switch and close', () => {
  const store = useStore.getState();
  store.resetToLanding();
  store.setActiveWalletIdentity('/test/a', 'instance-1');
  expect(useStore.getState()).toMatchObject({ activeWalletPath: '/test/a', walletInstanceToken: 'instance-1' });
  store.setActiveWalletIdentity('/test/a', 'instance-2');
  expect(useStore.getState().walletInstanceToken).toBe('instance-2');
  store.setActiveWalletPath('/test/b');
  expect(useStore.getState().walletInstanceToken).toBeNull();
  store.setActiveWalletIdentity('/test/b', 'instance-3');
  store.resetToLanding();
  expect(useStore.getState()).toMatchObject({ activeWalletPath: null, walletInstanceToken: null });
});
