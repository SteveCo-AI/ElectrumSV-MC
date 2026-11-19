// Login screen — wallet lifecycle: unlock existing wallet or create new one
// Three modes:
//   "login"  — Open existing wallet: name + password (+ TOTP code if enabled)
//   "create" — New wallet: name + password → show mnemonic → confirm mnemonic → main
import { useState, useEffect, useRef } from 'react';
import { useStore } from '../store';
import { api, isDefiniteTotpAuthFailure } from '../api';
import { useTranslation, interp } from '../i18n';

type Mode = 'login' | 'create' | 'restore';
type CreateStep = 'form' | 'mnemonic' | 'confirm';
type RestoreMethod = 'mnemonic' | 'wif' | null;

export function LoginScreen() {
  const { setAuthenticated, setWalletInfo, setAccounts, setActiveAccount,
           selectedWallet, setView, setActiveWalletIdentity,
           requireWalletReopen } = useStore();
  const { t } = useTranslation();
  const [walletName, setWalletName] = useState(selectedWallet ?? '');
  const [walletPassword, setWalletPasswordState] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<Mode>(selectedWallet ? 'login' : 'create');

  const [totpRequired, setTotpRequired] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [openedPath, setOpenedPath] = useState<string | null>(null);
  const [recoveryNotice, setRecoveryNotice] = useState<string | null>(null);
  const [recoveryMode, setRecoveryMode] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState('');
  const [totpChecked, setTotpChecked] = useState(false);

  const [createStep, setCreateStep] = useState<CreateStep>('form');
  const [mnemonic, setMnemonic] = useState<string | null>(null);
  const [confirmInput, setConfirmInput] = useState('');

  // Restore state
  const [restoreMethod, setRestoreMethod] = useState<RestoreMethod>(null);
  const [restoreInput, setRestoreInput] = useState('');
  const [restoreName, setRestoreName] = useState('');
  const [restorePassword, setRestorePassword] = useState('');
  const [restorePassphrase, setRestorePassphrase] = useState('');
  const [restoreDerivationMode, setRestoreDerivationMode] = useState<'standard_bip39' | 'historical_mc'>('standard_bip39');
  const mounted = useRef(false);
  const restorePending = useRef(false);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  // Legacy ElectrumSV (1.3.x) migration state
  const [legacyMode, setLegacyMode] = useState(false);
  const [showLegacyWarning, setShowLegacyWarning] = useState(false);
  const [migrating, setMigrating] = useState(false);
  const [legacyMigratedMnemonic, setLegacyMigratedMnemonic] = useState<string | null>(null);

  // In Tauri mode, the backend is always available (same process)
  const hasToken = true;

  useEffect(() => {
    if (mode !== 'login' || !selectedWallet) return;
    setTotpChecked(false);
    setTotpRequired(false);
  }, [mode, selectedWallet]);

  const handleLogin = async () => {
    setLoading(true);
    setError(null);
    try {
      const walletPath = selectedWallet
        ? `${selectedWallet}`
        : walletName;
      let path = openedPath;
      if (!path) {
        const opened = await api.openWallet(walletPath);
        if (typeof opened.wallet_path !== 'string' || !opened.wallet_path) throw new Error('Invalid wallet path');
        path = opened.wallet_path;
        setActiveWalletIdentity(path!, opened.wallet_instance_token ?? null);
        setOpenedPath(path);
      }

      if (!path) throw new Error('Invalid wallet path');
      try {
        await api.unlockWalletWithTOTP(path, walletPassword, totpCode || undefined);
      } catch (e: any) {
        if (String(e?.message || e).includes('TOTP code required')) {
          setTotpRequired(true);
          setTotpChecked(true);
          setLoading(false);
          return;
        }
        throw e;
      }
      setWalletPasswordState('');
      setTotpCode('');

      const wi = await api.getWalletInfo();
      setWalletInfo({ walletName: wi.wallet_name ?? selectedWallet ?? '', walletLoaded: true });
      const accounts: any = await api.getAccounts();
      const accountList = Array.isArray(accounts) ? accounts : (accounts.accounts ?? []);
      const mapped = accountList.map((a: any) => ({
        id: a.account_id ?? a.id,
        name: a.account_name ?? a.name ?? '',
        type: 'standard',
      }));
      setAccounts(mapped);
      if (mapped.length > 0 && mapped[0].id !== undefined) {
        setActiveAccount(mapped[0].id);
      }
      setAuthenticated(true);
      useStore.getState().setView('main');
    } catch (e: any) {
      setError(e?.message || String(e) || t.login.loginFailed);
    } finally {
      setLoading(false);
    }
  };

  const handleRecovery = async () => {
    setLoading(true); setError(null);
    try {
      let path = openedPath;
      if (!path) {
        const opened = await api.openWallet(selectedWallet || walletName);
        if (typeof opened.wallet_path !== 'string' || !opened.wallet_path) throw new Error('Invalid wallet path');
        path = opened.wallet_path;
        setActiveWalletIdentity(path!, opened.wallet_instance_token ?? null);
        setOpenedPath(path);
      }
      if (!path) throw new Error('Invalid wallet path');
      try {
        await api.totpRecover(walletPassword, recoveryCode);
      } catch (e: any) {
        if (isDefiniteTotpAuthFailure(e)) throw e;
        setRecoveryCode(''); setWalletPasswordState(''); setTotpCode(''); setRecoveryNotice(null);
        requireWalletReopen('The 2FA recovery outcome is unknown. Close and reopen the wallet to check its protection status before retrying.', path);
        return;
      }
      setRecoveryCode(''); setWalletPasswordState(''); setTotpCode('');
      setTotpRequired(false); setRecoveryMode(false);
      setRecoveryNotice('Recovery completed. 2FA and all recovery codes were removed. Unlock with your password and set up 2FA again before signing transactions.');
    } catch (e: any) { setError(e?.message || String(e)); }
    finally { setLoading(false); }
  };

  const handleCreate = async () => {
    setLoading(true);
    setError(null);
    try {
      const name = walletName.trim() || 'default_wallet';
      const result = await api.createWallet(walletPassword, name);
      setActiveWalletIdentity(result.wallet_path, result.wallet_instance_token ?? null);
      setMnemonic(result.mnemonic);
      setCreateStep('mnemonic');
    } catch (e: any) {
      setError(e.message || t.login.createFailed);
    } finally {
      setLoading(false);
    }
  };

  const handleConfirmMnemonic = () => {
    setError(null);
    if (confirmInput.trim().toLowerCase() === mnemonic?.trim().toLowerCase()) {
      loadWalletInfo();
    } else {
      setError(t.login.mnemonicMismatch);
    }
  };

  const handleSkipConfirm = () => {
    setError(null);
    loadWalletInfo();
  };

  const loadWalletInfo = async (restoredIdentity?: { path: string; token: string | null }) => {
    setLoading(true);
    setError(null);
    try {
      const wi = await api.getWalletInfo();
      if (!mounted.current) return;
      const accounts: any = await api.getAccounts();
      if (!mounted.current) return;
      if (restoredIdentity) setActiveWalletIdentity(restoredIdentity.path, restoredIdentity.token);
      setWalletInfo({ walletName: wi.wallet_name ?? walletName, walletLoaded: true });
      const accountList = Array.isArray(accounts) ? accounts : (accounts.accounts ?? []);
      const mapped = accountList.map((a: any) => ({
        id: a.account_id ?? a.id,
        name: a.account_name ?? a.name ?? '',
        type: 'standard',
      }));
      setAccounts(mapped);
      if (mapped.length > 0 && mapped[0].id !== undefined) {
        setActiveAccount(mapped[0].id);
      }
      setWalletPasswordState('');
      setTotpCode('');
      setAuthenticated(true);
      useStore.getState().setView('main');
    } catch (e: any) {
      if (mounted.current) setError(e.message || t.login.loadFailed);
    } finally {
      if (mounted.current) setLoading(false);
    }
  };

  const handleBack = () => {
    setCreateStep('form');
    setMnemonic(null);
    setConfirmInput('');
    setTotpRequired(false);
    setTotpCode('');
    setTotpChecked(false);
    setRestoreMethod(null);
    setRestoreInput('');
    setRestoreName('');
    setRestorePassword('');
    setRestorePassphrase('');
    setRestoreDerivationMode('standard_bip39');
    setLegacyMode(false);
    setShowLegacyWarning(false);
    setMigrating(false);
    setLegacyMigratedMnemonic(null);
    setView('landing');
  };

  const handleRestore = async () => {
    // Legacy mode: show warning dialog first instead of restoring directly
    if (restoreMethod === 'mnemonic' && legacyMode) {
      setShowLegacyWarning(true);
      return;
    }
    await doRestore();
  };

  const doRestore = async () => {
    if (restorePending.current) return;
    restorePending.current = true;
    setLoading(true);
    setError(null);
    try {
      const name = restoreName.trim() || 'restored_wallet';
      if (restoreMethod === 'mnemonic') {
        const result = await api.restoreBip39Wallet(name, restorePassword, restoreInput.trim(), restorePassphrase, restoreDerivationMode);
        if (!mounted.current) return;
        // Skip mnemonic display/confirm for restored wallets
        await loadWalletInfo({ path: result.wallet_path, token: result.wallet_instance_token ?? null });
      } else if (restoreMethod === 'wif') {
        throw new Error('WIF recovery is not yet supported safely. Keep your original private key.');
      }
    } catch (e: any) {
      if (mounted.current) setError(e.message || t.login.restoreInvalidMnemonic);
    } finally {
      restorePending.current = false;
      if (mounted.current) { setRestorePassphrase(''); setLoading(false); }
    }
  };

  const handleLegacyMigrate = async () => {
    setShowLegacyWarning(false);
    setMigrating(true);
    setError(null);
    try {
      const name = restoreName.trim() || 'migrated_wallet';
      // Step 1: Create new BIP39 wallet from legacy seed
      const result = await api.restoreLegacyWallet(restoreInput.trim(), restorePassword, name);
      if (result?.wallet_path) {
        setActiveWalletIdentity(result.wallet_path, result.wallet_instance_token ?? null);
      }
      // Step 2: Sweep legacy funds to the new wallet
      if (result?.wallet_path) {
        try {
          await api.sweepLegacyWallet(
            restoreInput.trim(), result.wallet_path, restorePassword
          );
        } catch (sweepErr: any) {
          // Sweep may fail if no UTXOs or network unavailable — non-fatal
          console.warn('sweep failed:', sweepErr?.message || sweepErr);
        }
      }
      // Step 3: Show the new BIP39 mnemonic for backup before proceeding
      if (result?.new_mnemonic) {
        setLegacyMigratedMnemonic(result.new_mnemonic);
      } else {
        // No mnemonic returned — proceed directly to wallet
        await loadWalletInfo();
      }
    } catch (e: any) {
      setError(e.message || t.login.restoreInvalidMnemonic);
    } finally {
      setMigrating(false);
    }
  };

  const handleLegacyMnemonicDone = async () => {
    setLegacyMigratedMnemonic(null);
    await loadWalletInfo();
  };

  // Restoration is a separate page. Sensitive values are entered only here,
  // never in the wallet selector/login screen.
  if (mode === 'restore') {
    const canRestore = Boolean(
      restoreMethod && restoreInput.trim() && restoreName.trim() && restorePassword.length >= 4,
    );

    // Legacy migration mnemonic display (after successful restoreLegacyWallet)
    if (legacyMigratedMnemonic) {
      return (
        <div className="flex h-screen items-center justify-center bg-void-950">
          <div className="w-full max-w-lg px-4">
            <div className="text-center mb-6">
              <div className="text-3xl font-bold text-accent mb-2">{t.login.legacyWarningTitle}</div>
              <div className="text-sm text-success">{t.login.legacyMigrationDone}</div>
            </div>
            <div className="bg-void-900 rounded-xl p-6 border border-void-700">
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-4">
                <p className="text-xs text-red-400 font-medium">
                  {t.login.legacyNewMnemonic}
                </p>
              </div>
              <div className="bg-void-950 border border-void-700 rounded-lg p-4 mb-4">
                <div className="text-sm text-gray-100 font-mono leading-relaxed break-words select-all">
                  {legacyMigratedMnemonic}
                </div>
              </div>
              <button
                onClick={handleLegacyMnemonicDone}
                disabled={loading}
                className="w-full bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
              >
                {loading ? t.common.loading : t.login.confirmOpen}
              </button>
              {error && <div className="text-sm text-danger mt-3">{error}</div>}
            </div>
          </div>
        </div>
      );
    }

    return (
      <div className="flex min-h-screen items-center justify-center bg-void-950 px-4 py-8">
        <div className="w-full max-w-lg">
          <div className="text-center mb-6">
            <div className="text-3xl font-bold text-accent mb-2">{t.login.restoreTitle}</div>
            <div className="text-sm text-gray-400">{t.login.restoreDesc}</div>
          </div>
          <div className="bg-void-900 rounded-xl p-6 border border-void-700">
            <p className="text-warning text-xs mb-4">Recovery uses a 20-address gap. A restored balance can be incomplete. Keep your original seed and do not use this prototype with real funds.</p>
            {!restoreMethod ? (
              <div className="space-y-3">
                <button onClick={() => setRestoreMethod('mnemonic')} className="w-full text-left rounded-lg border border-void-700 bg-void-800 hover:border-accent px-4 py-3 transition-colors">
                  <div className="text-sm font-medium text-gray-100">{t.login.restoreMnemonic}</div>
                  <div className="text-xs text-gray-400 mt-1">{t.login.restoreMnemonicDesc}</div>
                </button>
                <button onClick={() => setRestoreMethod('wif')} className="w-full text-left rounded-lg border border-void-700 bg-void-800 hover:border-accent px-4 py-3 transition-colors">
                  <div className="text-sm font-medium text-gray-100">{t.login.restoreWif}</div>
                  <div className="text-xs text-gray-400 mt-1">{t.login.restoreWifDesc}</div>
                </button>
              </div>
            ) : (
              <fieldset disabled={loading || migrating}>
                <button onClick={() => { setRestoreMethod(null); setRestoreInput(''); setRestorePassphrase(''); setRestoreDerivationMode('standard_bip39'); setError(null); setLegacyMode(false); }} className="text-xs text-gray-400 hover:text-gray-100 mb-4 transition-colors">
                  ← {t.login.restoreDesc}
                </button>
                <label className="block text-xs text-gray-400 mb-1">{t.login.restoreNameLabel}</label>
                <input type="text" value={restoreName} onChange={(e) => setRestoreName(e.target.value)} placeholder="restored_wallet" className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-3" />
                <label className="block text-xs text-gray-400 mb-1">{restoreMethod === 'mnemonic' ? t.login.restoreMnemonic : t.login.restoreWif}</label>
                <textarea value={restoreInput} onChange={(e) => setRestoreInput(e.target.value)} placeholder={restoreMethod === 'mnemonic' ? t.login.restoreMnemonicPlaceholder : t.login.restoreWifPlaceholder} className="w-full h-24 bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono focus:border-accent outline-none mb-3 resize-none" autoFocus spellCheck={false} />
                {restoreMethod === 'mnemonic' && (
                  <button
                    onClick={() => { setLegacyMode(!legacyMode); setRestorePassphrase(''); }}
                    className={`w-full rounded-lg border px-3 py-2 text-xs font-medium mb-3 transition-all ${
                      legacyMode
                        ? 'border-red-500 bg-red-500/10 text-red-400 shadow-[0_0_12px_rgba(239,68,68,0.3)]'
                        : 'border-void-700 text-gray-400 hover:border-gray-500'
                    }`}
                  >
                    {legacyMode ? '● ' : ''}{t.login.legacyToggle}
                  </button>
                )}
                {restoreMethod === 'mnemonic' && !legacyMode && <>
                  <label htmlFor="restore-bip39-passphrase" className="block text-xs text-gray-400 mb-1">BIP39 passphrase (optional)</label>
                  <input id="restore-bip39-passphrase" type="password" autoComplete="off" value={restorePassphrase} onChange={(e) => setRestorePassphrase(e.target.value)} className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-2" />
                  <p className="text-warning text-xs mb-3">This is separate from your wallet password. Every passphrase creates a different wallet; an incorrect passphrase cannot be detected.</p>
                  <fieldset className="text-xs text-gray-300 mb-3">
                    <legend className="mb-1">Passphrase derivation</legend>
                    <label className="block"><input type="radio" name="restore-derivation" checked={restoreDerivationMode === 'standard_bip39'} onChange={() => setRestoreDerivationMode('standard_bip39')} /> Standard BIP39 (recommended)</label>
                    <label className="block"><input type="radio" name="restore-derivation" checked={restoreDerivationMode === 'historical_mc'} onChange={() => setRestoreDerivationMode('historical_mc')} /> Historical MC Unicode derivation</label>
                    <p className="text-warning mt-1">Unicode passphrases can produce different wallets and addresses in these modes. Choose the original derivation.</p>
                  </fieldset>
                </>}
                <label htmlFor="restore-wallet-password" className="block text-xs text-gray-400 mb-1">{t.login.restorePasswordLabel}</label>
                <input id="restore-wallet-password" type="password" value={restorePassword} onChange={(e) => setRestorePassword(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && canRestore && handleRestore()} className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-4" />
                <button onClick={handleRestore} disabled={loading || migrating || !canRestore} className="w-full bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                  {loading || migrating ? (legacyMode ? t.login.legacyMigrating : t.login.restoring) : t.login.restoreButton}
                </button>
              </fieldset>
            )}
            {error && <div className="text-sm text-danger mt-3">{error}</div>}
          </div>
          <button disabled={loading || migrating} onClick={() => { setRestoreMethod(null); setRestoreInput(''); setRestorePassphrase(''); setRestoreDerivationMode('standard_bip39'); setError(null); setLegacyMode(false); setMode(selectedWallet ? 'login' : 'create'); }} className="w-full text-center text-xs text-gray-400 hover:text-gray-100 mt-4 transition-colors">
            {t.login.restoreCancel}
          </button>
        </div>

        {/* Legacy migration warning dialog */}
        {showLegacyWarning && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="w-full max-w-md mx-4 bg-void-900 rounded-xl border border-red-500/50 shadow-2xl">
              <div className="p-6">
                <div className="text-xl font-bold text-red-400 mb-4">{t.login.legacyWarningTitle}</div>
                <p className="text-sm text-gray-300 leading-relaxed mb-6">{t.login.legacyWarningBody}</p>
                <div className="flex gap-3">
                  <button
                    onClick={() => setShowLegacyWarning(false)}
                    className="flex-1 rounded-lg border border-void-700 bg-void-800 text-gray-400 px-4 py-2 text-sm font-medium hover:text-gray-100 transition-colors"
                  >
                    {t.login.restoreCancel}
                  </button>
                  <button
                    onClick={handleLegacyMigrate}
                    className="flex-1 rounded-lg bg-red-600 hover:bg-red-700 text-white px-4 py-2 text-sm font-medium transition-colors"
                  >
                    {t.login.legacyMigrate}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Migration progress overlay */}
        {migrating && !showLegacyWarning && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="bg-void-900 rounded-xl border border-void-700 px-8 py-6 flex flex-col items-center gap-4">
              <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
              <div className="text-sm text-gray-300">{t.login.legacyMigrating}</div>
            </div>
          </div>
        )}
      </div>
    );
  }

  // Mnemonic display step
  if (mode === 'create' && createStep === 'mnemonic' && mnemonic) {
    return (
      <div className="flex h-screen items-center justify-center bg-void-950">
        <div className="w-96 max-w-sm">
          <div className="text-center mb-6">
            <div className="text-3xl font-bold text-accent mb-2">{t.login.title}</div>
            <div className="text-sm text-gray-400">{t.login.backupSeed}</div>
          </div>

          <div className="bg-void-900 rounded-xl p-6 border border-void-700">
            <div className="bg-warning/10 border border-warning/30 rounded-lg p-3 mb-4">
              <p className="text-xs text-warning">
                {interp(t.login.backupWarning, { count: mnemonic.split(' ').length })}
              </p>
            </div>

            <div className="bg-void-950 border border-void-700 rounded-lg p-4 mb-4">
              <div className="text-xs text-gray-400 mb-2">{t.login.yourMnemonic}</div>
              <div className="text-sm text-gray-100 font-mono leading-relaxed break-words select-all">
                {mnemonic}
              </div>
            </div>

            <p className="text-xs text-gray-400 mb-3">
              {t.login.mnemonicNext}
            </p>

            <button
              onClick={() => setCreateStep('confirm')}
              className="w-full bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium transition-colors mb-2"
            >
              {t.login.writtenDown}
            </button>
            <button
              onClick={handleSkipConfirm}
              className="w-full text-xs text-gray-400 hover:text-gray-100 transition-colors"
            >
              {t.login.skipConfirm}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Mnemonic confirmation step
  if (mode === 'create' && createStep === 'confirm' && mnemonic) {
    return (
      <div className="flex h-screen items-center justify-center bg-void-950">
        <div className="w-96 max-w-sm">
          <div className="text-center mb-6">
            <div className="text-3xl font-bold text-accent mb-2">{t.login.title}</div>
            <div className="text-sm text-gray-400">{t.login.confirmSeed}</div>
          </div>

          <div className="bg-void-900 rounded-xl p-6 border border-void-700">
            <p className="text-xs text-gray-400 mb-3">
              {t.login.confirmDesc}
            </p>
            <textarea
              value={confirmInput}
              onChange={(e) => setConfirmInput(e.target.value)}
              placeholder={t.login.confirmPlaceholder}
              className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono focus:border-accent outline-none mb-3 h-24 resize-none"
              autoFocus
            />
            <button
              onClick={handleConfirmMnemonic}
              disabled={loading}
              className="w-full bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors mb-2"
            >
              {loading ? t.common.loading : t.login.confirmOpen}
            </button>
            <button
              onClick={() => setCreateStep('mnemonic')}
              className="w-full text-xs text-gray-400 hover:text-gray-100 transition-colors"
            >
              {t.login.backToSeed}
            </button>
            {error && <div className="text-sm text-danger mt-3">{error}</div>}
          </div>
        </div>
      </div>
    );
  }

  // Normal login/create form
  return (
    <div className="flex h-screen items-center justify-center bg-void-950">
      <div className="w-96 max-w-sm">
        <div className="text-center mb-8">
          <div className="text-3xl font-bold text-accent mb-2">{t.login.title}</div>
          <div className="text-sm text-gray-400">{t.login.subtitle}</div>
        </div>

        <div className="bg-void-900 rounded-xl p-6 border border-void-700">
          <div className="flex items-center gap-2 mb-4 text-xs">
            <div className="w-2 h-2 rounded-full bg-success" />
            <span className="text-success">
              {t.login.apiTokenReady}
            </span>
          </div>

          <div className="flex gap-2 mb-4">
            <button
              onClick={() => setMode('login')}
              className={`flex-1 text-sm py-2 rounded-lg transition-colors ${
                mode === 'login' ? 'bg-void-800 text-accent' : 'text-gray-400 hover:text-gray-100'
              }`}
            >
              {t.login.existingWallet}
            </button>
            <button
              onClick={() => setMode('create')}
              className={`flex-1 text-sm py-2 rounded-lg transition-colors ${
                mode === 'create' ? 'bg-void-800 text-accent' : 'text-gray-400 hover:text-gray-100'
              }`}
            >
              {t.login.newWallet}
            </button>
          </div>

          {mode === 'login' ? (
            <fieldset aria-label={t.login.existingWallet}>
              <p className="text-xs text-gray-400 mb-3">
                {selectedWallet
                  ? `${t.login.unlockSelected}`
                  : t.login.enterNamePassword}
              </p>
              {!selectedWallet && (
                <input
                  type="text"
                  value={walletName}
                  disabled={openedPath !== null}
                  onChange={(e) => setWalletName(e.target.value)}
                  placeholder={t.login.walletName}
                  className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-3"
                  autoFocus
                />
              )}
              <label htmlFor="login-wallet-password" className="block text-xs text-gray-400 mb-1">{t.login.walletPassword}</label>
              <input
                id="login-wallet-password"
                type="password"
                value={walletPassword}
                onChange={(e) => setWalletPasswordState(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !recoveryMode && hasToken && walletPassword.length >= 4 && !totpRequired && handleLogin()}
                placeholder={t.login.walletPassword}
                className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-3"
                autoFocus={!!selectedWallet}
              />
              {recoveryMode && <><p className="text-xs text-warning mb-2">Recovery disables 2FA and invalidates all recovery codes. The wallet remains locked. Enter the code exactly as shown, including case and hyphens.</p><input type="text" autoCapitalize="none" autoCorrect="off" spellCheck={false} value={recoveryCode} onChange={e => setRecoveryCode(e.target.value)} placeholder="Recovery code" className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 mb-3" /><button disabled={loading || !walletPassword || !recoveryCode} onClick={handleRecovery}>Recover 2FA access</button></>}
              {totpRequired && !recoveryMode && (
                <div className="mb-3 p-3 bg-void-950 border border-warning/30 rounded-lg">
                  <div className="text-xs text-warning mb-2">
                    {t.login.totpRequired}
                  </div>
                  <input
                    type="text"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && !recoveryMode && totpCode.length === 6 && handleLogin()}
                    placeholder={t.login.totpPlaceholder}
                    maxLength={6}
                    className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono text-center focus:border-accent outline-none"
                    autoFocus
                  />
                </div>
              )}
              <button
                onClick={handleLogin}
                disabled={loading || recoveryMode || !hasToken || (walletPassword.length < 4) || (totpRequired && totpCode.length !== 6)}
                className="w-full bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? t.login.unlocking : totpRequired ? t.login.unlock2fa : t.login.unlockWallet}
              </button>
              <button type="button" onClick={() => { setRecoveryMode(!recoveryMode); setRecoveryCode(''); setError(null); }} className="mt-3 text-sm text-accent">{recoveryMode ? 'Back to unlock' : 'Use a recovery code'}</button>
            </fieldset>
          ) : (
            <>
              <p className="text-xs text-gray-400 mb-3">
                {t.login.createDesc}
              </p>
              <input
                type="text"
                value={walletName}
                onChange={(e) => setWalletName(e.target.value)}
                placeholder={t.login.walletNamePlaceholder}
                className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-3"
                autoFocus
              />
              <input
                type="password"
                value={walletPassword}
                onChange={(e) => setWalletPasswordState(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && hasToken && walletName && walletPassword.length >= 4 && handleCreate()}
                placeholder={t.login.newPassword}
                className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-3"
              />
              <button
                onClick={handleCreate}
                disabled={loading || !hasToken || !walletName || walletPassword.length < 4}
                className="w-full bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? t.login.creating : t.login.createWallet}
              </button>
            </>
          )}

          <button
            onClick={() => { setMode('restore'); setRestoreMethod(null); setError(null); }}
            className="w-full mt-4 rounded-md border border-void-700 bg-void-950/60 px-3 py-2 text-xs text-gray-400 hover:border-accent hover:text-accent transition-colors"
          >
            {t.login.restoreWallet}
          </button>

          {recoveryNotice && <div className="text-sm text-success mt-3">{recoveryNotice}</div>}
          {error && <div className="text-sm text-danger mt-3">{error}</div>}
        </div>

        <button
          onClick={handleBack}
          className="w-full text-center text-xs text-gray-400 hover:text-gray-100 mt-4 transition-colors"
        >
          {t.login.backToWallets}
        </button>
      </div>
    </div>
  );
}
