// SecurityView — per-wallet TOTP (2FA) management + Hardware wallet toggle

import { useState, useEffect, useRef } from 'react';
import { api, isDefiniteTotpAuthFailure } from '../api';
import { useStore } from '../store';
import { MigrationPanel } from '../components/MigrationPanel';

type SetupStep = 'idle' | 'qr' | 'verify';

export function SecurityView() {
  const { requireWalletReopen } = useStore();
  const mounted = useRef(true);
  const pendingSetup = useRef(false);
  const setupOperation = useRef(false);
  const [walletPassword, setWalletPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // TOTP status
  const [totpEnabled, setTotpEnabled] = useState<boolean | null>(null);

  // Setup wizard
  const [setupStep, setSetupStep] = useState<SetupStep>('idle');
  const [setupSecret, setSetupSecret] = useState('');
  const [setupQrSvg, setSetupQrSvg] = useState<string | null>(null);
  const [setupCode, setSetupCode] = useState('');

  // Disable dialog
  const [disableCode, setDisableCode] = useState('');
  const [recoveryAuthCode, setRecoveryAuthCode] = useState('');

  // Recovery codes
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [recoveryLoading, setRecoveryLoading] = useState(false);

  // Hardware wallet
  const [hwEnabled, setHwEnabled] = useState(false);
  const [hwLoading, setHwLoading] = useState(false);

  // TOTP scope
  const [scopeEditable, setScopeEditable] = useState(false);
  const [totpScope, setTotpScope] = useState('tx');
  const [scopeLoading, setScopeLoading] = useState(false);
  const [scopeCode, setScopeCode] = useState('');
  const [scopePassword, setScopePassword] = useState('');

  // Load TOTP + HW status on mount
  useEffect(() => {
    mounted.current = true;
    loadTotpStatus();
    loadHwStatus();
    return () => { mounted.current = false; if (pendingSetup.current && !setupOperation.current) void api.cancelTotpSetup().catch(() => {}); };
  }, []);

  const loadTotpStatus = async () => {
    try {
      const result = await api.getTotpStatus();
      setTotpEnabled(result.enabled);
      setTotpScope(result.scope);
      setScopeEditable(result.scope_editable === true);
      if (result.enabled === true && pendingSetup.current) { pendingSetup.current = false; clearSetup(); }
      return result.enabled;
    } catch { setTotpEnabled(null); setError('Unable to determine 2FA status.'); return null; }
  };

  const loadHwStatus = async () => {
    try {
      const status = await api.getHardwareWalletStatus();
      setHwEnabled(status);
    } catch {
      // Ignore
    }
  };

  // Setup is pending until the authenticator code is confirmed.
  const handleSetupStart = async () => {
    setLoading(true);
    setError(null);
    setSuccess(null);
    setSetupQrSvg(null);
    try {
      const result = await api.totpEnable(walletPassword || '');
      if (!mounted.current) { await api.cancelTotpSetup(); return; }
      pendingSetup.current = true;
      setSetupSecret(result.secret_base32);
      let svg: string | null = null;
      try { svg = (await api.generateQr(result.otpauth_url, { scale: 10, quietZone: 4, ecLevel: 'M' })).svg; } catch { /* The secret can still be entered manually. */ }
      if (!mounted.current || !pendingSetup.current) return;
      setSetupQrSvg(svg); setSetupStep('qr');
    } catch (e: any) {
      setError(e?.message || String(e) || 'TOTP setup failed');
    } finally {
      setLoading(false);
    }
  };

  const clearSetup = () => {
    setSetupStep('idle'); setSetupSecret(''); setSetupQrSvg(null); setSetupCode(''); setWalletPassword('');
  };

  const handleSetupVerify = async () => {
    setLoading(true); setError(null); setupOperation.current = true;
    try {
      await api.confirmTotpSetup(walletPassword, setupCode);
      pendingSetup.current = false;
      if (!mounted.current) return;
      clearSetup();
      setTotpEnabled(null);
      if (await loadTotpStatus() === true) setSuccess('2FA enabled successfully.');
    } catch (e: any) {
      if (!mounted.current) {
        if (pendingSetup.current) await api.cancelTotpSetup().catch(() => {});
        return;
      }
      const actual = await loadTotpStatus();
      if (actual === true) { pendingSetup.current = false; clearSetup(); setSuccess('2FA is enabled.'); }
      else if (actual === false) setError(e?.message || String(e) || 'TOTP verification failed');
    } finally { setupOperation.current = false; if (mounted.current) setLoading(false); }
  };

  const handleSetupCancel = async () => {
    setLoading(true); setError(null); setupOperation.current = true;
    try {
      await api.cancelTotpSetup();
      pendingSetup.current = false;
      if (!mounted.current) return;
      clearSetup(); setTotpEnabled(null);
      await loadTotpStatus();
    } catch (e: any) {
      if (!mounted.current) return;
      const actual = await loadTotpStatus();
      if (actual === true) { pendingSetup.current = false; clearSetup(); setSuccess('2FA is enabled.'); }
      else if (actual === false) setError(e?.message || String(e) || 'Setup cancellation failed');
    } finally { setupOperation.current = false; if (mounted.current) setLoading(false); }
  };

  // ─── TOTP Disable ───
  const handleDisable = async () => {
    setLoading(true);
    setError(null); setSuccess(null);
    try {
      await api.totpDisable(walletPassword || '', disableCode);
      setTotpEnabled(false);
      setDisableCode('');
      setWalletPassword('');
      setRecoveryCodes(null);
      setSuccess('2FA disabled.');
    } catch (e: any) {
      if (isDefiniteTotpAuthFailure(e)) setError(e?.message || String(e));
      else {
        setTotpEnabled(null); setDisableCode(''); setWalletPassword(''); setRecoveryCodes(null);
        requireWalletReopen('The 2FA update outcome is unknown. Close and reopen the wallet to check its protection status before retrying.');
      }
    } finally {
      setLoading(false);
    }
  };

  // ─── Generate Recovery Codes ───
  const handleGenerateRecoveryCodes = async () => {
    setRecoveryLoading(true);
    setRecoveryCodes(null);
    setError(null);
    setSuccess(null);
    try {
      const codes = await api.generateTotpRecoveryCodes(walletPassword || '', recoveryAuthCode);
      setRecoveryCodes(codes);
      setWalletPassword(''); setRecoveryAuthCode('');
      setSuccess('Recovery codes generated. Save them now — they won\'t be shown again!');
    } catch {
      setError('Recovery code generation outcome is unknown. Previous codes may have been replaced. Authenticate and explicitly generate a new set.');
    } finally {
      setWalletPassword(''); setRecoveryAuthCode('');
      setRecoveryLoading(false);
    }
  };

  // ─── TOTP Scope change ───
  const handleScopeChange = async (newScope: string) => {
    setScopeLoading(true);
    setError(null);
    setSuccess(null);
    try {
      await api.setTotpScope(scopePassword, newScope, scopeCode || undefined);
      setTotpScope(newScope);
      setScopeCode('');
      setScopePassword('');
      setSuccess(`TOTP scope changed to: ${newScope === 'tx' ? 'Every transaction' : 'Login only'}`);
    } catch (e: any) {
      setError(e.message || 'Failed to change TOTP scope');
    } finally {
      setScopeLoading(false);
    }
  };

  // ─── Hardware wallet toggle ───
  const handleHwToggle = async () => {
    setHwLoading(true);
    setError(null);
    try {
      await api.setHardwareWalletEnabled(!hwEnabled);
      setHwEnabled(!hwEnabled);
      setSuccess(`Hardware wallet ${!hwEnabled ? 'enabled' : 'disabled'}.`);
    } catch (e: any) {
      setError(e.message || 'Hardware wallet toggle failed');
    } finally {
      setHwLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h2 className="text-xl font-semibold text-accent mb-6">Security Settings</h2>

      <MigrationPanel />

      {/* Status card */}
      <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm text-gray-400">Current Protection</span>
          <span className={`text-sm font-medium ${totpEnabled ? 'text-success' : 'text-warning'}`}>
            {totpEnabled === null ? '● 2FA status unknown' : totpEnabled ? '● Password + 2FA (TX)' : '● Password only'}
          </span>
        </div>
        <p className="text-xs text-gray-400">
          {totpEnabled === null ? '2FA status is unavailable; check wallet access and retry.' : totpEnabled
            ? 'Your wallet is protected with two-factor authentication. A TOTP code is required for every transaction.'
            : 'Your wallet uses password-only protection. Consider enabling 2FA for additional security.'}
        </p>
      </div>

      {totpEnabled === null && <button disabled={loading} onClick={() => void loadTotpStatus()} className="text-sm text-accent mb-4">Check 2FA status</button>}

      {/* Hardware Wallet card */}
      <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-100 mb-1">Hardware Wallet</h3>
            <p className="text-xs text-gray-400">
              {hwEnabled
                ? 'Hardware wallet signing is enabled. Transactions will be signed by your connected device.'
                : 'Software-only signing. Enable to use a hardware wallet for signing transactions.'}
            </p>
          </div>
          <button
            onClick={handleHwToggle}
            disabled={hwLoading}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              hwEnabled ? 'bg-accent' : 'bg-void-700'
            } disabled:opacity-50`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                hwEnabled ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>
      </div>

      {/* TOTP Scope — shown when TOTP is enabled */}
      {totpEnabled && (
        <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
          <h3 className="text-sm font-medium text-gray-100 mb-3">TOTP Scope</h3>
          <p className="text-xs text-gray-400 mb-3">
            Current scope: <span className="text-gray-100 font-medium">
              {totpScope === 'tx' ? 'Every transaction (max security)' : 'Login only'}
            </span>
            <br />
            {totpScope === 'tx'
              ? 'A TOTP code is required for every transaction AND at login.'
              : 'A TOTP code is required to sign transactions regardless of this stored setting.'}
          </p>
          {!scopeEditable && <p className="text-xs text-warning mb-3">Changing the scope is unavailable for this wallet.</p>}
          <div className="space-y-2">
            <input
              disabled={!scopeEditable}
              type="password"
              value={scopePassword}
              onChange={(e) => setScopePassword(e.target.value)}
              placeholder="Wallet password"
              className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
            />
            {totpScope === 'tx' && (
              <input
                type="text"
                value={scopeCode}
                onChange={(e) => setScopeCode(e.target.value)}
                placeholder="Current TOTP code (required to lower scope)"
                maxLength={6}
                className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono text-center focus:border-accent outline-none"
              />
            )}
            <div className="flex gap-2">
              {totpScope === 'tx' && (
                <button
                  onClick={() => handleScopeChange('login')}
                  disabled={!scopeEditable || scopeLoading || !scopePassword}
                  className="flex-1 bg-void-800 hover:bg-void-700 text-gray-100 rounded-lg px-3 py-2 text-xs font-medium border border-void-700 disabled:opacity-50 transition-colors"
                >
                  {scopeLoading ? '…' : 'Lower to Login-only'}
                </button>
              )}
              {totpScope === 'login' && (
                <button
                  onClick={() => handleScopeChange('tx')}
                  disabled={!scopeEditable || scopeLoading || !scopePassword}
                  className="flex-1 bg-accent hover:bg-accent-hover text-white rounded-lg px-3 py-2 text-xs font-medium disabled:opacity-50 transition-colors"
                >
                  {scopeLoading ? '…' : 'Raise to Every-TX'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {error && <div className="text-sm text-danger mb-4 p-3 bg-danger/10 rounded-lg">{error}</div>}
      {success && <div className="text-sm text-success mb-4 p-3 bg-success/10 rounded-lg">{success}</div>}

      {/* Enable 2FA — Setup Wizard */}
      {totpEnabled === false && setupStep === 'idle' && (
        <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
          <h3 className="text-sm font-medium text-gray-100 mb-3">Enable 2FA (TOTP)</h3>
          <p className="text-xs text-gray-400 mb-4">
            Add an extra layer of security with your authenticator app
            (Google Authenticator, Authy, FreeOTP). A TOTP code will be
            required for every transaction you sign.
          </p>
          <input type="password" value={walletPassword} onChange={e => setWalletPassword(e.target.value)} placeholder="Wallet password" className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm mb-3" />
          <button
            onClick={handleSetupStart}
            disabled={loading || !walletPassword}
            className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
          >
            {loading ? 'Starting…' : 'Set up 2FA'}
          </button>
          {!walletPassword && (
            <p className="text-xs text-warning mt-2">Wallet password required</p>
          )}
        </div>
      )}

      {/* Setup — QR code step */}
      {setupStep === 'qr' && (
        <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
          <h3 className="text-sm font-medium text-gray-100 mb-3">Scan QR Code</h3>
          <p className="text-xs text-gray-400 mb-3">
            Scan with your 2FA app, or enter the secret manually.
          </p>
          {setupQrSvg && (
            <div className="flex justify-center mb-4">
              <div className="w-48 h-48 rounded-lg bg-white p-1" dangerouslySetInnerHTML={{ __html: setupQrSvg }} />
            </div>
          )}
          <div className="mb-3">
            <span className="text-xs text-gray-400">Secret: </span>
            <span className="text-xs font-mono text-gray-300 select-all">{setupSecret}</span>
          </div>

          {/* Code verification */}
          <input
            type="text"
            value={setupCode}
            onChange={(e) => setSetupCode(e.target.value)}
            placeholder="Enter 6-digit code from your app"
            maxLength={6}
            className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono text-center focus:border-accent outline-none mb-3"
          />
          <div className="flex gap-2">
            <button
              onClick={handleSetupVerify}
              disabled={loading || totpEnabled !== false || setupCode.length !== 6}
              className="flex-1 bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
            >
              {loading ? 'Verifying…' : 'Verify & Enable'}
            </button>
            <button
              onClick={handleSetupCancel}
              disabled={loading || totpEnabled === null}
              className="text-sm text-gray-400 hover:text-gray-100 px-4 py-2"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Disable 2FA */}
      {totpEnabled && (
        <div role="group" aria-labelledby="disable-2fa-heading" className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
          <h3 id="disable-2fa-heading" className="text-sm font-medium text-gray-100 mb-3">Disable 2FA</h3>
          <p className="text-xs text-gray-400 mb-3">
            Enter your current TOTP code to verify, then disable 2FA.
          </p>
          <label htmlFor="disable-2fa-password" className="block text-xs text-gray-400 mb-1">Wallet password for disabling 2FA</label>
          <input id="disable-2fa-password" type="password" value={walletPassword} onChange={e => setWalletPassword(e.target.value)} placeholder="Wallet password" className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm mb-3" />
          <label htmlFor="disable-2fa-code" className="block text-xs text-gray-400 mb-1">Authenticator code for disabling 2FA</label>
          <input
            id="disable-2fa-code"
            type="text"
            value={disableCode}
            onChange={(e) => setDisableCode(e.target.value)}
            placeholder="Current 6-digit TOTP code"
            maxLength={6}
            className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono text-center focus:border-accent outline-none mb-3"
          />
          <button
            onClick={handleDisable}
            disabled={loading || !walletPassword || disableCode.length !== 6}
            className="bg-void-800 text-danger hover:bg-void-700 border border-danger/30 rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
          >
            {loading ? 'Disabling…' : 'Disable 2FA'}
          </button>
        </div>
      )}

      {/* Recovery Codes — shown when TOTP is enabled */}
      {totpEnabled && (
        <div role="group" aria-labelledby="recovery-codes-heading" className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
          <h3 id="recovery-codes-heading" className="text-sm font-medium text-gray-100 mb-3">Recovery Codes</h3>
          <p className="text-xs text-gray-400 mb-4">
            Generate one-time recovery codes to regain access if you lose your
            authenticator device. Store them in a safe place — each code can only
            be used once. Recovering access from the login screen disables 2FA and all recovery codes. After unlocking with your password, set up 2FA again before signing transactions.
          </p>

          <p className="text-xs text-warning mb-3">Generating a new set replaces all previous recovery codes.</p>
          <label htmlFor="recovery-codes-password" className="block text-xs text-gray-400 mb-1">Wallet password for recovery codes</label>
          <input id="recovery-codes-password" type="password" value={walletPassword} onChange={e => setWalletPassword(e.target.value)} placeholder="Wallet password" className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm mb-3" />
          <label htmlFor="recovery-codes-totp" className="block text-xs text-gray-400 mb-1">Authenticator code for recovery codes</label>
          <input id="recovery-codes-totp" type="text" value={recoveryAuthCode} onChange={(e) => setRecoveryAuthCode(e.target.value)} placeholder="Current 6-digit TOTP code" maxLength={6} className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 mb-3" />
          {/* Generate button */}
          {!recoveryCodes && (
            <button
              onClick={handleGenerateRecoveryCodes}
              disabled={recoveryLoading || !walletPassword || recoveryAuthCode.length !== 6}
              className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
            >
              {recoveryLoading ? 'Generating…' : 'Generate Recovery Codes'}
            </button>
          )}

          {/* Display codes one-time */}
          {recoveryCodes && (
            <div>
              <div className="mb-3 p-3 bg-warning/10 rounded-lg border border-warning/30">
                <p className="text-xs text-warning font-medium">
                  ⚠ Save these codes now — they will not be shown again!
                </p>
              </div>
              <div className="grid grid-cols-1 gap-2 mb-4 min-w-0">
                {recoveryCodes.map((code, idx) => (
                  <div
                    key={idx}
                    className="bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm font-mono text-gray-100 select-all whitespace-nowrap overflow-x-auto min-w-0"
                  >
                    {code}
                  </div>
                ))}
              </div>
              <button
                onClick={() => setRecoveryCodes(null)}
                className="text-sm text-gray-400 hover:text-gray-100 transition-colors"
              >
                I've saved my codes — dismiss
              </button>
            </div>
          )}
        </div>
      )}

    </div>
  );
}