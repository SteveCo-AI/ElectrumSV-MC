import { useEffect, useState, useRef } from 'react';
import { api, type MigrationPreview } from '../api';
import { useStore } from '../store';

function validPreview(p: MigrationPreview): boolean {
  return p?.from_version === 33 && p.to_version === 34 &&
    typeof p.confirmation_token === 'string' && p.confirmation_token.length > 0 && p.confirmation_token.length <= 1024 &&
    Number.isInteger(p.expires_in_seconds) && p.expires_in_seconds > 0 && p.expires_in_seconds <= 300 &&
    typeof p.policy?.legacy_totp_enabled === 'boolean' &&
    ['unspecified', 'login', 'tx'].includes(p.policy.legacy_wallet_scope) &&
    (p.policy.legacy_record_scope === null || ['login', 'tx'].includes(p.policy.legacy_record_scope)) &&
    p.policy.target_policy_id === (p.policy.legacy_totp_enabled ? 'totp-reauth-backup-change-delete-v1' : 'totp-off-sign-unavailable-v1') &&
    Array.isArray(p.policy.newly_require_totp) &&
    [...p.policy.newly_require_totp].sort().join(',') === (p.policy.legacy_totp_enabled ? 'backup,change_password,delete_wallet' : '');
}

export function MigrationPanel() {
  const { setMigrationGate, migrationMessage, activeWalletPath } = useStore();
  const inFlight = useRef(false);
  const [format, setFormat] = useState<33 | 34 | null>(null);
  const [statusError, setStatusError] = useState(false);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [backupPath, setBackupPath] = useState('');
  const [preview, setPreview] = useState<MigrationPreview | null>(null);
  const [accepted, setAccepted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.getWalletInfo().then(info => {
      if (active) setFormat(info.is_open === true && (info.wallet_format === 33 || info.wallet_format === 34) ? info.wallet_format : null);
    }).catch(() => { if (active) setStatusError(true); });
    return () => { active = false; };
  }, []);

  const close = () => {
    if (busy) return;
    setOpen(false); setPassword(''); setTotpCode(''); setBackupPath(''); setPreview(null); setAccepted(false); setError(null);
  };
  const prepare = async () => {
    setBusy(true); setError(null); setPreview(null); setAccepted(false);
    try {
      const result = await api.previewMigration(password, totpCode || undefined);
      if (!validPreview(result)) throw new Error('Invalid migration preview');
      setPreview(result);
    } catch (e: any) { setError(e?.message || String(e)); }
    finally { setBusy(false); }
  };
  const commit = async () => {
    if (inFlight.current || !activeWalletPath || !preview || !accepted || !backupPath || !password || busy) return;
    inFlight.current = true;
    const request = { password, totpCode: totpCode || undefined, backupPath, token: preview.confirmation_token };
    setPassword(''); setTotpCode(''); setPreview(null); setAccepted(false);
    setMigrationGate('pending');
    try {
      const result = await api.migrateWallet(request.password, request.totpCode, request.backupPath, request.token);
      if (result?.from_version !== 33 || result.to_version !== 34 || result.reopen_required !== true || typeof result.backup_path !== 'string' || !result.backup_path) {
        setMigrationGate('reopen_unknown', 'The migration response was invalid; its outcome is unknown.');
      } else {
        setMigrationGate('reopen_success', `Migration completed. Backup: ${result.backup_path}`);
      }
    } catch (e: any) {
      if (e && typeof e === 'object' && e.outcome === 'not_committed' && e.reopen_required === false && ['not_created', 'published', 'unknown'].includes(e.backup_outcome)) {
        const backup = e.backup_outcome === 'published' ? ' A backup was published; choose a new backup path before retrying.' : e.backup_outcome === 'unknown' ? ' The backup outcome is unknown; inspect the destination before retrying.' : '';
        setMigrationGate('idle', `Migration was not committed.${backup} Authenticate and request a new preview to retry.`);
      } else if (e && typeof e === 'object' && e.outcome === 'not_committed' && e.reopen_required === true && ['not_created', 'published', 'unknown'].includes(e.backup_outcome)) {
        setMigrationGate('reopen_not_committed', 'Migration was not committed. The backup may have been created; reopen the wallet and check its format.');
      } else {
        setMigrationGate('reopen_unknown', 'Migration outcome is unknown. The backup may have been created. Do not retry before reopening and checking the wallet.');
      }
    } finally { inFlight.current = false; }
  };

  return <section className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
    <h3 className="text-sm font-medium text-gray-100 mb-2">Wallet format</h3>
    <p className="text-xs text-gray-400">Format marker is unverified; migration checks the wallet before making changes.</p>
    <p className="text-sm text-gray-400">{format === null ? 'Format unknown' : format === 33 ? 'Legacy format 33' : 'Format 34'}</p>
    {statusError && <p className="text-warning text-xs">Could not read wallet format.</p>}
    {migrationMessage && <p className="text-warning text-sm mt-2">{migrationMessage}</p>}
    {format === 33 && !open && <button className="text-accent mt-3" onClick={() => { setOpen(true); setMigrationGate('idle'); }}>Review migration</button>}
    {open && <div className="mt-4 space-y-3">
      <p className="text-sm text-warning">Migration is never automatic. A validated legacy backup must be created inside the wallet data directory without replacing an existing file. The legacy backup retains weaker legacy protection and may expose the 2FA secret. Protect it separately.</p>
      <input disabled={busy} type="password" placeholder="Migration password" value={password} onChange={e => { setPassword(e.target.value); setPreview(null); setAccepted(false); }} className="w-full bg-void-800 rounded px-3 py-2" />
      <input disabled={busy} type="text" placeholder="TOTP code if enabled" value={totpCode} onChange={e => { setTotpCode(e.target.value); setPreview(null); setAccepted(false); }} className="w-full bg-void-800 rounded px-3 py-2" />
      <input disabled={busy} type="text" placeholder="New backup path inside wallet data directory" value={backupPath} onChange={e => setBackupPath(e.target.value)} className="w-full bg-void-800 rounded px-3 py-2" />
      <button disabled={busy || !password || !backupPath} onClick={prepare} className="text-accent">{busy ? 'Checking…' : 'Authenticate and review'}</button>
      {preview && <div className="text-sm space-y-2">
        <p>Current 2FA: {preview.policy.legacy_totp_enabled ? 'enabled' : 'disabled'}; wallet scope: {preview.policy.legacy_wallet_scope}; stored 2FA scope: {preview.policy.legacy_record_scope ?? 'none'}.</p>
        <p>Target policy: {preview.policy.target_policy_id}. With 2FA enabled, format 34 requires a TOTP code for unlock, signing, backup, password change and deletion. Signing requires 2FA to be enabled.</p>
        <p>Newly requiring TOTP: {preview.policy.newly_require_totp.length ? preview.policy.newly_require_totp.join(', ') : 'none'}.</p>
        <p>Recovery codes remain unchanged. The legacy backup retains its previous protection. The wallet must be reopened after migration.</p>
        <p>Old secret data may remain in SQLite free pages, WAL files, filesystem storage or backups; migration does not securely erase these remnants.</p>
        <p>Confirmation is valid for up to {preview.expires_in_seconds} seconds after preview.</p>
        <label className="block"><input type="checkbox" checked={accepted} onChange={e => setAccepted(e.target.checked)} /> I understand the policy changes and legacy backup protection.</label>
        <button disabled={busy || !activeWalletPath || !accepted || !password || !backupPath} onClick={commit} className="text-accent">Migrate wallet</button>
      </div>}
      {error && <p className="text-danger text-sm">{error}</p>}
      <button disabled={busy} onClick={close} className="text-gray-400">Cancel</button>
    </div>}
  </section>;
}
