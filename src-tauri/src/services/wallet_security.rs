//! Shared authenticated operations for versioned wallet secrets.
//! Callers hold `wallet_operation` for the entire operation.
use crate::{security::{envelope::WalletContext, wallet_bundle::{self, WalletBundle}}, state::AppState};
use std::sync::Arc;
use tokio::sync::MutexGuard;
use zeroize::Zeroize;

pub(crate) struct Authenticated {
    instance: Arc<()>,
    generation: u64,
    context: WalletContext,
    old_envelope: Vec<u8>,
    bundle: WalletBundle,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredWallet {
    pub format: String,
    pub wallet_id: [u8; 16],
    pub xpub: String,
    pub derivation: String,
    pub envelope: String,
}
impl StoredWallet {
    pub fn encode(context: &WalletContext, envelope: &[u8]) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&Self { format: "wallet-envelope-v1".into(), wallet_id: context.wallet_id, xpub: context.xpub.clone(), derivation: context.derivation.clone(), envelope: std::str::from_utf8(envelope).map_err(|_| "invalid wallet envelope")?.into() }).map_err(|_| "invalid wallet record".into())
    }
}
fn check_totp(bundle: &WalletBundle, code: Option<&str>) -> Result<(), String> {
    if let Some(policy) = &bundle.totp {
        let code = code.ok_or("TOTP code required")?;
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(&policy.secret, "ElectrumSV-Mc", "wallet").map_err(|_| "invalid TOTP policy")?;
        if !totp.verify_current(code).map_err(|_| "TOTP verification failed")? { return Err("invalid TOTP code".into()); }
    }
    Ok(())
}
/// Returns None only for legacy wallets; callers must apply the legacy contract.
pub(crate) async fn authenticate_locked(state: &AppState, _guard: &MutexGuard<'_, ()>, password: &str, code: Option<&str>, require_totp: bool) -> Result<Option<Authenticated>, String> {
    let (instance, generation, context, envelope) = {
        let active = state.active_wallet.lock().unwrap();
        let active = active.as_ref().ok_or("no wallet is currently open")?;
        let Some(secure) = &active.secure_wallet else { return Ok(None) };
        if secure.needs_reopen { return Err("reopen wallet after interrupted update".into()); }
        (active.instance_id.clone(), secure.generation, secure.context.clone(), secure.envelope.clone())
    };
    let bundle = wallet_bundle::open(password, &context, &envelope).await?;
    if require_totp { check_totp(&bundle, code)?; }
    let active = state.active_wallet.lock().unwrap();
    let active = active.as_ref().ok_or("wallet changed")?;
    let secure = active.secure_wallet.as_ref().ok_or("wallet changed")?;
    if !Arc::ptr_eq(&instance, &active.instance_id) || generation != secure.generation || envelope != secure.envelope { return Err("wallet changed".into()); }
    Ok(Some(Authenticated { instance, generation, context, old_envelope: envelope, bundle }))
}
impl Authenticated {
    pub(crate) fn mnemonic(&self) -> &str { &self.bundle.mnemonic }
    pub(crate) fn xprv(&self) -> &str { &self.bundle.xprv }
    pub(crate) fn totp_enabled(&self) -> bool { self.bundle.totp.is_some() }
    #[cfg(test)]
    pub(crate) fn has_recovery_code(&self, code: &str) -> bool {
        let hash = crate::security::totp::hash_recovery_code(code);
        self.bundle.totp.as_ref().is_some_and(|p| p.recovery_hashes.contains(&hash))
    }
    #[cfg(test)]
    pub(crate) fn recovery_count(&self) -> usize { self.bundle.totp.as_ref().map_or(0, |p| p.recovery_hashes.len()) }
}
/// Returns None for legacy. A locked secure wallet has unknown TOTP status.
pub(crate) fn status_locked(state: &AppState, _guard: &MutexGuard<'_, ()>) -> Result<Option<Option<bool>>, String> {
    let active = state.active_wallet.lock().unwrap();
    let active = active.as_ref().ok_or("no wallet is currently open")?;
    Ok(active.secure_wallet.as_ref().map(|s| s.bundle.as_ref().map(|b| b.totp.is_some())))
}
pub(crate) fn verify_sign_totp_locked(state: &AppState, _guard: &MutexGuard<'_, ()>, code: &str) -> Result<Option<()>, String> {
    let active = state.active_wallet.lock().unwrap();
    let active = active.as_ref().ok_or("no wallet is currently open")?;
    let Some(secure) = &active.secure_wallet else { return Ok(None) };
    let bundle = secure.bundle.as_ref().ok_or("wallet is locked")?;
    if bundle.totp.is_none() { return Err("TOTP is not enabled".into()); }
    check_totp(bundle, Some(code))?;
    Ok(Some(()))
}

/// Atomically replaces exactly the record authenticated above; no network work is performed.
pub(crate) async fn rotate_password_locked(state: &AppState, _guard: &MutexGuard<'_, ()>, auth: Authenticated, new_password: &str) -> Result<(), String> {
    let new_envelope = wallet_bundle::seal(new_password, &auth.context, &auth.bundle).await?;
    let old = StoredWallet::encode(&auth.context, &auth.old_envelope)?;
    let new = StoredWallet::encode(&auth.context, &new_envelope)?;
    let (pool, was_unlocked) = {
        let active = state.active_wallet.lock().unwrap();
        let active = active.as_ref().ok_or("wallet changed")?;
        let secure = active.secure_wallet.as_ref().ok_or("wallet changed")?;
        if !Arc::ptr_eq(&auth.instance, &active.instance_id) || secure.generation != auth.generation || secure.envelope != auth.old_envelope { return Err("wallet changed".into()); }
        (active.db_pool.clone(), secure.bundle.is_some())
    };
    let mut tx = pool.begin().await.map_err(|_| "wallet update failed")?;
    let result = sqlx::query("UPDATE MasterKeys SET derivation_data=?, date_updated=? WHERE derivation_data=?")
        .bind(new).bind(chrono::Utc::now().timestamp()).bind(old).execute(&mut *tx).await.map_err(|_| "wallet update failed")?;
    if result.rows_affected() != 1 { return Err("wallet changed".into()); }
    // A cancelled commit can have an unknown result: invalidate the secret session first.
    #[cfg(test)]
    let mut barrier;
    {
        let mut active = state.active_wallet.lock().unwrap();
        let active = active.as_mut().ok_or("wallet changed")?;
        #[cfg(test)] { barrier = active.commit_barrier.take(); }
        let secure = active.secure_wallet.as_mut().ok_or("wallet changed")?;
        if !Arc::ptr_eq(&auth.instance, &active.instance_id) || secure.generation != auth.generation { return Err("wallet changed".into()); }
        secure.bundle = None; secure.pending_totp = None; secure.needs_reopen = true;
        if let Some(xprv) = &mut active.decrypted_xprv { xprv.zeroize(); }
        active.decrypted_xprv = None;
    }
    #[cfg(test)]
    if barrier.as_ref().is_some_and(|b| !b.after_commit) {
        let b = barrier.take().unwrap(); let _ = b.started.send(()); let _ = b.resume.await;
    }
    tx.commit().await.map_err(|_| "wallet update failed; reopen wallet")?;
    #[cfg(test)]
    if let Some(b) = barrier.take() { let _ = b.started.send(()); let _ = b.resume.await; }
    let mut active = state.active_wallet.lock().unwrap();
    let active = active.as_mut().ok_or("wallet changed")?;
    let secure = active.secure_wallet.as_mut().ok_or("wallet changed")?;
    if !Arc::ptr_eq(&auth.instance, &active.instance_id) || secure.generation != auth.generation { return Err("wallet changed".into()); }
    secure.envelope = new_envelope; secure.generation += 1; secure.needs_reopen = false;
    if was_unlocked { active.decrypted_xprv = Some(auth.bundle.xprv.clone()); secure.bundle = Some(auth.bundle); }
    Ok(())
}

pub(crate) async fn begin_totp_locked(state: &AppState, guard: &MutexGuard<'_, ()>, password: &str) -> Result<Option<crate::commands::wallet::EnableTotpResult>, String> {
    use rand::RngCore;
    let Some(auth) = authenticate_locked(state, guard, password, None, false).await? else { return legacy_begin_locked(state, guard, password).await.map(Some) };
    if auth.bundle.totp.is_some() { return Err("TOTP is already enabled".into()); }
    let mut secret = zeroize::Zeroizing::new(vec![0u8; 20]);
    rand::rngs::OsRng.try_fill_bytes(&mut secret).map_err(|_| "random generation failed")?;
    let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").map_err(|_| "TOTP setup failed")?;
    let result = crate::commands::wallet::EnableTotpResult { secret_base32: totp.secret_base32(), otpauth_url: totp.otpauth_url() };
    let mut active = state.active_wallet.lock().unwrap();
    let active = active.as_mut().ok_or("wallet changed")?;
    let secure = active.secure_wallet.as_mut().ok_or("wallet changed")?;
    if !Arc::ptr_eq(&auth.instance, &active.instance_id) || secure.generation != auth.generation || secure.needs_reopen { return Err("wallet changed".into()); }
    secure.pending_totp = Some(crate::state::PendingTotp { secret, expires: std::time::Instant::now() + std::time::Duration::from_secs(300), generation: auth.generation });
    Ok(Some(result))
}

pub(crate) fn cancel_totp_locked(state: &AppState, _guard: &MutexGuard<'_, ()>) -> Result<Option<()>, String> {
    let mut active = state.active_wallet.lock().unwrap();
    let active = active.as_mut().ok_or("no wallet is currently open")?;
    let Some(secure) = active.secure_wallet.as_mut() else { active.legacy_pending_totp = None; return Ok(Some(())) };
    secure.pending_totp = None;
    Ok(Some(()))
}

pub(crate) async fn confirm_totp_locked(state: &AppState, guard: &MutexGuard<'_, ()>, password: &str, code: &str) -> Result<Option<()>, String> {
    let Some(mut auth) = authenticate_locked(state, guard, password, None, false).await? else { return legacy_confirm_locked(state, guard, password, code).await.map(Some) };
    if auth.bundle.totp.is_some() { return Err("TOTP is already enabled".into()); }
    let secret = {
        let mut active = state.active_wallet.lock().unwrap();
        let active = active.as_mut().ok_or("wallet changed")?;
        let secure = active.secure_wallet.as_mut().ok_or("wallet changed")?;
        if !Arc::ptr_eq(&auth.instance, &active.instance_id) || secure.generation != auth.generation { return Err("wallet changed".into()); }
        let pending = secure.pending_totp.as_ref().ok_or("TOTP setup is not pending")?;
        if pending.expires <= std::time::Instant::now() || pending.generation != auth.generation { secure.pending_totp = None; return Err("TOTP setup expired".into()); }
        pending.secret.clone()
    };
    let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").map_err(|_| "invalid TOTP setup")?;
    if !totp.verify_current(code).map_err(|_| "TOTP verification failed")? { return Err("invalid TOTP code".into()); }
    auth.bundle.totp = Some(crate::security::wallet_bundle::TotpPolicy { secret: secret.to_vec(), recovery_hashes: Vec::new() });
    rotate_password_locked(state, guard, auth, password).await?;
    Ok(Some(()))
}

pub(crate) async fn recover_totp_locked(state: &AppState, guard: &MutexGuard<'_, ()>, password: &str, recovery_code: &str) -> Result<Option<()>, String> {
    let Some(mut auth) = authenticate_locked(state, guard, password, None, false).await? else { return legacy_recover_locked(state, guard, password, recovery_code).await.map(Some) };
    let policy = auth.bundle.totp.as_ref().ok_or("TOTP is not enabled")?;
    let hash = crate::security::totp::hash_recovery_code(recovery_code);
    if !policy.recovery_hashes.iter().any(|candidate| candidate == &hash) { return Err("invalid recovery code".into()); }
    auth.bundle.totp = None;
    rotate_password_locked(state, guard, auth, password).await?;
    let mut active = state.active_wallet.lock().unwrap();
    let active = active.as_mut().ok_or("wallet changed")?;
    if let Some(secure) = &mut active.secure_wallet { secure.bundle = None; }
    if let Some(xprv) = &mut active.decrypted_xprv { xprv.zeroize(); }
    active.decrypted_xprv = None;
    Ok(Some(()))
}

pub(crate) async fn unlock_locked(state: &AppState, guard: &MutexGuard<'_, ()>, password: &str, code: Option<&str>) -> Result<Option<()>, String> {
    let Some(auth) = authenticate_locked(state, guard, password, code, true).await? else { return Ok(None) };
    let mut active = state.active_wallet.lock().unwrap();
    let active = active.as_mut().ok_or("wallet changed")?;
    let secure = active.secure_wallet.as_mut().ok_or("wallet changed")?;
    if !Arc::ptr_eq(&auth.instance, &active.instance_id) || secure.generation != auth.generation || secure.needs_reopen { return Err("wallet changed".into()); }
    if secure.bundle.is_some() { return Err("wallet is already unlocked".into()); }
    active.decrypted_xprv = Some(auth.bundle.xprv.clone());
    secure.bundle = Some(auth.bundle);
    Ok(Some(()))
}

pub(crate) async fn disable_totp_locked(state: &AppState, guard: &MutexGuard<'_, ()>, password: &str, code: &str) -> Result<Option<()>, String> {
    let Some(mut auth) = authenticate_locked(state, guard, password, Some(code), true).await? else { return Ok(None) };
    if auth.bundle.totp.is_none() { return Err("TOTP is not enabled".into()); }
    auth.bundle.totp = None;
    rotate_password_locked(state, guard, auth, password).await?;
    Ok(Some(()))
}

pub(crate) async fn generate_recovery_codes_locked_with(state: &AppState, guard: &MutexGuard<'_, ()>, password: &str, code: &str, generate: impl FnOnce() -> Result<Vec<String>, crate::security::totp::TotpError> + Send) -> Result<Option<Vec<String>>, String> {
    let Some(mut auth) = authenticate_locked(state, guard, password, Some(code), true).await? else { return Ok(None) };
    let policy = auth.bundle.totp.as_mut().ok_or("TOTP is not enabled")?;
    let codes = zeroize::Zeroizing::new(generate().map_err(|_| "recovery code generation failed")?);
    policy.recovery_hashes = codes.iter().map(|code| crate::security::totp::hash_recovery_code(code)).collect();
    rotate_password_locked(state, guard, auth, password).await?;
    Ok(Some(codes.to_vec()))
}

/// Returns legacy as None and locked secure status as Some(None).
pub(crate) fn recovery_count_locked(state: &AppState, _guard: &MutexGuard<'_, ()>) -> Result<Option<Option<i64>>, String> {
    let active = state.active_wallet.lock().unwrap();
    let active = active.as_ref().ok_or("no wallet is currently open")?;
    Ok(active.secure_wallet.as_ref().map(|secure| secure.bundle.as_ref().map(|bundle| bundle.totp.as_ref().map_or(0, |policy| policy.recovery_hashes.len() as i64))))
}

pub(crate) fn invalidate_legacy_pending_locked(state: &AppState, _guard: &MutexGuard<'_, ()>) {
    if let Some(active) = state.active_wallet.lock().unwrap().as_mut() { active.legacy_pending_totp = None; }
}

async fn legacy_begin_locked(state: &AppState, _guard: &MutexGuard<'_, ()>, password: &str) -> Result<crate::commands::wallet::EnableTotpResult, String> {
    use rand::RngCore;
    let (instance, pool, ks) = {
        let active = state.active_wallet.lock().unwrap();
        let a = active.as_ref().ok_or("no wallet is currently open")?;
        (a.instance_id.clone(), a.db_pool.clone(), a.keystore_data.clone())
    };
    if !crate::core::keystore::verify_password(&ks, password) { return Err("incorrect password".into()); }
    if crate::db::repositories::is_totp_enabled(&pool).await.map_err(|_| "TOTP status unavailable")? { return Err("TOTP is already enabled".into()); }
    let mut secret = zeroize::Zeroizing::new(vec![0; 20]);
    rand::rngs::OsRng.try_fill_bytes(&mut secret).map_err(|_| "random generation failed")?;
    let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").map_err(|_| "TOTP setup failed")?;
    let result = crate::commands::wallet::EnableTotpResult { secret_base32: totp.secret_base32(), otpauth_url: totp.otpauth_url() };
    let mut active = state.active_wallet.lock().unwrap();
    let a = active.as_mut().ok_or("wallet changed")?;
    if !Arc::ptr_eq(&instance, &a.instance_id) || a.secure_wallet.is_some() { return Err("wallet changed".into()); }
    a.legacy_pending_totp = Some(crate::state::PendingTotp { secret, expires: std::time::Instant::now() + std::time::Duration::from_secs(300), generation: 0 });
    Ok(result)
}

async fn legacy_confirm_locked(state: &AppState, _guard: &MutexGuard<'_, ()>, password: &str, code: &str) -> Result<(), String> {
    let (instance, pool, ks, secret) = {
        let mut active = state.active_wallet.lock().unwrap();
        let a = active.as_mut().ok_or("no wallet is currently open")?;
        let pending = a.legacy_pending_totp.as_ref().ok_or("TOTP setup is not pending")?;
        if pending.expires <= std::time::Instant::now() { a.legacy_pending_totp = None; return Err("TOTP setup expired".into()); }
        (a.instance_id.clone(), a.db_pool.clone(), a.keystore_data.clone(), pending.secret.clone())
    };
    if !crate::core::keystore::verify_password(&ks, password) { return Err("incorrect password".into()); }
    let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").map_err(|_| "invalid TOTP setup")?;
    if !totp.verify_current(code).map_err(|_| "TOTP verification failed")? { return Err("invalid TOTP code".into()); }
    let mut tx = pool.begin().await.map_err(|_| "TOTP update failed")?;
    let now = chrono::Utc::now().timestamp();
    sqlx::query("INSERT INTO TotpSecrets(id,secret_encrypted,nonce,scope,date_created,date_updated) VALUES(1,?,'','login',?,?)").bind(&*secret).bind(now).bind(now).execute(&mut *tx).await.map_err(|_| "TOTP already enabled or update failed")?;
    sqlx::query("DELETE FROM TotpRecoveryCodes").execute(&mut *tx).await.map_err(|_| "TOTP update failed")?;
    #[cfg(test)]
    let mut barrier;
    let mut prior_session = {
        let mut active = state.active_wallet.lock().unwrap();
        let a = active.as_mut().ok_or("wallet changed")?;
        if !Arc::ptr_eq(&instance, &a.instance_id) { return Err("wallet changed".into()); }
        a.legacy_pending_totp = None;
        #[cfg(test)] { barrier = a.commit_barrier.take(); }
        zeroize::Zeroizing::new(a.decrypted_xprv.take())
    };
    #[cfg(test)]
    if barrier.as_ref().is_some_and(|b| !b.after_commit) {
        let b = barrier.take().unwrap(); let _ = b.started.send(()); let _ = b.resume.await;
    }
    tx.commit().await.map_err(|_| "TOTP update failed; reopen wallet")?;
    #[cfg(test)]
    if let Some(b) = barrier.take() { let _ = b.started.send(()); let _ = b.resume.await; }
    let mut active = state.active_wallet.lock().unwrap();
    let a = active.as_mut().ok_or("wallet changed")?;
    if !Arc::ptr_eq(&instance, &a.instance_id) { return Err("wallet changed".into()); }
    a.decrypted_xprv = prior_session.take();
    Ok(())
}
async fn legacy_recover_locked(state: &AppState, _guard: &MutexGuard<'_, ()>, password: &str, recovery_code: &str) -> Result<(), String> {
    let ks = {
        let active = state.active_wallet.lock().unwrap();
        let a = active.as_ref().ok_or("no wallet is currently open")?;
        a.keystore_data.clone()
    };
    if !crate::core::keystore::verify_password(&ks, password) { return Err("incorrect password".into()); }
    if !legacy_recover_code_locked(state, _guard, recovery_code).await? { return Err("invalid recovery code".into()); }
    Ok(())
}

pub(crate) async fn legacy_recover_code_locked(state: &AppState, _guard: &MutexGuard<'_, ()>, recovery_code: &str) -> Result<bool, String> {
    let (pool, instance) = {
        let active = state.active_wallet.lock().unwrap();
        let a = active.as_ref().ok_or("no wallet is currently open")?;
        if a.secure_wallet.is_some() { return Err("password required for secure recovery".into()); }
        (a.db_pool.clone(), a.instance_id.clone())
    };
    let hash = crate::security::totp::hash_recovery_code(recovery_code);
    let mut tx = pool.begin().await.map_err(|_| "TOTP recovery failed")?;
    if !crate::db::repositories::recover_totp_in_transaction(&mut tx, &hash).await.map_err(|_| "TOTP recovery failed")? { return Ok(false); }
    #[cfg(test)]
    let mut barrier;
    {
        let mut active = state.active_wallet.lock().unwrap();
        let a = active.as_mut().ok_or("wallet changed")?;
        if !Arc::ptr_eq(&instance, &a.instance_id) || a.secure_wallet.is_some() { return Err("wallet changed".into()); }
        #[cfg(test)] { barrier = a.commit_barrier.take(); }
        a.legacy_pending_totp = None;
        if let Some(xprv) = &mut a.decrypted_xprv { xprv.zeroize(); }
        a.decrypted_xprv = None;
    }
    #[cfg(test)]
    if barrier.as_ref().is_some_and(|b| !b.after_commit) { let b = barrier.take().unwrap(); let _ = b.started.send(()); let _ = b.resume.await; }
    tx.commit().await.map_err(|_| "TOTP recovery outcome unknown; reopen wallet")?;
    #[cfg(test)]
    if let Some(b) = barrier.take() { let _ = b.started.send(()); let _ = b.resume.await; }
    Ok(true)
}
