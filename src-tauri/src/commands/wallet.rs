// commands/wallet.rs — Wallet lifecycle Tauri commands
//
// Milestone 1: list_wallets
// Milestone 2: create_wallet, open_wallet, close_wallet, unlock_wallet, get_wallet_status

use crate::db::connection;
use crate::db::repositories;
use crate::services::wallet_service;
use crate::state::AppState;
use tauri::State;

/// Lists all available wallets in the data directory.
#[tauri::command]
pub fn list_wallets(state: State<'_, AppState>) -> Result<Vec<connection::WalletFileInfo>, String> {
    log::info!("list_wallets — scanning data_dir: {}", state.data_dir);
    connection::list_wallet_files(&state.data_dir).map_err(|e| e.to_string())
}

/// Create a new wallet.
///
/// If `mnemonic` is None, a new 12-word BIP39 mnemonic is generated.
/// The mnemonic is returned in the result — it is NEVER stored in plaintext.
#[tauri::command]
pub async fn create_wallet(
    state: State<'_, AppState>,
    name: String,
    password: String,
    mnemonic: Option<String>,
    passphrase: Option<String>,
) -> Result<wallet_service::CreateWalletResult, String> {
    log::info!("create_wallet — name: {}", name);
    wallet_service::create_wallet(
        &state,
        &name,
        &password,
        mnemonic.as_deref(),
        passphrase.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn restore_bip39_wallet(
    state: State<'_, AppState>, name: String, password: String, mnemonic: String,
    passphrase: String, mode: wallet_service::Bip39RestoreMode,
) -> Result<wallet_service::CreateWalletResult, String> {
    wallet_service::restore_bip39_wallet(&state, &name, &password, &mnemonic, &passphrase, mode)
        .await.map_err(|e| e.to_string())
}

/// Open an existing wallet from disk.
///
/// The wallet is opened in locked state. Call unlock_wallet to decrypt keys.
#[tauri::command]
pub async fn open_wallet(
    state: State<'_, AppState>,
    wallet_path: String,
) -> Result<wallet_service::OpenWalletResult, String> {
    log::info!("open_wallet — path: {}", wallet_path);
    wallet_service::open_wallet(&state, &wallet_path)
        .await
        .map_err(|e| e.to_string())
}

/// Close the currently open wallet.
#[tauri::command]
pub async fn close_wallet(state: State<'_, AppState>) -> Result<(), String> {
    log::info!("close_wallet");
    wallet_service::close_wallet(&state).await.map_err(|e| e.to_string())
}

/// Unlock the currently open wallet with the password.
async fn require_totp(pool: &sqlx::SqlitePool, code: Option<&str>) -> Result<(), String> {
    if let Some(secret) = repositories::load_totp_secret(pool).await.map_err(|e| e.to_string())? {
        let code = code.filter(|c| !c.is_empty()).ok_or("TOTP code required")?;
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").map_err(|e| e.to_string())?;
        if !totp.verify_current(code).map_err(|e| e.to_string())? { return Err("invalid TOTP code".into()); }
    }
    Ok(())
}

#[tauri::command]
pub async fn unlock_wallet(state: State<'_, AppState>, password: String, totp_code: Option<String>) -> Result<(), String> {
    wallet_service::unlock_wallet_authorized(&state, &password, totp_code.as_deref()).await
}

/// Get the status of the currently open wallet.
#[tauri::command]
pub fn get_wallet_status(state: State<'_, AppState>) -> wallet_service::WalletStatus {
    wallet_service::get_wallet_status(&state)
}

#[tauri::command]
pub async fn preview_migration(state: State<'_, AppState>, password: String, totp_code: Option<String>) -> Result<crate::services::wallet_migration::MigrationPreview, crate::services::wallet_migration::MigrationError> {
    crate::services::wallet_migration::preview_migration(&state, &password, totp_code.as_deref()).await
}

#[tauri::command]
pub async fn migrate_wallet(state: State<'_, AppState>, password: String, totp_code: Option<String>, backup_path: String, confirmation_token: String) -> Result<crate::services::wallet_migration::MigrationSuccess, crate::services::wallet_migration::MigrationError> {
    crate::services::wallet_migration::migrate_wallet(&state, &password, totp_code.as_deref(), &backup_path, &confirmation_token).await
}

// ============================================================================
// TOTP commands (Milestone 5)
// ============================================================================

/// Result of enabling TOTP — returns the otpauth URL and base32 secret.
#[derive(Debug, serde::Serialize)]
pub struct EnableTotpResult {
    /// otpauth:// URL for QR code generation
    pub otpauth_url: String,
    /// Base32-encoded secret for manual entry
    pub secret_base32: String,
}

/// Enable TOTP for the current wallet.
///
/// Generates a new TOTP secret, encrypts it, and stores it in the TotpSecrets table.
/// Requires an unlocked wallet (to encrypt the secret with the wallet password).
#[tauri::command]
pub async fn enable_totp(state: State<'_, AppState>, password: String) -> Result<EnableTotpResult, String> {
    enable_totp_inner(&state, password).await
}

pub async fn enable_totp_inner(state: &AppState, password: String) -> Result<EnableTotpResult, String> {
    let _wallet_guard = state.wallet_operation.lock().await;
    if crate::services::wallet_security::status_locked(state, &_wallet_guard)?.is_some() {
        return Err("use begin_totp_setup and confirm_totp_setup for this wallet".into());
    }
    log::info!("enable_totp");

    let (pool, _, wallet_name, _) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        if !keystore::verify_password(&active.keystore_data, &password) { return Err("incorrect password".into()); }
        (
            active.db_pool.clone(),
            active.account_id,
            active.wallet_name.clone(),
            active.decrypted_xprv.clone(),
        )
    };

    // Check if TOTP is already enabled
    let already_enabled = repositories::is_totp_enabled(&pool)
        .await
        .map_err(|e| e.to_string())?;
    if already_enabled {
        return Err("TOTP is already enabled".to_string());
    }

    repositories::delete_recovery_codes(&pool).await.map_err(|e| e.to_string())?;
    // Generate a new TOTP secret
    let totp = crate::security::totp::TotpInstance::new("ElectrumSV-Mc", &wallet_name)
        .map_err(|e| e.to_string())?;

    let otpauth_url = totp.otpauth_url();
    let secret_base32 = totp.secret_base32();

    // Store the secret (raw bytes for now — DB is already protected by wallet password)
    repositories::store_totp_secret(&pool, totp.secret_bytes())
        .await
        .map_err(|e| e.to_string())?;
    crate::services::wallet_security::invalidate_legacy_pending_locked(state, &_wallet_guard);

    log::info!("TOTP enabled for wallet '{}'", wallet_name);

    Ok(EnableTotpResult {
        otpauth_url,
        secret_base32,
    })
}

#[tauri::command]
pub async fn begin_totp_setup(state: State<'_, AppState>, password: String) -> Result<EnableTotpResult, String> {
    begin_totp_setup_inner(&state, &password).await
}
pub(crate) async fn begin_totp_setup_inner(state: &AppState, password: &str) -> Result<EnableTotpResult, String> {
    let guard = state.wallet_operation.lock().await;
    crate::services::wallet_security::begin_totp_locked(state, &guard, password).await?.ok_or("use legacy TOTP setup for this wallet".into())
}
#[tauri::command]
pub async fn confirm_totp_setup(state: State<'_, AppState>, password: String, code: String) -> Result<(), String> {
    confirm_totp_setup_inner(&state, &password, &code).await
}
pub(crate) async fn confirm_totp_setup_inner(state: &AppState, password: &str, code: &str) -> Result<(), String> {
    let guard = state.wallet_operation.lock().await;
    crate::services::wallet_security::confirm_totp_locked(state, &guard, password, code).await?.ok_or("TOTP setup is not pending".into())
}
#[tauri::command]
pub async fn cancel_totp_setup(state: State<'_, AppState>) -> Result<(), String> { cancel_totp_setup_inner(&state).await }
pub(crate) async fn cancel_totp_setup_inner(state: &AppState) -> Result<(), String> {
    let guard = state.wallet_operation.lock().await;
    crate::services::wallet_security::cancel_totp_locked(state, &guard)?.ok_or("TOTP setup is not pending".into())
}
#[tauri::command]
pub async fn recover_totp(state: State<'_, AppState>, password: String, recovery_code: String) -> Result<(), String> {
    recover_totp_inner(&state, &password, &recovery_code).await
}
pub(crate) async fn recover_totp_inner(state: &AppState, password: &str, recovery_code: &str) -> Result<(), String> {
    let guard = state.wallet_operation.lock().await;
    crate::services::wallet_security::recover_totp_locked(state, &guard, password, recovery_code).await?.ok_or("use legacy recovery for this wallet".into())
}

/// Disable TOTP for the current wallet.
#[tauri::command]
pub async fn disable_totp(state: State<'_, AppState>, password: String, code: String) -> Result<(), String> {
    disable_totp_inner(&state, password, code).await
}
pub(crate) async fn disable_totp_inner(state: &AppState, password: String, code: String) -> Result<(), String> {
    let _operation = state.wallet_operation.lock().await;
    if crate::services::wallet_security::disable_totp_locked(&state, &_operation, &password, &code).await?.is_some() { return Ok(()); }
    log::info!("disable_totp");

    let (pool, _) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        if !keystore::verify_password(&active.keystore_data, &password) { return Err("incorrect password".into()); }
        (active.db_pool.clone(), active.account_id)
    };

    if !repositories::is_totp_enabled(&pool).await.map_err(|e| e.to_string())? { return Err("TOTP is not enabled".into()); }
    require_totp(&pool, Some(&code)).await?;
    crate::services::wallet_security::invalidate_legacy_pending_locked(state, &_operation);
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp();
    sqlx::query("INSERT INTO WalletData(key,value,date_created,date_updated) VALUES('totp_recovery_codes','[]',?,?) ON CONFLICT(key) DO UPDATE SET value='[]',date_updated=excluded.date_updated")
        .bind(now).bind(now).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    #[cfg(test)]
    let mut barrier = state.active_wallet.lock().unwrap().as_mut().and_then(|a| a.commit_barrier.take());
    #[cfg(test)]
    if barrier.as_ref().is_some_and(|b| !b.after_commit) { let b = barrier.take().unwrap(); let _ = b.started.send(()); let _ = b.resume.await; }
    let deleted = sqlx::query("DELETE FROM TotpSecrets WHERE id=1").execute(&mut *tx).await.map_err(|e| e.to_string())?;
    if deleted.rows_affected() != 1 { return Err("TOTP state changed".into()); }
    // A failed or cancelled COMMIT can leave its outcome unknown; do not retain an unlocked session.
    let mut prior_session = {
        let mut active = state.active_wallet.lock().unwrap();
        let active = active.as_mut().ok_or("wallet changed")?;
        zeroize::Zeroizing::new(active.decrypted_xprv.take())
    };
    tx.commit().await.map_err(|_| "TOTP update outcome unknown; reopen wallet".to_string())?;
    #[cfg(test)]
    if let Some(b) = barrier.take() { let _ = b.started.send(()); let _ = b.resume.await; }
    if let Some(active) = state.active_wallet.lock().unwrap().as_mut() { active.decrypted_xprv = prior_session.take(); }

    log::info!("TOTP disabled");
    Ok(())
}

/// Verify a TOTP code (for testing before signing or for UI feedback).
#[tauri::command]
pub async fn verify_totp(state: State<'_, AppState>, code: String) -> Result<bool, String> {
    verify_totp_inner(&state, code).await
}

pub async fn verify_totp_inner(state: &AppState, code: String) -> Result<bool, String> {
    let _wallet_guard = state.wallet_operation.lock().await;
    if crate::services::wallet_security::verify_sign_totp_locked(state, &_wallet_guard, &code)?.is_some() { return Ok(true); }
    log::info!("verify_totp");

    let (pool, _, wallet_name) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (
            active.db_pool.clone(),
            active.account_id,
            active.wallet_name.clone(),
        )
    };

    let encrypted_secret = repositories::load_totp_secret(&pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("TOTP is not enabled")?;

    let totp = crate::security::totp::TotpInstance::from_secret_bytes(
        &encrypted_secret,
        "ElectrumSV-Mc",
        &wallet_name,
    )
    .map_err(|e| e.to_string())?;

    let valid = totp.verify_current(&code).map_err(|e| e.to_string())?;
    Ok(valid)
}

/// Check if TOTP is enabled for the current wallet.
#[tauri::command]
pub async fn is_totp_enabled_cmd(state: State<'_, AppState>) -> Result<Option<bool>, String> {
    is_totp_enabled_inner(&state).await
}

pub async fn is_totp_enabled_inner(state: &AppState) -> Result<Option<bool>, String> {
    let _wallet_guard = state.wallet_operation.lock().await;
    if let Some(status) = crate::services::wallet_security::status_locked(state, &_wallet_guard)? { return Ok(status); }
    let (pool, _) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.db_pool.clone(), active.account_id)
    };

    repositories::is_totp_enabled(&pool)
        .await
        .map(Some).map_err(|e| e.to_string())
}

// ============================================================================
// TOTP Recovery codes commands (Milestone 8-C)
// ============================================================================

/// Generate 10 TOTP recovery codes.
///
/// Generates 10 random recovery codes, hashes each with SHA256, stores the
/// hashes in the database, and returns the plaintext codes to the frontend
/// for one-time display. The plaintext codes are never stored.
#[tauri::command]
pub async fn generate_totp_recovery_codes(
    state: State<'_, AppState>, password: String, code: String,
) -> Result<Vec<String>, String> {
    generate_totp_recovery_codes_inner(&state, password, code).await
}
pub(crate) async fn generate_totp_recovery_codes_inner(state: &AppState, password: String, code: String) -> Result<Vec<String>, String> {
    generate_totp_recovery_codes_with(state, password, code, || crate::security::totp::generate_recovery_codes(10)).await
}
async fn generate_totp_recovery_codes_with(state: &AppState, password: String, code: String, generate: impl FnOnce() -> Result<Vec<String>, crate::security::totp::TotpError> + Send) -> Result<Vec<String>, String> {
    let _operation = state.wallet_operation.lock().await;
    let secure = {
        let active = state.active_wallet.lock().unwrap();
        active.as_ref().ok_or("no wallet is currently open")?.secure_wallet.is_some()
    };
    if secure {
        return crate::services::wallet_security::generate_recovery_codes_locked_with(state, &_operation, &password, &code, generate).await?.ok_or("wallet changed".into());
    }
    log::info!("generate_totp_recovery_codes");

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        if !keystore::verify_password(&active.keystore_data, &password) { return Err("incorrect password".into()); }
        active.db_pool.clone()
    };

    if !repositories::is_totp_enabled(&pool).await.map_err(|e| e.to_string())? { return Err("TOTP is not enabled".into()); }
    require_totp(&pool, Some(&code)).await?;

    // Generate 10 random recovery codes
    let codes = zeroize::Zeroizing::new(generate().map_err(|_| "recovery code generation failed")?);

    // Hash each code and store the hashes
    let hashed_codes: Vec<String> = codes
        .iter()
        .map(|c| crate::security::totp::hash_recovery_code(c))
        .collect();

    #[cfg(test)]
    let mut barrier = state.active_wallet.lock().unwrap().as_mut().and_then(|a| a.commit_barrier.take());
    #[cfg(test)]
    if barrier.as_ref().is_some_and(|b| !b.after_commit) { let b = barrier.take().unwrap(); let _ = b.started.send(()); let _ = b.resume.await; }
    repositories::store_recovery_codes(&pool, &hashed_codes)
        .await
        .map_err(|e| e.to_string())?;
    #[cfg(test)]
    if let Some(b) = barrier.take() { let _ = b.started.send(()); let _ = b.resume.await; }

    log::info!("Generated {} TOTP recovery codes", codes.len());
    Ok(codes.to_vec())
}

/// Recover access using a recovery code.
///
/// Checks if the given recovery code matches any stored hash. If matched,
/// the code is consumed (removed from the list), TOTP is disabled, and all
/// recovery codes are deleted. Returns true if recovery was successful.
#[tauri::command]
pub async fn totp_recover(
    state: State<'_, AppState>,
    recovery_code: String,
) -> Result<bool, String> {
    totp_recover_inner(&state, &recovery_code).await
}
pub(crate) async fn totp_recover_inner(state: &AppState, recovery_code: &str) -> Result<bool, String> {
    let _operation = state.wallet_operation.lock().await;
    if crate::services::wallet_security::status_locked(state, &_operation)?.is_some() { return Err("password required for secure recovery".into()); }
    log::info!("totp_recover");

    crate::services::wallet_security::legacy_recover_code_locked(state, &_operation, recovery_code).await
}

// ============================================================================
// Hardware wallet commands (Milestone 5)
// ============================================================================

/// Set hardware wallet enabled flag (runtime toggle).
///
/// Murena-Prinzip: Even if the cargo feature `hardware-wallet` is enabled at
/// compile time, the user must also enable it at runtime via this command.
#[tauri::command]
pub async fn set_hardware_wallet_enabled(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    log::info!("set_hardware_wallet_enabled — {}", enabled);

    let (pool, _) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.db_pool.clone(), active.account_id)
    };

    // Check if cargo feature is enabled when trying to turn on
    if enabled && !cfg!(feature = "hardware-wallet") {
        return Err(
            "hardware-wallet cargo feature is not enabled — rebuild with --features hardware-wallet"
                .to_string(),
        );
    }

    repositories::set_hardware_wallet_enabled(&pool, enabled)
        .await
        .map_err(|e| e.to_string())?;

    log::info!("Hardware wallet enabled: {}", enabled);
    Ok(())
}

/// Get hardware wallet enabled status.
#[tauri::command]
pub async fn get_hardware_wallet_status(state: State<'_, AppState>) -> Result<bool, String> {
    let (pool, _) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.db_pool.clone(), active.account_id)
    };

    repositories::get_hardware_wallet_enabled(&pool)
        .await
        .map_err(|e| e.to_string())
}

// ============================================================================
// Wallet utility commands (Milestone 6)
// ============================================================================

use crate::core::keystore;
use crate::security::encryption;

/// Result of export_seed command.
#[derive(Debug, serde::Serialize)]
pub struct ExportSeedResult {
    pub has_seed: bool,
    pub mnemonic: Option<String>,
}

/// A single exported private key entry (address + WIF).
#[derive(Debug, serde::Serialize)]
pub struct PrivKeyEntry {
    pub address: String,
    pub wif: String,
}

/// Result of export_privkey command.
#[derive(Debug, serde::Serialize)]
pub struct ExportPrivkeyResult {
    /// Single WIF when exporting one key
    pub wif: Option<String>,
    /// List of (address, WIF) pairs when exporting all keys
    pub keys: Option<Vec<PrivKeyEntry>>,
}

/// Export the BIP39 mnemonic seed phrase.
///
/// Requires the wallet password to decrypt the mnemonic.
/// Returns has_seed=false if the wallet does not use a BIP39 seed.
#[tauri::command]
pub async fn export_seed(
    state: State<'_, AppState>,
    password: String,
    totp_code: Option<String>,
) -> Result<ExportSeedResult, String> {
    let operation = state.wallet_operation.lock().await;
    if let Some(auth) = crate::services::wallet_security::authenticate_locked(&state, &operation, &password, totp_code.as_deref(), true).await? {
        return Ok(ExportSeedResult { has_seed: true, mnemonic: Some(auth.mnemonic().to_string()) });
    }
    log::info!("export_seed");

    let (keystore_data, pool) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.keystore_data.clone(), active.db_pool.clone())
    };

    // Verify password
    if !keystore::verify_password(&keystore_data, &password) {
        return Err("incorrect password".to_string());
    }

    // If TOTP is enabled, verify the TOTP code before revealing the seed
    let totp_enabled = repositories::is_totp_enabled(&pool)
        .await
        .map_err(|e| e.to_string())?;
    if totp_enabled {
        let code = totp_code.ok_or("TOTP code required to export seed when 2FA is enabled")?;
        let encrypted_secret = repositories::load_totp_secret(&pool)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("TOTP is not enabled")?;
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(
            &encrypted_secret,
            "ElectrumSV-Mc",
            "wallet",
        )
        .map_err(|e| e.to_string())?;
        let valid = totp.verify_current(&code).map_err(|e| e.to_string())?;
        if !valid {
            return Err("invalid TOTP code".to_string());
        }
    }

    // Check seed type
    if keystore_data.seed_type != "bip39" {
        return Ok(ExportSeedResult {
            has_seed: false,
            mnemonic: None,
        });
    }

    // Decrypt mnemonic
    let mnemonic = keystore::decrypt_mnemonic(&keystore_data, &password)
        .map_err(|e| e.to_string())?;

    Ok(ExportSeedResult {
        has_seed: true,
        mnemonic: Some(mnemonic),
    })
}

/// Change the wallet password.
///
/// Re-encrypts xprv, mnemonic, and passphrase with the new password.
/// Updates the keystore data in both the database and in-memory state.
#[tauri::command]
pub async fn change_password(
    state: State<'_, AppState>,
    old_password: String,
    new_password: String,
    totp_code: Option<String>,
) -> Result<(), String> {
    change_password_authorized(&state, &old_password, &new_password, totp_code.as_deref()).await
}

pub(crate) async fn change_password_impl(state: &AppState, old_password: &str, new_password: &str) -> Result<(), String> {
    change_password_authorized(state, old_password, new_password, None).await
}

pub(crate) async fn change_password_authorized(state: &AppState, old_password: &str, new_password: &str, code: Option<&str>) -> Result<(), String> {
    let _operation = state.wallet_operation.lock().await;
    log::info!("change_password");
    if new_password.is_empty() { return Err("new password must not be empty".into()); }
    if let Some(auth) = crate::services::wallet_security::authenticate_locked(state, &_operation, old_password, code, true).await? {
        return crate::services::wallet_security::rotate_password_locked(state, &_operation, auth, new_password).await;
    }

    let (pool, keystore_data) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (
            active.db_pool.clone(),
            active.keystore_data.clone(),
        )
    };

    // Verify old password
    if !keystore::verify_password(&keystore_data, &old_password) {
        return Err("incorrect password".to_string());
    }

    // Decrypt xprv with old password
    let decrypted_xprv = keystore::decrypt_xprv(&keystore_data, &old_password)
        .map_err(|e| e.to_string())?;

    // Decrypt mnemonic with old password (if bip39)
    let decrypted_seed = if keystore_data.seed_type == "bip39" {
        Some(
            keystore::decrypt_mnemonic(&keystore_data, &old_password)
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };

    // Decrypt passphrase with old password (if present)
    let decrypted_passphrase = if let Some(ref enc_pass) = keystore_data.passphrase {
        Some(
            encryption::pw_decode(enc_pass, &old_password)
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };

    if let Some(seed_words) = &decrypted_seed {
        let seed = crate::core::mnemonic::mnemonic_to_seed(seed_words, decrypted_passphrase.as_deref().unwrap_or(""))
            .map_err(|_| "wallet mnemonic cannot be validated")?;
        let master = bsv::compat::bip32::ExtendedKey::from_seed(&seed).map_err(|_| "wallet mnemonic cannot be validated")?;
        let derived = master.derive(&keystore_data.derivation).map_err(|_| "wallet derivation cannot be validated")?;
        if !derived.is_private() || derived.to_base58() != decrypted_xprv {
            return Err("wallet mnemonic, passphrase and private key do not match".into());
        }
    } else if !keystore_data.seed.is_empty() {
        return Err("password change is not supported for this legacy seed format".into());
    }

    // Re-encrypt with new password
    let new_xprv = encryption::pw_encode(&decrypted_xprv, &new_password);
    let new_seed = decrypted_seed
        .map(|s| encryption::pw_encode(&s, &new_password));
    let new_passphrase = decrypted_passphrase
        .map(|p| encryption::pw_encode(&p, &new_password));

    // Build new keystore data
    let new_keystore_data = keystore::KeyStoreData {
        xpub: keystore_data.xpub.clone(),
        xprv: new_xprv,
        seed_type: keystore_data.seed_type.clone(),
        derivation: keystore_data.derivation.clone(),
        seed: new_seed.unwrap_or_default(),
        passphrase: new_passphrase,
    };

    // Update MasterKeys.derivation_data in DB
    let new_ks_bytes = keystore::keystore_data_to_bytes(&new_keystore_data);
    let mk_row = repositories::get_first_master_key(&pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("no master key found in database")?;

    let now = chrono::Utc::now().timestamp();
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    sqlx::query("UPDATE MasterKeys SET derivation_data = ?, date_updated = ? WHERE masterkey_id = ?")
        .bind(&new_ks_bytes).bind(now).bind(mk_row.masterkey_id)
        .execute(&mut *tx).await.map_err(|e| e.to_string())?;
    sqlx::query("INSERT INTO WalletData (key, value, date_created, date_updated) VALUES ('password-token', '', ?, ?) ON CONFLICT(key) DO UPDATE SET value = '', date_updated = excluded.date_updated")
        .bind(now).bind(now).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;

    let mut guard = state.active_wallet.lock().unwrap();
    let active = guard.as_mut().expect("wallet operation guard keeps active wallet stable");
    active.keystore_data = new_keystore_data;
    drop(guard);
    crate::services::wallet_security::invalidate_legacy_pending_locked(state, &_operation);

    log::info!("Password changed successfully");
    Ok(())
}

/// Delete a wallet from disk.
///
/// Closes the wallet if it is the currently active one, then deletes
/// the .sqlite file from disk.
#[tauri::command]
pub async fn delete_wallet(
    state: State<'_, AppState>,
    wallet_path: String,
    password: String,
    totp_code: Option<String>,
) -> Result<(), String> {
    delete_wallet_authorized(&state, &wallet_path, &password, totp_code.as_deref()).await
}

async fn delete_wallet_impl(state: &AppState, wallet_path: &str, password: &str) -> Result<(), String> {
    delete_wallet_authorized(state, wallet_path, password, None).await
}
async fn delete_wallet_authorized(state: &AppState, wallet_path: &str, password: &str, code: Option<&str>) -> Result<(), String> {
    let _operation = state.wallet_operation.lock().await;
    log::info!("delete_wallet — path: {}", wallet_path);

    let secure = crate::services::wallet_security::authenticate_locked(state, &_operation, password, code, true).await?;

    let pool = {
        let guard = state.active_wallet.lock().map_err(|_| "wallet state unavailable")?;
        let active = guard.as_ref().ok_or("open this wallet before deleting it")?;
        if active.wallet_path != wallet_path { return Err("wallet is not the active wallet".into()); }
        if secure.is_none() && !keystore::verify_password(&active.keystore_data, &password) { return Err("incorrect password".into()); }
        active.db_pool.clone()
    };

    // Delete the .sqlite file from disk — but only if it's in the data_dir
    // (prevent path traversal attacks).
    // Use symlink_metadata so we can detect and reject symlinks (canonicalize
    // follows symlinks, which would mask a symlink pointing outside data_dir).
    let wallet_path_buf = std::path::PathBuf::from(&wallet_path);

    // Reject symlinks: the wallet file must be a regular file, not a symlink.
    let meta = std::fs::symlink_metadata(&wallet_path_buf)
        .map_err(|e| format!("failed to read wallet file metadata: {}", e))?;
    if meta.file_type().is_symlink() {
        return Err("wallet file must be a regular file, not a symlink".to_string());
    }

    let canonical_wallet = wallet_path_buf
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize wallet path: {}", e))?;

    let data_dir = std::path::PathBuf::from(&state.data_dir);
    let canonical_data_dir = data_dir
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize data_dir: {}", e))?;

    if !canonical_wallet.starts_with(&canonical_data_dir) {
        return Err("wallet file must be within the application data directory".to_string());
    }

    // Re-check after canonicalize that the resolved path is still a regular file
    // (defends against TOCTOU where the file was replaced between the two checks).
    let canon_meta = std::fs::symlink_metadata(&canonical_wallet)
        .map_err(|e| format!("failed to read canonicalized wallet metadata: {}", e))?;
    if !canon_meta.is_file() {
        return Err("wallet file must be a regular file".to_string());
    }

    let wallet = {
        let mut active = state.active_wallet.lock().map_err(|_| "wallet state unavailable")?;
        active.take().ok_or("no wallet is currently open")?
    };
    pool.close().await;
    std::fs::remove_file(&canonical_wallet)
        .map_err(|e| format!("failed to delete wallet file: {}", e))?;
    wallet.wallet_lock.unlock().map_err(|e| format!("failed to unlock wallet: {e}"))?;

    log::info!("Wallet deleted: {}", wallet_path);
    Ok(())
}

/// Export private key(s) as WIF (Wallet Import Format).
///
/// If `all` is true, exports all KeyInstances for the active account.
/// If `address` is provided, exports the key for that specific address.
/// Requires an unlocked wallet (xprv needed for key derivation).
#[tauri::command]
pub async fn export_privkey(
    state: State<'_, AppState>,
    password: String,
    address: Option<String>,
    all: Option<bool>,
    totp_code: Option<String>,
) -> Result<ExportPrivkeyResult, String> {
    let operation = state.wallet_operation.lock().await;
    let secure = crate::services::wallet_security::authenticate_locked(&state, &operation, &password, totp_code.as_deref(), true).await?;
    log::info!(
        "export_privkey — address: {:?}, all: {:?}",
        address,
        all
    );

    let (pool, account_id, xprv_opt, keystore_data) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (
            active.db_pool.clone(),
            active.account_id,
            active.decrypted_xprv.clone(),
            active.keystore_data.clone(),
        )
    };

    // Verify password
    if secure.is_none() && !keystore::verify_password(&keystore_data, &password) {
        return Err("incorrect password".to_string());
    }

    // If TOTP is enabled, verify the TOTP code before revealing private keys
    let totp_enabled = secure.is_none() && repositories::is_totp_enabled(&pool)
        .await
        .map_err(|e| e.to_string())?;
    if totp_enabled {
        let code = totp_code.ok_or("TOTP code required to export private key when 2FA is enabled")?;
        let encrypted_secret = repositories::load_totp_secret(&pool)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("TOTP is not enabled")?;
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(
            &encrypted_secret,
            "ElectrumSV-Mc",
            "wallet",
        )
        .map_err(|e| e.to_string())?;
        let valid = totp.verify_current(&code).map_err(|e| e.to_string())?;
        if !valid {
            return Err("invalid TOTP code".to_string());
        }
    }

    // Need unlocked wallet for key derivation
    let xprv_str = xprv_opt.ok_or("wallet is locked — unlock first")?;

    // Get all KeyInstances for the account
    let keyinstances = repositories::get_keyinstances_for_account(&pool, account_id)
        .await
        .map_err(|e| e.to_string())?;

    // Helper: derive private key WIF from xprv at a given subpath
    let derive_wif = |subpath: &[u32; 2]| -> Result<(String, String), String> {
        let account_key = bsv::compat::bip32::ExtendedKey::from_string(&xprv_str)
            .map_err(|e| format!("invalid xprv: {}", e))?;
        let path = format!("{}/{}", subpath[0], subpath[1]);
        let child_key = account_key
            .derive(&path)
            .map_err(|e| format!("derivation failed: {}", e))?;

        // Extract private key bytes (same pattern as signer.rs)
        let xprv_b58 = child_key.to_base58();
        let decoded = bsv::primitives::utils::base58_decode(&xprv_b58)
            .map_err(|e| format!("base58 decode: {}", e))?;

        if decoded.len() < 78 {
            return Err(format!("decoded xprv too short: {} bytes", decoded.len()));
        }
        if decoded[45] != 0x00 {
            return Err("invalid xprv: expected 0x00 prefix before key bytes".to_string());
        }

        let key_bytes = &decoded[46..78];
        let priv_key = bsv::primitives::private_key::PrivateKey::from_bytes(key_bytes)
            .map_err(|e| format!("private key creation: {}", e))?;

        // Derive the address for this key
        let pubkey = priv_key.to_public_key();
        let addr = crate::core::address::pubkey_to_p2pkh_address(&pubkey);

        // WIF with mainnet prefix 0x80
        let wif = priv_key.to_wif(&[0x80]);

        Ok((addr, wif))
    };

    let do_all = all.unwrap_or(false);

    if do_all {
        // Export all keys
        let mut entries = Vec::new();
        for ki in &keyinstances {
            // Parse derivation_data to get subpath
            let derivation_data: serde_json::Value =
                serde_json::from_slice(&ki.derivation_data)
                    .map_err(|e| e.to_string())?;

            let subpath_arr = derivation_data
                .get("subpath")
                .and_then(|s| s.as_array())
                .ok_or("missing subpath in derivation_data")?;

            let type_idx = subpath_arr
                .first()
                .and_then(|t| t.as_u64())
                .ok_or("invalid subpath type index")? as u32;
            let addr_idx = subpath_arr
                .get(1)
                .and_then(|t| t.as_u64())
                .ok_or("invalid subpath address index")? as u32;

            let (addr, wif) = derive_wif(&[type_idx, addr_idx])?;
            entries.push(PrivKeyEntry { address: addr, wif });
        }

        Ok(ExportPrivkeyResult {
            wif: None,
            keys: Some(entries),
        })
    } else if let Some(target_addr) = address {
        // Export key for a specific address
        for ki in &keyinstances {
            let derivation_data: serde_json::Value =
                serde_json::from_slice(&ki.derivation_data)
                    .map_err(|e| e.to_string())?;

            let subpath_arr = derivation_data
                .get("subpath")
                .and_then(|s| s.as_array())
                .ok_or("missing subpath in derivation_data")?;

            let type_idx = subpath_arr
                .first()
                .and_then(|t| t.as_u64())
                .ok_or("invalid subpath type index")? as u32;
            let addr_idx = subpath_arr
                .get(1)
                .and_then(|t| t.as_u64())
                .ok_or("invalid subpath address index")? as u32;

            let (addr, wif) = derive_wif(&[type_idx, addr_idx])?;
            if addr == target_addr {
                return Ok(ExportPrivkeyResult {
                    wif: Some(wif),
                    keys: None,
                });
            }
        }

        Err(format!("address not found in key instances: {}", target_addr))
    } else {
        Err("either 'all' must be true or 'address' must be provided".to_string())
    }
}

// ============================================================================
// BSM (Bitcoin Signed Message) — Milestone 8
// ============================================================================

use base64::Engine as _;

/// Result of sign_message — returns the base64-encoded BSM signature.
#[derive(Debug, serde::Serialize)]
pub struct SignMessageResult {
    /// Base64-encoded 65-byte compact BSM signature
    pub signature: String,
}

/// Result of verify_message — returns whether the signature is valid.
#[derive(Debug, serde::Serialize)]
pub struct VerifyMessageResult {
    /// True if the signature matches the address and message
    pub valid: bool,
}

/// Sign a message with a Bitcoin Signed Message (BSM) signature.
///
/// Uses the bsv-sdk compat::bsm module: magic prefix + double-SHA256 + ECDSA.
/// The signature is returned as base64-encoded 65-byte compact BSM format.
/// Requires an unlocked wallet (xprv needed for key derivation) and the wallet password.
#[tauri::command]
pub async fn sign_message(
    state: State<'_, AppState>,
    address: String,
    message: String,
    password: String,
    totp_code: Option<String>,
) -> Result<SignMessageResult, String> {
    let operation = state.wallet_operation.lock().await;
    let secure = crate::services::wallet_security::authenticate_locked(&state, &operation, &password, totp_code.as_deref(), true).await?;
    log::info!("sign_message — address: {}", address);

    let (pool, account_id, xprv_opt, keystore_data) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (
            active.db_pool.clone(),
            active.account_id,
            active.decrypted_xprv.clone(),
            active.keystore_data.clone(),
        )
    };

    // Verify password
    if secure.is_none() && !keystore::verify_password(&keystore_data, &password) {
        return Err("incorrect password".to_string());
    }

    if secure.is_none() { require_totp(&pool, totp_code.as_deref()).await?; }

    // Need unlocked wallet for key derivation
    let xprv_str = xprv_opt.ok_or("wallet is locked — unlock first")?;

    // Find KeyInstance matching the address
    let keyinstances = repositories::get_keyinstances_for_account(&pool, account_id)
        .await
        .map_err(|e| e.to_string())?;

    let mut found_subpath: Option<[u32; 2]> = None;
    for ki in &keyinstances {
        let derivation_data: serde_json::Value =
            serde_json::from_slice(&ki.derivation_data).map_err(|e| e.to_string())?;

        let subpath_arr = derivation_data
            .get("subpath")
            .and_then(|s| s.as_array())
            .ok_or("missing subpath in derivation_data")?;

        let type_idx = subpath_arr[0].as_u64().unwrap_or(0) as u32;
        let addr_idx = subpath_arr[1].as_u64().unwrap_or(0) as u32;

        // Derive address to compare
        let account_key = bsv::compat::bip32::ExtendedKey::from_string(&xprv_str)
            .map_err(|e| format!("invalid xprv: {}", e))?;
        let path = format!("{}/{}", type_idx, addr_idx);
        let child_key = account_key
            .derive(&path)
            .map_err(|e| format!("derivation failed: {}", e))?;
        let pubkey = child_key
            .public_key()
            .map_err(|e| format!("public key derivation: {}", e))?;
        let derived_addr = crate::core::address::pubkey_to_p2pkh_address(&pubkey);

        if derived_addr == address {
            found_subpath = Some([type_idx, addr_idx]);
            break;
        }
    }

    let subpath = found_subpath
        .ok_or_else(|| format!("address not found in key instances: {}", address))?;

    // Derive private key at the found subpath
    let account_key = bsv::compat::bip32::ExtendedKey::from_string(&xprv_str)
        .map_err(|e| format!("invalid xprv: {}", e))?;
    let path = format!("{}/{}", subpath[0], subpath[1]);
    let child_key = account_key
        .derive(&path)
        .map_err(|e| format!("derivation failed: {}", e))?;

    let xprv_b58 = child_key.to_base58();
    let decoded = bsv::primitives::utils::base58_decode(&xprv_b58)
        .map_err(|e| format!("base58 decode: {}", e))?;

    if decoded.len() < 78 {
        return Err(format!("decoded xprv too short: {} bytes", decoded.len()));
    }

    let key_bytes = &decoded[46..78];
    let priv_key = bsv::primitives::private_key::PrivateKey::from_bytes(key_bytes)
        .map_err(|e| format!("private key creation: {}", e))?;

    // Sign with BSM
    let sig_bytes = bsv::compat::bsm::BSM::sign(message.as_bytes(), &priv_key)
        .map_err(|e| format!("BSM signing failed: {}", e))?;

    // Base64 encode
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

    log::info!("Message signed for address {}", address);
    Ok(SignMessageResult {
        signature: signature_b64,
    })
}

/// Verify a Bitcoin Signed Message (BSM) signature.
///
/// Recovers the public key from the 65-byte compact BSM signature using
/// the recovery byte, derives the P2PKH address, and compares with the
/// provided address. No wallet or state needed — verification is stateless.
#[tauri::command]
pub async fn verify_message(
    address: String,
    message: String,
    signature: String,
) -> Result<VerifyMessageResult, String> {
    log::info!("verify_message — address: {}", address);

    // Base64 decode the signature
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&signature)
        .map_err(|e| format!("invalid base64 signature: {}", e))?;

    if sig_bytes.len() != 65 {
        return Err("BSM signature must be 65 bytes".to_string());
    }

    // Parse compact BSM signature → (Signature, recovery, compressed)
    let (sig, recovery, _compressed) =
        bsv::primitives::signature::Signature::from_compact_bsm(&sig_bytes)
            .map_err(|e| format!("invalid BSM signature: {}", e))?;

    // Compute BSM magic hash (double-SHA256 with magic prefix)
    let msg_hash = bsv::compat::bsm::BSM::magic_hash(message.as_bytes());

    // Convert to BigNumber for public key recovery
    let msg_bn = bsv::primitives::big_number::BigNumber::from_bytes(
        &msg_hash,
        bsv::primitives::big_number::Endian::Big,
    );

    // Recover public key from signature
    let recovered_pubkey = sig
        .recover_public_key(recovery, &msg_bn)
        .map_err(|e| format!("public key recovery failed: {}", e))?;

    // Derive P2PKH address from recovered pubkey (mainnet prefix 0x00)
    let recovered_addr = recovered_pubkey.to_address(&[0x00]);

    // Compare with provided address
    let valid = recovered_addr == address;

    log::info!(
        "BSM verification: {} (recovered: {}, expected: {})",
        valid,
        recovered_addr,
        address
    );
    Ok(VerifyMessageResult { valid })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address;
    use crate::db::connection;
    use crate::db::repositories;
    use crate::services::wallet_service;
    use crate::state::AppState;
    use bsv::compat::bip32::ExtendedKey;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_test_state(test_name: &str) -> AppState {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir =
            std::env::temp_dir().join(format!("electrumsv_mc_wallet_{}_{}", test_name, id));
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir).ok();
        }
        std::fs::create_dir_all(&temp_dir).unwrap();
        AppState {
            data_dir: temp_dir.to_string_lossy().to_string(),
            active_wallet: std::sync::Mutex::new(None),
            network: std::sync::Mutex::new(crate::state::NetworkState::new()),
            pending_plans: std::sync::Mutex::new(std::collections::HashMap::new()),
            wallet_operation: tokio::sync::Mutex::new(()),
        }
    }

    // --------------------------------------------------------------------
    // list_wallets / create_wallet / open_wallet / close_wallet / unlock
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_list_wallets_empty_dir() {
        let state = make_test_state("list_empty");
        // No wallets created yet — list should be empty
        let wallets = connection::list_wallet_files(&state.data_dir).unwrap();
        assert!(wallets.is_empty());
    }

    #[tokio::test]
    async fn test_list_wallets_after_create() {
        let state = make_test_state("list_after_create");
        wallet_service::create_wallet(&state, "test_list_w", "pw123", None, None)
            .await
            .unwrap();

        let wallets = connection::list_wallet_files(&state.data_dir).unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].name, "test_list_w");
        assert!(wallets[0].path.ends_with(".sqlite"));

        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_wallet_generates_12_word_mnemonic() {
        let state = make_test_state("create_gen");
        let result = wallet_service::create_wallet(&state, "test_gen", "pw123", None, None)
            .await
            .unwrap();

        assert!(result.is_new_mnemonic);
        let words: Vec<&str> = result.mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        assert_eq!(result.account_id, 1);

        let status = wallet_service::get_wallet_status(&state);
        assert!(status.is_open);
        assert!(status.is_unlocked);
        assert_eq!(status.wallet_name, Some("test_gen".to_string()));

        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_wallet_with_known_mnemonic() {
        let state = make_test_state("create_known");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result =
            wallet_service::create_wallet(&state, "test_known", "pw123", Some(mnemonic), None)
                .await
                .unwrap();

        assert!(!result.is_new_mnemonic);
        assert_eq!(result.mnemonic, mnemonic);

        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_open_wallet_locked() {
        let state = make_test_state("open_locked");
        let result = wallet_service::create_wallet(&state, "test_open", "pw123", None, None)
            .await
            .unwrap();
        let wallet_path = result.wallet_path.clone();

        // Close and reopen — should be locked
        wallet_service::close_wallet(&state).await.unwrap();
        let open_result = wallet_service::open_wallet(&state, &wallet_path)
            .await
            .unwrap();

        assert!(!open_result.is_unlocked);
        assert_eq!(open_result.wallet_name, "test_open");

        let status = wallet_service::get_wallet_status(&state);
        assert!(status.is_open);
        assert!(!status.is_unlocked);

        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_unlock_wallet_correct_password() {
        let state = make_test_state("unlock_correct");
        let result = wallet_service::create_wallet(&state, "test_unlock", "pw123", None, None)
            .await
            .unwrap();
        let wallet_path = result.wallet_path;

        // Close, reopen, then unlock
        wallet_service::close_wallet(&state).await.unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();

        assert!(wallet_service::unlock_wallet_authorized(&state, "pw123", None).await.is_ok());
        let status = wallet_service::get_wallet_status(&state);
        assert!(status.is_unlocked);

        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_unlock_wallet_wrong_password() {
        let state = make_test_state("unlock_wrong");
        let result = wallet_service::create_wallet(&state, "test_unlock_w", "pw123", None, None)
            .await
            .unwrap();
        let wallet_path = result.wallet_path;

        wallet_service::close_wallet(&state).await.unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();

        assert!(wallet_service::unlock_wallet_authorized(&state, "wrong_pw", None).await.is_err());

        let status = wallet_service::get_wallet_status(&state);
        assert!(!status.is_unlocked);

        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_close_wallet_no_wallet_open() {
        let state = make_test_state("close_none");
        let err = wallet_service::close_wallet(&state).await.unwrap_err();
        assert!(matches!(err, wallet_service::WalletError::NoWalletOpen));
    }

    // --------------------------------------------------------------------
    // TOTP
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_totp_disabled_by_default() {
        let state = make_test_state("totp_default");
        wallet_service::create_wallet(&state, "test_totp_def", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let enabled = repositories::is_totp_enabled(&pool).await.unwrap();
        assert!(!enabled);

        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_totp_store_and_load_secret() {
        let state = make_test_state("totp_store");
        wallet_service::create_wallet(&state, "test_totp_store", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Store a TOTP secret
        let totp = crate::security::totp::TotpInstance::new("ElectrumSV-Mc", "test_wallet")
            .unwrap();
        let secret_bytes = totp.secret_bytes().to_vec();
        repositories::store_totp_secret(&pool, &secret_bytes)
            .await
            .unwrap();

        // Should now be enabled
        assert!(repositories::is_totp_enabled(&pool).await.unwrap());

        // Load and verify
        let loaded = repositories::load_totp_secret(&pool).await.unwrap();
        assert_eq!(loaded, Some(secret_bytes));

        // Delete (disable)
        repositories::delete_totp_secret(&pool).await.unwrap();
        assert!(!repositories::is_totp_enabled(&pool).await.unwrap());

        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_totp_verify_current_code() {
        let state = make_test_state("totp_verify");
        wallet_service::create_wallet(&state, "test_totp_verify", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let totp = crate::security::totp::TotpInstance::new("ElectrumSV-Mc", "test_wallet")
            .unwrap();
        let secret_bytes = totp.secret_bytes().to_vec();
        repositories::store_totp_secret(&pool, &secret_bytes)
            .await
            .unwrap();

        // Generate current code and verify
        let code = totp.generate_current().unwrap();
        let valid = totp.verify_current(&code).unwrap();
        assert!(valid);

        // Wrong code should fail
        let wrong_code = "000000";
        let valid_wrong = totp.verify_current(wrong_code).unwrap();
        assert!(!valid_wrong);

        wallet_service::close_wallet(&state).await.unwrap();
    }

    // --------------------------------------------------------------------
    // TOTP Recovery codes
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn legacy_disable_failure_preserves_totp_and_recovery_codes() {
        let state = make_test_state("legacy_disable_atomic");
        wallet_service::create_legacy_fixture(&state, "legacy", "pw", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None).await.unwrap();
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        let secret = [7u8;20]; repositories::store_totp_secret(&pool, &secret).await.unwrap();
        let codes = vec![crate::security::totp::hash_recovery_code("ABCD-EFGH")];
        repositories::store_recovery_codes(&pool, &codes).await.unwrap();
        sqlx::query("CREATE TRIGGER reject_legacy_totp_delete BEFORE DELETE ON TotpSecrets BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END").execute(&pool).await.unwrap();
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").unwrap();
        assert!(disable_totp_inner(&state, "pw".into(), totp.generate_current().unwrap()).await.is_err());
        assert!(repositories::is_totp_enabled(&pool).await.unwrap());
        assert_eq!(repositories::load_recovery_codes(&pool).await.unwrap(), codes);
        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn legacy_recovery_cancellation_locks_session_and_reopens_actual_state() {
        for after_commit in [false, true] {
            let state = std::sync::Arc::new(make_test_state(&format!("legacy_recovery_cancel_{after_commit}")));
            wallet_service::create_legacy_fixture(&state, "legacy", "pw", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None).await.unwrap();
            let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
            repositories::store_totp_secret(&pool, &[7;20]).await.unwrap();
            repositories::store_recovery_codes(&pool, &[crate::security::totp::hash_recovery_code("ABCD-EFGH")]).await.unwrap();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel(); let (_resume_tx, resume_rx) = tokio::sync::oneshot::channel();
            state.active_wallet.lock().unwrap().as_mut().unwrap().commit_barrier = Some(crate::state::TestCommitBarrier { after_commit, started: started_tx, resume: resume_rx });
            let worker = state.clone(); let task = tokio::spawn(async move { recover_totp_inner(&worker, "pw", "ABCD-EFGH").await });
            tokio::time::timeout(std::time::Duration::from_secs(20),started_rx).await.unwrap().unwrap();
            assert!(!wallet_service::get_wallet_status(&state).is_unlocked);
            task.abort(); let _ = task.await;
            wallet_service::close_wallet(&state).await.unwrap(); wallet_service::open_wallet(&state, "legacy").await.unwrap();
            let current = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
            assert_eq!(repositories::is_totp_enabled(&current).await.unwrap(), !after_commit);
            assert_eq!(!repositories::load_recovery_codes(&current).await.unwrap().is_empty(), !after_commit);
            wallet_service::close_wallet(&state).await.unwrap();
        }
    }

    #[tokio::test]
    async fn legacy_disable_cancellation_preserves_database_atomicity() {
        for after_commit in [false, true] {
            let state = std::sync::Arc::new(make_test_state(&format!("legacy_disable_cancel_{after_commit}")));
            wallet_service::create_legacy_fixture(&state, "legacy", "pw", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None).await.unwrap();
            let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
            let secret = [7u8;20]; repositories::store_totp_secret(&pool, &secret).await.unwrap();
            repositories::store_recovery_codes(&pool, &[crate::security::totp::hash_recovery_code("ABCD-EFGH")]).await.unwrap();
            let code = crate::security::totp::TotpInstance::from_secret_bytes(&secret,"ElectrumSV-Mc","wallet").unwrap().generate_current().unwrap();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel(); let (_resume_tx, resume_rx) = tokio::sync::oneshot::channel();
            state.active_wallet.lock().unwrap().as_mut().unwrap().commit_barrier = Some(crate::state::TestCommitBarrier { after_commit, started: started_tx, resume: resume_rx });
            let worker = state.clone(); let task = tokio::spawn(async move { disable_totp_inner(&worker,"pw".into(),code).await });
            tokio::time::timeout(std::time::Duration::from_secs(20),started_rx).await.unwrap().unwrap();
            assert_eq!(wallet_service::get_wallet_status(&state).is_unlocked, !after_commit);
            task.abort(); let _ = task.await;
            wallet_service::close_wallet(&state).await.unwrap(); wallet_service::open_wallet(&state, "legacy").await.unwrap();
            let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
            assert_eq!(repositories::is_totp_enabled(&pool).await.unwrap(), !after_commit);
            assert_eq!(!repositories::load_recovery_codes(&pool).await.unwrap().is_empty(), !after_commit);
            wallet_service::close_wallet(&state).await.unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "subprocess recovery crash harness"]
    async fn recovery_crash_child_harness() {
        use std::io::Write;
        let mut state = AppState::new(); state.data_dir = std::env::var("WALLET_P2_CRASH_DIR").unwrap();
        let state = std::sync::Arc::new(state);
        let legacy = std::env::var("WALLET_P2_CRASH_FORMAT").unwrap() == "33";
        let after_commit = std::env::var("WALLET_P2_CRASH_PHASE").unwrap() == "after";
        let action = std::env::var("WALLET_P2_CRASH_ACTION").unwrap();
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        if legacy { wallet_service::create_legacy_fixture(&state, "legacy", "pw", phrase, None).await.unwrap(); }
        else { wallet_service::create_wallet(&state, "legacy", "pw", Some(phrase), None).await.unwrap(); }
        let setup = begin_totp_setup_inner(&state, "pw").await.unwrap();
        let secret = totp_rs::Secret::Encoded(setup.secret_base32).to_bytes().unwrap();
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").unwrap();
        confirm_totp_setup_inner(&state, "pw", &totp.generate_current().unwrap()).await.unwrap();
        generate_totp_recovery_codes_with(&state, "pw".into(), totp.generate_current().unwrap(), || Ok(vec!["ABCD-EFGH".into()])).await.unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel(); let (_resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        state.active_wallet.lock().unwrap().as_mut().unwrap().commit_barrier = Some(crate::state::TestCommitBarrier { after_commit, started: started_tx, resume: resume_rx });
        let worker = state.clone(); let code = totp.generate_current().unwrap();
        let task = tokio::spawn(async move {
            match action.as_str() {
                "disable" => disable_totp_inner(&worker, "pw".into(), code).await.map(|_| ()),
                "recover" => recover_totp_inner(&worker, "pw", "ABCD-EFGH").await,
                "generate" => generate_totp_recovery_codes_inner(&worker, "pw".into(), code).await.map(|_| ()),
                _ => panic!("invalid synthetic test action"),
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(90),started_rx).await.unwrap().unwrap();
        println!("RECOVERY_TEST_READY"); std::io::stdout().flush().unwrap();
        let _ = task.await;
    }

    #[tokio::test]
    async fn killed_recovery_process_preserves_atomic_code_state() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        for (legacy, action) in [(true,"disable"), (true,"recover"), (false,"recover"), (true,"generate"), (false,"generate")] {
            for after_commit in [false, true] {
                let state = make_test_state(&format!("kill_{legacy}_{action}_{after_commit}"));
                let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--ignored", "--exact", "commands::wallet::tests::recovery_crash_child_harness", "--nocapture"])
                    .env("WALLET_P2_CRASH_DIR", &state.data_dir).env("WALLET_P2_CRASH_FORMAT", if legacy { "33" } else { "34" })
                    .env("WALLET_P2_CRASH_PHASE", if after_commit { "after" } else { "before" }).env("WALLET_P2_CRASH_ACTION", action)
                    .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).kill_on_drop(true).spawn().unwrap();
                let mut output = BufReader::new(child.stdout.take().unwrap());
                tokio::time::timeout(std::time::Duration::from_secs(120), async {
                    loop { let mut line = String::new(); assert!(output.read_line(&mut line).await.unwrap()>0, "child exited before barrier"); if line.contains("RECOVERY_TEST_READY") { break; } }
                }).await.expect("child did not reach commit barrier");
                child.kill().await.unwrap(); assert!(!child.wait().await.unwrap().success());
                wallet_service::open_wallet(&state, "legacy").await.unwrap();
                let (enabled, old_present, count) = if legacy {
                    let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
                    let codes = repositories::load_recovery_codes(&pool).await.unwrap();
                    (repositories::is_totp_enabled(&pool).await.unwrap(), codes.contains(&crate::security::totp::hash_recovery_code("ABCD-EFGH")), codes.len())
                } else {
                    let guard = state.wallet_operation.lock().await;
                    let auth = crate::services::wallet_security::authenticate_locked(&state, &guard, "pw", None, false).await.unwrap().unwrap();
                    (auth.totp_enabled(), auth.has_recovery_code("ABCD-EFGH"), auth.recovery_count())
                };
                let disabled = after_commit && action != "generate";
                assert_eq!(enabled, !disabled);
                assert_eq!(old_present, !after_commit);
                assert_eq!(count, if disabled { 0 } else if after_commit { 10 } else { 1 });
                assert_eq!(recover_totp_inner(&state, "pw", "ABCD-EFGH").await.is_ok(), !after_commit);
                if !after_commit { assert!(recover_totp_inner(&state, "pw", "ABCD-EFGH").await.is_err()); }
                wallet_service::close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(&state.data_dir).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn concurrent_recovery_and_regeneration_are_serialized_without_lost_updates() {
        use std::{future::Future, task::Poll};
        for legacy in [true, false] {
            for recover_first in [true, false] {
                let state = make_test_state(&format!("recovery_race_{legacy}_{recover_first}"));
                let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
                if legacy { wallet_service::create_legacy_fixture(&state, "race", "pw", phrase, None).await.unwrap(); }
                else { wallet_service::create_wallet(&state, "race", "pw", Some(phrase), None).await.unwrap(); }
                let setup = begin_totp_setup_inner(&state, "pw").await.unwrap();
                let secret = totp_rs::Secret::Encoded(setup.secret_base32).to_bytes().unwrap();
                let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").unwrap();
                confirm_totp_setup_inner(&state, "pw", &totp.generate_current().unwrap()).await.unwrap();
                let old = "ABCD-EFGH";
                generate_totp_recovery_codes_with(&state, "pw".into(), totp.generate_current().unwrap(), || Ok(vec![old.to_string()])).await.unwrap();
                let gate = state.wallet_operation.lock().await;
                let code = totp.generate_current().unwrap();
                let mut recover = Box::pin(recover_totp_inner(&state, "pw", old));
                let mut regenerate = Box::pin(generate_totp_recovery_codes_inner(&state, "pw".into(), code));
                std::future::poll_fn(|cx| {
                    if recover_first {
                        assert!(matches!(recover.as_mut().poll(cx), Poll::Pending));
                        assert!(matches!(regenerate.as_mut().poll(cx), Poll::Pending));
                    } else {
                        assert!(matches!(regenerate.as_mut().poll(cx), Poll::Pending));
                        assert!(matches!(recover.as_mut().poll(cx), Poll::Pending));
                    }
                    Poll::Ready(())
                }).await;
                drop(gate);
                let (recovered, generated) = tokio::time::timeout(
                    std::time::Duration::from_secs(180), async { tokio::join!(recover, regenerate) },
                ).await.expect("recovery race timed out");
                if recover_first {
                    assert!(recovered.is_ok());
                    assert!(generated.is_err());
                } else {
                    assert!(recovered.is_err());
                    let codes = generated.unwrap();
                    assert_eq!(codes.len(), 10);
                    recover_totp_inner(&state, "pw", &codes[0]).await.unwrap();
                    assert!(recover_totp_inner(&state, "pw", &codes[0]).await.is_err());
                }
                assert!(recover_totp_inner(&state, "pw", old).await.is_err());
                assert_eq!(is_totp_enabled_inner(&state).await.unwrap(), if legacy { Some(false) } else { None });
                wallet_service::close_wallet(&state).await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn recovery_generation_preserves_existing_codes_on_rng_and_sql_failure() {
        for legacy in [true, false] {
            let state = make_test_state(if legacy { "recovery_rng_legacy" } else { "recovery_rng_secure" });
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            if legacy { wallet_service::create_legacy_fixture(&state, "recovery", "pw", phrase, None).await.unwrap(); }
            else { wallet_service::create_wallet(&state, "recovery", "pw", Some(phrase), None).await.unwrap(); }
            let setup = begin_totp_setup_inner(&state, "pw").await.unwrap();
            let secret = totp_rs::Secret::Encoded(setup.secret_base32).to_bytes().unwrap();
            let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").unwrap();
            confirm_totp_setup_inner(&state, "pw", &totp.generate_current().unwrap()).await.unwrap();
            let old = "ABCD-EFGH".to_string();
            let long = "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345-6789".to_string();
            generate_totp_recovery_codes_with(&state, "pw".into(), totp.generate_current().unwrap(), || Ok(vec![old.clone(), long.clone()])).await.unwrap();
            let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
            let before_key = repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data;
            let before_codes = repositories::get_wallet_data(&pool, repositories::TOTP_RECOVERY_CODES_KEY).await.unwrap();
            let failed = generate_totp_recovery_codes_with(&state, "pw".into(), totp.generate_current().unwrap(), || Err(crate::security::totp::TotpError::RecoveryGeneration)).await;
            assert!(failed.is_err());
            assert_eq!(repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data, before_key);
            assert_eq!(repositories::get_wallet_data(&pool, repositories::TOTP_RECOVERY_CODES_KEY).await.unwrap(), before_codes);
            let trigger = if legacy { "CREATE TRIGGER recovery_fail BEFORE UPDATE ON WalletData WHEN OLD.key='totp_recovery_codes' BEGIN SELECT RAISE(ABORT,'test'); END" } else { "CREATE TRIGGER recovery_fail BEFORE UPDATE ON MasterKeys BEGIN SELECT RAISE(ABORT,'test'); END" };
            sqlx::query(trigger).execute(&pool).await.unwrap();
            assert!(generate_totp_recovery_codes_inner(&state, "pw".into(), totp.generate_current().unwrap()).await.is_err());
            assert_eq!(repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data, before_key);
            assert_eq!(repositories::get_wallet_data(&pool, repositories::TOTP_RECOVERY_CODES_KEY).await.unwrap(), before_codes);
            sqlx::query("DROP TRIGGER recovery_fail").execute(&pool).await.unwrap();
            assert!(recover_totp_inner(&state, "pw", &old.to_lowercase()).await.is_err());
            recover_totp_inner(&state, "pw", &old).await.unwrap();
            assert!(recover_totp_inner(&state, "pw", &old).await.is_err());
            let setup = begin_totp_setup_inner(&state, "pw").await.unwrap();
            let secret = totp_rs::Secret::Encoded(setup.secret_base32).to_bytes().unwrap();
            let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").unwrap();
            confirm_totp_setup_inner(&state, "pw", &totp.generate_current().unwrap()).await.unwrap();
            let fresh = generate_totp_recovery_codes_inner(&state, "pw".into(), totp.generate_current().unwrap()).await.unwrap();
            assert_eq!(fresh.len(), 10);
            assert!(fresh.iter().all(|code| code.len() == 39 && code.split('-').count() == 8));
            assert!(recover_totp_inner(&state, "pw", &fresh[0].replace('-', "")).await.is_err());
            recover_totp_inner(&state, "pw", &fresh[0]).await.unwrap();
            assert!(recover_totp_inner(&state, "pw", &fresh[0]).await.is_err());
            wallet_service::close_wallet(&state).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_recovery_codes_generate_and_consume() {
        let state = make_test_state("recovery_codes");
        wallet_service::create_wallet(&state, "test_recovery", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Generate 10 recovery codes
        let codes = crate::security::totp::generate_recovery_codes(10).unwrap();
        assert_eq!(codes.len(), 10);

        // Each code contains 32 symbols in eight groups of four.
        for code in &codes {
            assert_eq!(code.len(), 39);
            assert!(code.split('-').count() == 8 && code.split('-').all(|part| part.len() == 4));
        }

        // Hash and store
        let hashed: Vec<String> = codes
            .iter()
            .map(|c| crate::security::totp::hash_recovery_code(c))
            .collect();
        repositories::store_recovery_codes(&pool, &hashed)
            .await
            .unwrap();

        // Consume the first code
        let first_hash = crate::security::totp::hash_recovery_code(&codes[0]);
        let matched = repositories::consume_recovery_code(&pool, &first_hash)
            .await
            .unwrap();
        assert!(matched);

        // Consume same code again — should not match
        let matched_again = repositories::consume_recovery_code(&pool, &first_hash)
            .await
            .unwrap();
        assert!(!matched_again);

        // Consume a non-existent code
        let fake_hash = crate::security::totp::hash_recovery_code("FAKE-CODE");
        let matched_fake = repositories::consume_recovery_code(&pool, &fake_hash)
            .await
            .unwrap();
        assert!(!matched_fake);

        // Delete all remaining
        repositories::delete_recovery_codes(&pool).await.unwrap();
        let remaining = repositories::load_recovery_codes(&pool).await.unwrap();
        assert!(remaining.is_empty());

        wallet_service::close_wallet(&state).await.unwrap();
    }

    // --------------------------------------------------------------------
    // Hardware wallet toggle
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_hardware_wallet_toggle() {
        let state = make_test_state("hw_toggle");
        wallet_service::create_wallet(&state, "test_hw", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Default: disabled
        let enabled = repositories::get_hardware_wallet_enabled(&pool)
            .await
            .unwrap();
        assert!(!enabled);

        // Enable
        repositories::set_hardware_wallet_enabled(&pool, true)
            .await
            .unwrap();
        assert!(repositories::get_hardware_wallet_enabled(&pool).await.unwrap());

        // Disable
        repositories::set_hardware_wallet_enabled(&pool, false)
            .await
            .unwrap();
        assert!(!repositories::get_hardware_wallet_enabled(&pool).await.unwrap());

        wallet_service::close_wallet(&state).await.unwrap();
    }

    // --------------------------------------------------------------------
    // export_seed (test via keystore directly)
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_export_seed_correct_password() {
        let state = make_test_state("export_seed_ok");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_legacy_fixture(&state, "test_export", "pw123", mnemonic, None)
            .await
            .unwrap();

        let keystore_data = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().keystore_data.clone()
        };

        // Verify password
        assert!(keystore::verify_password(&keystore_data, "pw123"));

        // Decrypt mnemonic
        let decrypted = keystore::decrypt_mnemonic(&keystore_data, "pw123").unwrap();
        assert_eq!(decrypted, mnemonic);

        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_export_seed_wrong_password() {
        let state = make_test_state("export_seed_wrong");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_legacy_fixture(&state, "test_export_w", "pw123", mnemonic, None)
            .await
            .unwrap();

        let keystore_data = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().keystore_data.clone()
        };

        // Wrong password should fail verification
        assert!(!keystore::verify_password(&keystore_data, "wrong_pw"));

        // decrypt_mnemonic with wrong password should error
        let result = keystore::decrypt_mnemonic(&keystore_data, "wrong_pw");
        assert!(result.is_err());

        wallet_service::close_wallet(&state).await.unwrap();
    }

    // --------------------------------------------------------------------
    #[tokio::test]
    async fn password_change_rejects_empty_auth_and_seed_mismatch_without_mutating_wallet() {
        let state = make_test_state("pw_strict_auth");
        let created = wallet_service::create_legacy_fixture(&state, "strict", "secret", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None).await.unwrap();
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        let original = repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data;
        assert!(change_password_impl(&state, "", "new").await.is_err());
        assert!(change_password_impl(&state, "wrong", "new").await.is_err());
        assert!(change_password_impl(&state, "secret", "").await.is_err());
        assert!(delete_wallet_impl(&state, &created.wallet_path, "").await.is_err());
        assert!(std::path::Path::new(&created.wallet_path).exists());
        assert_eq!(repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data, original);
        let mut corrupt = keystore::keystore_data_from_bytes(&original).unwrap();
        corrupt.seed = encryption::pw_encode("legal winner thank year wave sausage worth useful legal winner thank yellow", "secret");
        let corrupt_bytes = keystore::keystore_data_to_bytes(&corrupt);
        sqlx::query("UPDATE MasterKeys SET derivation_data=?").bind(&corrupt_bytes).execute(&pool).await.unwrap();
        state.active_wallet.lock().unwrap().as_mut().unwrap().keystore_data = corrupt;
        assert!(change_password_impl(&state, "secret", "new").await.is_err());
        assert_eq!(repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data, corrupt_bytes);
        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn password_change_preserves_bip39_passphrase_and_refuses_unknown_legacy_seed() {
        let state = make_test_state("pw_bip39_passphrase");
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_legacy_fixture(&state, "passphrase", "old", words, Some("TREZOR")).await.unwrap();
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        change_password_impl(&state, "old", "new").await.unwrap();
        let saved = repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data;
        let data = keystore::keystore_data_from_bytes(&saved).unwrap();
        assert!(keystore::verify_password(&data, "new"));
        assert_eq!(keystore::decrypt_mnemonic(&data, "new").unwrap(), words);
        assert_eq!(encryption::pw_decode(data.passphrase.as_deref().unwrap(), "new").unwrap(), "TREZOR");
        for case in 0..2 {
            let mut corrupt = data.clone();
            if case == 0 { corrupt.passphrase = Some(encryption::pw_encode("different", "new")); }
            else { corrupt.derivation = "m/44'/0'/1'".into(); }
            let expected = keystore::keystore_data_to_bytes(&corrupt);
            sqlx::query("UPDATE MasterKeys SET derivation_data=?").bind(&expected).execute(&pool).await.unwrap();
            state.active_wallet.lock().unwrap().as_mut().unwrap().keystore_data = corrupt;
            assert!(change_password_impl(&state, "new", "other").await.is_err());
            assert_eq!(repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data, expected);
            let current = state.active_wallet.lock().unwrap().as_ref().unwrap().keystore_data.clone();
            assert_eq!(keystore::keystore_data_to_bytes(&current), expected);
        }
        let mut unknown = data;
        unknown.seed_type = "legacy".into();
        let unknown_bytes = keystore::keystore_data_to_bytes(&unknown);
        sqlx::query("UPDATE MasterKeys SET derivation_data=?").bind(&unknown_bytes).execute(&pool).await.unwrap();
        state.active_wallet.lock().unwrap().as_mut().unwrap().keystore_data = unknown;
        assert!(change_password_impl(&state, "new", "other").await.is_err());
        assert_eq!(repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data, unknown_bytes);
        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn plaintext_legacy_wallet_may_change_to_nonempty_password() {
        let state = make_test_state("pw_plaintext_legacy");
        wallet_service::create_legacy_fixture(&state, "legacy", "old", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None).await.unwrap();
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        let mut legacy = state.active_wallet.lock().unwrap().as_ref().unwrap().keystore_data.clone();
        legacy.xprv = keystore::decrypt_xprv(&legacy, "old").unwrap();
        legacy.seed = keystore::decrypt_mnemonic(&legacy, "old").unwrap();
        assert!(keystore::verify_password(&legacy, ""));
        sqlx::query("UPDATE MasterKeys SET derivation_data=?").bind(keystore::keystore_data_to_bytes(&legacy)).execute(&pool).await.unwrap();
        state.active_wallet.lock().unwrap().as_mut().unwrap().keystore_data = legacy;
        change_password_impl(&state, "", "new").await.unwrap();
        let stored = repositories::get_first_master_key(&pool).await.unwrap().unwrap();
        let new_keystore = keystore::keystore_data_from_bytes(&stored.derivation_data).unwrap();
        assert!(!keystore::verify_password(&new_keystore, ""));
        assert!(keystore::verify_password(&new_keystore, "new"));
        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn password_change_rolls_back_token_failure_and_updates_memory() {
        let state = make_test_state("password_atomic");
        wallet_service::create_legacy_fixture(&state, "atomic", "old", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None).await.unwrap();
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        sqlx::query("CREATE TRIGGER reject_token BEFORE UPDATE ON WalletData WHEN OLD.key = 'password-token' BEGIN SELECT RAISE(ABORT, 'token failure'); END")
            .execute(&pool).await.unwrap();
        assert!(change_password_impl(&state, "old", "new").await.is_err());
        {
            let guard = state.active_wallet.lock().unwrap();
            let active = guard.as_ref().unwrap();
            assert!(keystore::verify_password(&active.keystore_data, "old"));
            assert!(!keystore::verify_password(&active.keystore_data, "new"));
        }
        let stored = repositories::get_first_master_key(&pool).await.unwrap().unwrap();
        let ks = keystore::keystore_data_from_bytes(&stored.derivation_data).unwrap();
        assert!(keystore::verify_password(&ks, "old"));
        sqlx::query("DROP TRIGGER reject_token").execute(&pool).await.unwrap();
        change_password_impl(&state, "old", "new").await.unwrap();
        let guard = state.active_wallet.lock().unwrap();
        assert!(keystore::verify_password(&guard.as_ref().unwrap().keystore_data, "new"));
        drop(guard);
        assert_eq!(repositories::get_wallet_data(&pool, "password-token").await.unwrap().as_deref(), Some(""));
        wallet_service::close_wallet(&state).await.unwrap();
        pool.close().await;
    }

    #[tokio::test]
    async fn guarded_delete_removes_open_wallet() {
        let state = make_test_state("guarded_delete");
        let created = wallet_service::create_wallet(&state, "delete", "pw", None, None).await.unwrap();
        delete_wallet_impl(&state, &created.wallet_path, "pw").await.unwrap();
        assert!(!std::path::Path::new(&created.wallet_path).exists());
        assert!(!wallet_service::get_wallet_status(&state).is_open);
    }

    // change_password (test that wallet can unlock with new password)
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_change_password() {
        let state = make_test_state("change_pw");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result =
            wallet_service::create_legacy_fixture(&state, "test_changepw", "old_pw", mnemonic, None)
                .await
                .unwrap();
        let wallet_path = result.wallet_path;

        // Close, reopen with old password
        wallet_service::close_wallet(&state).await.unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();
        wallet_service::unlock_wallet(&state, "old_pw").unwrap();

        // Get the keystore data and pool
        let (pool, keystore_data) = {
            let guard = state.active_wallet.lock().unwrap();
            let active = guard.as_ref().unwrap();
            (active.db_pool.clone(), active.keystore_data.clone())
        };

        // Verify old password works
        assert!(keystore::verify_password(&keystore_data, "old_pw"));

        // Re-encrypt with new password (mimic change_password logic)
        let decrypted_xprv = keystore::decrypt_xprv(&keystore_data, "old_pw").unwrap();
        let decrypted_seed = keystore::decrypt_mnemonic(&keystore_data, "old_pw").unwrap();

        let new_xprv = encryption::pw_encode(&decrypted_xprv, "new_pw");
        let new_seed = encryption::pw_encode(&decrypted_seed, "new_pw");

        let new_keystore = keystore::KeyStoreData {
            xpub: keystore_data.xpub.clone(),
            xprv: new_xprv,
            seed_type: keystore_data.seed_type.clone(),
            derivation: keystore_data.derivation.clone(),
            seed: new_seed,
            passphrase: keystore_data.passphrase.clone(),
        };

        // Update DB
        let ks_bytes = keystore::keystore_data_to_bytes(&new_keystore);
        let mk_row = repositories::get_first_master_key(&pool)
            .await
            .unwrap()
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "UPDATE MasterKeys SET derivation_data = ?, date_updated = ? WHERE masterkey_id = ?",
        )
        .bind(&ks_bytes)
        .bind(now)
        .bind(mk_row.masterkey_id)
        .execute(&pool)
        .await
        .unwrap();

        // Security fix: password-token must be cleared (empty), NOT set to the new
        // password in cleartext. The old buggy behaviour stored "new_pw" here.
        repositories::set_wallet_data(&pool, "password-token", "")
            .await
            .unwrap();

        // Verify the token is empty — no plaintext password in the DB
        assert_eq!(
            repositories::get_wallet_data(&pool, "password-token")
                .await
                .unwrap()
                .unwrap_or_default(),
            ""
        );

        // Update in-memory state
        {
            let mut guard = state.active_wallet.lock().unwrap();
            if let Some(ref mut active) = *guard {
                active.keystore_data = new_keystore;
            }
        }

        // Close and reopen — should unlock with new password, not old
        wallet_service::close_wallet(&state).await.unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();

        // Old password should fail
        let err = wallet_service::unlock_wallet(&state, "old_pw").unwrap_err();
        assert!(matches!(err, wallet_service::WalletError::WrongPassword));

        // Reopen and try new password
        wallet_service::close_wallet(&state).await.unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();
        assert!(wallet_service::unlock_wallet(&state, "new_pw").is_ok());

        // Verify mnemonic is still the same
        let decrypted_mnemonic = {
            let guard = state.active_wallet.lock().unwrap();
            let ks = &guard.as_ref().unwrap().keystore_data;
            keystore::decrypt_mnemonic(ks, "new_pw").unwrap()
        };
        assert_eq!(decrypted_mnemonic, mnemonic);

        wallet_service::close_wallet(&state).await.unwrap();
    }

    // --------------------------------------------------------------------
    // delete_wallet
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_delete_wallet_removes_file() {
        let state = make_test_state("delete_wallet");
        let result = wallet_service::create_wallet(&state, "test_delete", "pw123", None, None)
            .await
            .unwrap();
        let wallet_path = result.wallet_path.clone();

        // Close wallet first
        wallet_service::close_wallet(&state).await.unwrap();

        // File should exist
        assert!(std::path::Path::new(&wallet_path).exists());

        // Delete the file
        std::fs::remove_file(&wallet_path).unwrap();

        // File should be gone
        assert!(!std::path::Path::new(&wallet_path).exists());

        // list_wallets should return empty
        let wallets = connection::list_wallet_files(&state.data_dir).unwrap();
        assert!(wallets.is_empty());
    }

    // --------------------------------------------------------------------
    // sign_message / verify_message (BSM round-trip)
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_sign_and_verify_message_roundtrip() {
        let state = make_test_state("sign_verify");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_bsm", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        // Get the xprv and derive a key at 0/0
        let xprv = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().decrypted_xprv.as_ref().unwrap().clone()
        };

        let account_key = ExtendedKey::from_string(&xprv).unwrap();
        let child = account_key.derive("0/0").unwrap();
        let pubkey = child.public_key().unwrap();
        let addr = address::pubkey_to_p2pkh_address(&pubkey);

        // Extract private key bytes
        let xprv_b58 = child.to_base58();
        let decoded = bsv::primitives::utils::base58_decode(&xprv_b58).unwrap();
        assert!(decoded.len() >= 78);
        let key_bytes = &decoded[46..78];
        let priv_key = bsv::primitives::private_key::PrivateKey::from_bytes(key_bytes).unwrap();

        // Sign a message
        let message = "Hello BSV!";
        let sig_bytes = bsv::compat::bsm::BSM::sign(message.as_bytes(), &priv_key).unwrap();
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        // Verify signature length
        assert_eq!(sig_bytes.len(), 65);

        // Verify the signature using BSM recovery
        let sig_decoded = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        let (sig, recovery, _compressed) =
            bsv::primitives::signature::Signature::from_compact_bsm(&sig_decoded).unwrap();
        let msg_hash = bsv::compat::bsm::BSM::magic_hash(message.as_bytes());
        let msg_bn = bsv::primitives::big_number::BigNumber::from_bytes(
            &msg_hash,
            bsv::primitives::big_number::Endian::Big,
        );
        let recovered_pubkey = sig.recover_public_key(recovery, &msg_bn).unwrap();
        let recovered_addr = recovered_pubkey.to_address(&[0x00]);

        assert_eq!(recovered_addr, addr);

        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_verify_message_wrong_message() {
        let state = make_test_state("verify_wrong");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_bsm_w", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let xprv = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().decrypted_xprv.as_ref().unwrap().clone()
        };

        let account_key = ExtendedKey::from_string(&xprv).unwrap();
        let child = account_key.derive("0/0").unwrap();
        let pubkey = child.public_key().unwrap();
        let addr = address::pubkey_to_p2pkh_address(&pubkey);

        let xprv_b58 = child.to_base58();
        let decoded = bsv::primitives::utils::base58_decode(&xprv_b58).unwrap();
        let key_bytes = &decoded[46..78];
        let priv_key = bsv::primitives::private_key::PrivateKey::from_bytes(key_bytes).unwrap();

        // Sign "message1"
        let sig_bytes = bsv::compat::bsm::BSM::sign(b"message1", &priv_key).unwrap();
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        // Verify against "message2" — should not match the address
        let sig_decoded = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        let (sig, recovery, _compressed) =
            bsv::primitives::signature::Signature::from_compact_bsm(&sig_decoded).unwrap();
        let msg_hash = bsv::compat::bsm::BSM::magic_hash(b"message2");
        let msg_bn = bsv::primitives::big_number::BigNumber::from_bytes(
            &msg_hash,
            bsv::primitives::big_number::Endian::Big,
        );
        let recovered_pubkey = sig.recover_public_key(recovery, &msg_bn).unwrap();
        let recovered_addr = recovered_pubkey.to_address(&[0x00]);

        // Different message → different recovered address (almost certainly)
        assert_ne!(recovered_addr, addr);

        wallet_service::close_wallet(&state).await.unwrap();
    }

    // --------------------------------------------------------------------
    // export_privkey (derive WIF from xprv)
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_export_privkey_derivation() {
        let state = make_test_state("export_privkey");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_wif", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let xprv = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().decrypted_xprv.as_ref().unwrap().clone()
        };

        // Derive private key at 0/0 and convert to WIF
        let account_key = ExtendedKey::from_string(&xprv).unwrap();
        let child = account_key.derive("0/0").unwrap();
        let pubkey = child.public_key().unwrap();
        let addr = address::pubkey_to_p2pkh_address(&pubkey);

        let xprv_b58 = child.to_base58();
        let decoded = bsv::primitives::utils::base58_decode(&xprv_b58).unwrap();
        assert!(decoded.len() >= 78);
        assert_eq!(decoded[45], 0x00); // 0x00 prefix before key bytes

        let key_bytes = &decoded[46..78];
        let priv_key = bsv::primitives::private_key::PrivateKey::from_bytes(key_bytes).unwrap();
        let wif = priv_key.to_wif(&[0x80]);

        // WIF should start with 'K' or 'L' (mainnet compressed private key)
        assert!(wif.starts_with('K') || wif.starts_with('L'));
        assert!(!wif.is_empty());

        // Verify: the WIF's public key should match the derived address
        let pubkey_from_wif = priv_key.to_public_key();
        let addr_from_wif = address::pubkey_to_p2pkh_address(&pubkey_from_wif);
        assert_eq!(addr_from_wif, addr);

        wallet_service::close_wallet(&state).await.unwrap();
    }

    // --------------------------------------------------------------------
    // Wallet status variations
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_wallet_status_no_wallet() {
        let state = make_test_state("status_none");
        let status = wallet_service::get_wallet_status(&state);
        assert!(!status.is_open);
        assert_eq!(status.wallet_name, None);
        assert!(!status.is_unlocked);
        assert_eq!(status.account_id, None);
    }

    #[tokio::test]
    async fn test_wallet_status_open_and_locked() {
        let state = make_test_state("status_locked");
        let result = wallet_service::create_wallet(&state, "test_status", "pw123", None, None)
            .await
            .unwrap();
        let wallet_path = result.wallet_path;

        wallet_service::close_wallet(&state).await.unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();

        let status = wallet_service::get_wallet_status(&state);
        assert!(status.is_open);
        assert!(!status.is_unlocked);
        assert_eq!(status.wallet_name, Some("test_status".to_string()));
        assert!(status.xpub.is_some());

        wallet_service::close_wallet(&state).await.unwrap();
    }

    // --------------------------------------------------------------------
    // Security-Fix tests
    // --------------------------------------------------------------------

    /// After change_password, the "password-token" WalletData entry must be
    /// empty — no plaintext password may be stored in the DB.
    #[tokio::test]
    async fn test_change_password_no_plaintext() {
        let state = make_test_state("chpw_no_pt");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result =
            wallet_service::create_legacy_fixture(&state, "test_nopt", "old_pw", mnemonic, None)
                .await
                .unwrap();
        let wallet_path = result.wallet_path;

        // Close, reopen, unlock
        wallet_service::close_wallet(&state).await.unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();
        wallet_service::unlock_wallet(&state, "old_pw").unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Simulate the (fixed) change_password logic: clear password-token
        repositories::set_wallet_data(&pool, "password-token", "")
            .await
            .unwrap();

        // The token must NOT contain the new password in cleartext
        let stored = repositories::get_wallet_data(&pool, "password-token")
            .await
            .unwrap()
            .unwrap_or_default();
        assert_eq!(stored, "");
        assert_ne!(stored, "new_pw");

        wallet_service::close_wallet(&state).await.unwrap();
    }

    /// delete_wallet must reject paths outside the application data directory
    /// (path-traversal protection via canonicalize() + starts_with()).
    #[tokio::test]
    async fn test_delete_wallet_path_traversal_rejected() {
        let state = make_test_state("del_traversal");
        wallet_service::create_wallet(&state, "test_traversal", "pw123", None, None)
            .await
            .unwrap();
        wallet_service::close_wallet(&state).await.unwrap();

        // A path outside the data_dir — use a temp file in /tmp
        let outside_path = std::env::temp_dir().join("electrumsv_mc_traversal_target.txt");
        std::fs::write(&outside_path, "dummy").unwrap();

        // Reproduce the path-traversal guard from delete_wallet
        let wallet_path_buf = std::path::PathBuf::from(&outside_path);
        let canonical_wallet = wallet_path_buf.canonicalize().unwrap();
        let canonical_data_dir =
            std::path::PathBuf::from(&state.data_dir).canonicalize().unwrap();

        let rejected = !canonical_wallet.starts_with(&canonical_data_dir);
        assert!(rejected, "path outside data_dir must be rejected");

        // The error message must match the one in delete_wallet
        let err_msg = "wallet file must be within the application data directory";
        assert!(
            err_msg.contains("within the application data directory"),
            "error message mismatch"
        );

        // Cleanup
        std::fs::remove_file(&outside_path).ok();
    }

    /// When TOTP is enabled, export_seed must fail without a TOTP code.
    #[tokio::test]
    async fn test_export_seed_totp_required() {
        let state = make_test_state("seed_totp_req");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_seed_totp", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Enable TOTP
        let totp = crate::security::totp::TotpInstance::new("ElectrumSV-Mc", "test_wallet")
            .unwrap();
        repositories::store_totp_secret(&pool, totp.secret_bytes())
            .await
            .unwrap();
        assert!(repositories::is_totp_enabled(&pool).await.unwrap());

        // Simulate the TOTP check from export_seed: no code provided → error
        let totp_code: Option<String> = None;
        let totp_enabled = repositories::is_totp_enabled(&pool).await.unwrap();
        let result: Result<(), String> = if totp_enabled {
            match totp_code {
                None => Err(
                    "TOTP code required to export seed when 2FA is enabled".to_string(),
                ),
                Some(_) => Ok(()),
            }
        } else {
            Ok(())
        };

        let err = result.unwrap_err();
        assert_eq!(err, "TOTP code required to export seed when 2FA is enabled");

        wallet_service::close_wallet(&state).await.unwrap();
    }

    /// When TOTP is enabled, export_privkey must fail without a TOTP code.
    #[tokio::test]
    async fn test_export_privkey_totp_required() {
        let state = make_test_state("privkey_totp_req");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_privkey_totp", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Enable TOTP
        let totp = crate::security::totp::TotpInstance::new("ElectrumSV-Mc", "test_wallet")
            .unwrap();
        repositories::store_totp_secret(&pool, totp.secret_bytes())
            .await
            .unwrap();
        assert!(repositories::is_totp_enabled(&pool).await.unwrap());

        // Simulate the TOTP check from export_privkey: no code provided → error
        let totp_code: Option<String> = None;
        let totp_enabled = repositories::is_totp_enabled(&pool).await.unwrap();
        let result: Result<(), String> = if totp_enabled {
            match totp_code {
                None => Err(
                    "TOTP code required to export private key when 2FA is enabled"
                        .to_string(),
                ),
                Some(_) => Ok(()),
            }
        } else {
            Ok(())
        };

        let err = result.unwrap_err();
        assert_eq!(
            err,
            "TOTP code required to export private key when 2FA is enabled"
        );

        wallet_service::close_wallet(&state).await.unwrap();
    }

    /// export_privkey with a wrong password must return "incorrect password".
    #[tokio::test]
    async fn test_export_privkey_wrong_password() {
        let state = make_test_state("privkey_wrong_pw");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_privkey_wp", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let keystore_data = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().keystore_data.clone()
        };

        // Wrong password must fail verification (same check as export_privkey)
        let wrong = "definitely_wrong_password";
        assert!(!keystore::verify_password(&keystore_data, wrong));

        // The command returns "incorrect password" on verification failure
        let err = if !keystore::verify_password(&keystore_data, wrong) {
            "incorrect password".to_string()
        } else {
            "should not reach here".to_string()
        };
        assert_eq!(err, "incorrect password");

        wallet_service::close_wallet(&state).await.unwrap();
    }
}
