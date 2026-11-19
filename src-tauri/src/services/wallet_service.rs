// services/wallet_service.rs — Wallet lifecycle orchestration
//
// Coordinates mnemonic generation, BIP32 key derivation, DB creation,
// and state management for wallet create/open/unlock operations.
//
// This is the Rust equivalent of Python's wallet_service.py.

use crate::core::{keystore, mnemonic};
use crate::db::{connection, repositories};
use crate::security::encryption;
use crate::state::{ActiveWallet, AppState};
use std::path::{Path, PathBuf};

/// Join a directory and filename into a cross-platform path string.
/// Uses std::path::PathBuf so the OS-native separator is applied
/// (/ on Unix, \ on Windows).
fn join_path(dir: &str, filename: &str) -> String {
    PathBuf::from(dir)
        .join(filename)
        .to_string_lossy()
        .to_string()
}

fn new_instance_token() -> Result<String, WalletError> {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut bytes)
        .map_err(|_| WalletError::Internal(anyhow::anyhow!("random generation failed")))?;
    Ok(hex::encode(bytes))
}

fn lock_wallet(path: &Path) -> Result<std::fs::File, WalletError> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).open(lock_path)
        .map_err(|e| WalletError::Internal(e.into()))?;
    file.try_lock().map_err(|e| WalletError::Internal(anyhow::anyhow!("wallet is already in use or cannot be locked: {e}")))?;
    Ok(file)
}

/// Result of creating a new wallet.
#[derive(Debug, serde::Serialize)]
pub struct CreateWalletResult {
    pub wallet_instance_token: String,
    /// The BIP39 mnemonic phrase (only returned on creation, never stored in plaintext)
    pub mnemonic: String,
    /// Absolute path to the .sqlite file
    pub wallet_path: String,
    /// Account ID of the created default account
    pub account_id: i64,
    /// Whether a new mnemonic was generated (true) or an existing one was used (false)
    pub is_new_mnemonic: bool,
}

/// Result of opening an existing wallet.
#[derive(Debug, serde::Serialize)]
pub struct OpenWalletResult {
    pub wallet_instance_token: String,
    pub wallet_path: String,
    pub wallet_name: String,
    pub account_name: String,
    pub is_unlocked: bool,
}

/// Result of getting wallet status.
#[derive(Debug, serde::Serialize)]
pub struct WalletStatus {
    pub wallet_instance_token: Option<String>,
    pub is_open: bool,
    pub wallet_name: Option<String>,
    pub is_unlocked: bool,
    pub account_id: Option<i64>,
    pub xpub: Option<String>,
    /// Loaded format marker; this is not an authentication result.
    pub wallet_format: Option<u32>,
}

/// Error type for wallet operations.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("password is required")]
    PasswordRequired,
    #[error("wallet already exists: {0}")]
    WalletAlreadyExists(String),
    #[error("wallet not found: {0}")]
    WalletNotFound(String),
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("wallet operation in progress") ]
    Busy,
    #[error("no wallet is currently open")]
    NoWalletOpen,
    #[error("wallet is already unlocked")]
    AlreadyUnlocked,
    #[error("wallet is locked — unlock first")]
    WalletLocked,
    #[error("wrong password")]
    WrongPassword,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("encryption error: {0}")]
    Encryption(#[from] encryption::EncryptionError),
    #[error("BSV SDK error: {0}")]
    BsvSdk(String),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<bsv::compat::error::CompatError> for WalletError {
    fn from(e: bsv::compat::error::CompatError) -> Self {
        WalletError::BsvSdk(e.to_string())
    }
}

#[derive(Clone, Copy, Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bip39RestoreMode {
    StandardBip39,
    HistoricalMc,
}

/// Restore a valid BIP39 mnemonic using an explicitly chosen passphrase convention.
pub async fn restore_bip39_wallet(
    state: &AppState, name: &str, password: &str, phrase: &str, passphrase: &str,
    mode: Bip39RestoreMode,
) -> Result<CreateWalletResult, WalletError> {
    use unicode_normalization::UnicodeNormalization;
    use zeroize::Zeroizing;
    bsv::compat::bip39::Mnemonic::from_string(phrase, bsv::compat::bip39::Language::English)
        .map_err(|_| WalletError::InvalidMnemonic("valid BIP39 checksum required".into()))?;
    let effective = Zeroizing::new(match mode {
        Bip39RestoreMode::StandardBip39 => passphrase.nfkd().collect::<String>(),
        Bip39RestoreMode::HistoricalMc => passphrase.to_owned(),
    });
    create_wallet(state, name, password, Some(phrase), Some(&effective)).await
}

/// Create a new wallet with a BIP32 account from a BIP39 mnemonic.
///
/// If no mnemonic is provided, a new 12-word mnemonic is generated.
/// The mnemonic is returned to the caller. The new wallet stores the mnemonic,
/// passphrase and derived xprv together in an encrypted authenticated bundle.
pub async fn create_wallet(
    state: &AppState,
    name: &str,
    password: &str,
    provided_mnemonic: Option<&str>,
    mnemonic_passphrase: Option<&str>,
) -> Result<CreateWalletResult, WalletError> {
    let _operation = state.wallet_operation.lock().await;
    if password.is_empty() {
        return Err(WalletError::PasswordRequired);
    }

    let name = if name.is_empty() {
        "default_wallet"
    } else {
        name
    };
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(WalletError::Internal(anyhow::anyhow!("invalid wallet name")));
    }
    let wallet_path = join_path(&state.data_dir, &format!("{}.sqlite", name));

    let instance_token = new_instance_token()?;

    let wallet_lock = std::sync::Arc::new(lock_wallet(Path::new(&wallet_path))?);
    if Path::new(&wallet_path).exists() {
        return Err(WalletError::WalletAlreadyExists(wallet_path));
    }

    // Generate or validate mnemonic
    let (mnemonic_str, is_new_mnemonic) = match provided_mnemonic {
        Some(m) => {
            mnemonic::validate_mnemonic(m)
                .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
            (m.to_string(), false)
        }
        None => {
            let m =
                mnemonic::generate_mnemonic().map_err(|e| WalletError::BsvSdk(e.to_string()))?;
            (m, true)
        }
    };

    // Derive seed and BIP32 keys
    let seed = mnemonic::mnemonic_to_seed(&mnemonic_str, mnemonic_passphrase.unwrap_or(""))
        .map_err(|e| WalletError::BsvSdk(e.to_string()))?;
    let derived = keystore::derive_keys_from_seed(&seed)?;

    // New wallets use one authenticated bundle. Legacy wallets are not converted here.
    use rand::RngCore;
    let mut wallet_id = [0u8; 16];
    rand::rngs::OsRng.try_fill_bytes(&mut wallet_id).map_err(|_| WalletError::Internal(anyhow::anyhow!("random generation failed")))?;
    let context = crate::security::envelope::WalletContext { wallet_id, xpub: derived.xpub.clone(), derivation: keystore::DERIVATION_PATH.into() };
    let bundle = crate::security::wallet_bundle::WalletBundle { version: 1, xprv: derived.xprv.clone(), mnemonic: mnemonic_str.clone(), passphrase: mnemonic_passphrase.unwrap_or("").into(), totp: None };
    let envelope = crate::security::wallet_bundle::seal(password, &context, &bundle).await.map_err(|e| WalletError::Internal(anyhow::anyhow!(e)))?;
    let record = crate::services::wallet_security::StoredWallet::encode(&context, &envelope).map_err(|e| WalletError::Internal(anyhow::anyhow!(e)))?;
    let ks_data = keystore::KeyStoreData { xpub: derived.xpub.clone(), xprv: String::new(), seed_type: "bundle-v1".into(), derivation: context.derivation.clone(), seed: String::new(), passphrase: None };
    connection::create_wallet_db(&wallet_path).await?;
    let pool = connection::open_wallet_db_locked(&wallet_path, wallet_lock.clone()).await?;
    let mut tx = pool.begin().await.map_err(|e| WalletError::Internal(e.into()))?;
    let now = chrono::Utc::now().timestamp();
    let masterkey_id = sqlx::query("INSERT INTO MasterKeys (parent_masterkey_id, derivation_type, derivation_data, date_created, date_updated) VALUES (NULL, ?, ?, ?, ?)")
        .bind(keystore::DERIVATION_TYPE_BIP32).bind(record).bind(now).bind(now).execute(&mut *tx).await.map_err(|e| WalletError::Internal(e.into()))?.last_insert_rowid();
    let account_id = sqlx::query("INSERT INTO Accounts (default_masterkey_id, default_script_type, account_name, date_created, date_updated) VALUES (?, ?, ?, ?, ?)")
        .bind(masterkey_id).bind(repositories::script_type::P2PKH).bind("Standard account").bind(now).bind(now).execute(&mut *tx).await.map_err(|e| WalletError::Internal(e.into()))?.last_insert_rowid();
    sqlx::query("INSERT INTO WalletData(key,value,date_created,date_updated) VALUES('crypto-format','wallet-envelope-v1',?,?)").bind(now).bind(now).execute(&mut *tx).await.map_err(|e| WalletError::Internal(e.into()))?;
    for (key, value) in [("migration", "34"), ("next_masterkey_id", "2"), ("next_account_id", "2")] {
        sqlx::query("UPDATE WalletData SET value=?,date_updated=? WHERE key=?").bind(value).bind(now).bind(key).execute(&mut *tx).await.map_err(|e| WalletError::Internal(e.into()))?;
    }
    tx.commit().await.map_err(|e| WalletError::Internal(e.into()))?;
    // Set as active wallet in state
    let active = ActiveWallet {
        instance_id: std::sync::Arc::new(()),
        instance_token: instance_token.clone(),
        wallet_lock,
        wallet_path: wallet_path.clone(),
        wallet_name: name.to_string(),
        db_pool: pool,
        keystore_data: ks_data,
        account_id,
        decrypted_xprv: Some(derived.xprv), // freshly created — already unlocked
        secure_wallet: Some(crate::state::SecureWallet { context, envelope, bundle: Some(bundle), generation: 0, needs_reopen: false, pending_totp: None }),
        legacy_pending_totp: None,
        #[cfg(test)] commit_barrier: None,
        #[cfg(test)] migration_write_fail: false,
    };

    retire_active_wallet(state).await?;
    let mut guard = state.active_wallet.lock().unwrap();
    *guard = Some(active);

    log::info!(
        "Wallet created at {} with account {} (new mnemonic: {})",
        wallet_path,
        account_id,
        is_new_mnemonic
    );

    Ok(CreateWalletResult {
        wallet_instance_token: instance_token,
        mnemonic: mnemonic_str,
        wallet_path,
        account_id,
        is_new_mnemonic,
    })
}

/// Open an existing wallet from disk.
///
/// Loads the DB and reads the keystore data from MasterKeys.
/// The wallet is opened in locked state — call unlock_wallet to decrypt the xprv.
pub async fn open_wallet(
    state: &AppState,
    wallet_path: &str,
) -> Result<OpenWalletResult, WalletError> {
    let _operation = state.wallet_operation.lock().await;
    let name = if wallet_path.ends_with(".sqlite") { wallet_path.to_string() } else { format!("{}.sqlite", wallet_path) };
    let path = Path::new(&name);
    let candidate = if path.components().count() == 1 { Path::new(&state.data_dir).join(path) } else { path.to_path_buf() };
    let meta = std::fs::symlink_metadata(&candidate).map_err(|_| WalletError::WalletNotFound(candidate.to_string_lossy().to_string()))?;
    if meta.file_type().is_symlink() || !meta.is_file() { return Err(WalletError::Internal(anyhow::anyhow!("wallet must be a regular file"))); }
    let canonical = candidate.canonicalize().map_err(|e| WalletError::Internal(e.into()))?;
    let root = Path::new(&state.data_dir).canonicalize().map_err(|e| WalletError::Internal(e.into()))?;
    if !canonical.starts_with(&root) { return Err(WalletError::Internal(anyhow::anyhow!("wallet must be inside the wallet data directory"))); }
    let wallet_path = canonical.to_string_lossy().to_string();

    // Check if already open
    {
        let guard = state.active_wallet.lock().unwrap();
        if let Some(ref active) = *guard {
            if active.wallet_path == wallet_path {
                return Ok(OpenWalletResult {
                    wallet_instance_token: active.instance_token.clone(),
                    wallet_path: active.wallet_path.clone(),
                    wallet_name: active.wallet_name.clone(),
                    account_name: "Standard account".to_string(),
                    is_unlocked: active.is_unlocked(),
                });
            }
        }
    }

    let instance_token = new_instance_token()?;
    let wallet_lock = std::sync::Arc::new(lock_wallet(Path::new(&wallet_path))?);
    // Open DB
    let pool = connection::open_wallet_db_locked(&wallet_path, wallet_lock.clone()).await?;

    // Read master key
    let mk_row = repositories::get_first_master_key(&pool)
        .await?
        .ok_or_else(|| WalletError::Internal(anyhow::anyhow!("No master key found in wallet")))?;

    let version = repositories::get_wallet_data(&pool, "migration").await?.ok_or_else(|| WalletError::Internal(anyhow::anyhow!("missing wallet version")))?;
    let (ks_data, secure_wallet) = if version == "34" {
        let counts: (i64, i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM MasterKeys), (SELECT count(*) FROM Accounts), (SELECT count(*) FROM KeyInstances WHERE derivation_type != 3 OR masterkey_id IS NULL OR account_id != (SELECT account_id FROM Accounts LIMIT 1) OR masterkey_id != (SELECT masterkey_id FROM MasterKeys LIMIT 1)), (SELECT count(*) FROM MultisigConfigs)").fetch_one(&pool).await.map_err(|e| WalletError::Internal(e.into()))?;
        let account_ref: (Option<i64>, i32) = sqlx::query_as("SELECT default_masterkey_id, default_script_type FROM Accounts").fetch_one(&pool).await.map_err(|e| WalletError::Internal(e.into()))?;
        if counts != (1, 1, 0, 0) || mk_row.derivation_type != keystore::DERIVATION_TYPE_BIP32 || mk_row.parent_masterkey_id.is_some() || account_ref != (Some(mk_row.masterkey_id), repositories::script_type::P2PKH) || mk_row.derivation_data.len() > 140_000 { return Err(WalletError::Internal(anyhow::anyhow!("unsupported wallet key inventory"))); }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct KnownKeyPath { subpath: [u32; 2] }
        let (key_count, invalid_count): (i64, i64) = sqlx::query_as("SELECT count(*), COALESCE(sum(CASE WHEN script_type != 2 OR length(derivation_data) > 256 THEN 1 ELSE 0 END),0) FROM KeyInstances").fetch_one(&pool).await.map_err(|e| WalletError::Internal(e.into()))?;
        if key_count > 100_000 || invalid_count != 0 { return Err(WalletError::Internal(anyhow::anyhow!("unsupported wallet key inventory"))); }
        let paths: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT derivation_data FROM KeyInstances").fetch_all(&pool).await.map_err(|e| WalletError::Internal(e.into()))?;
        for (data,) in paths {
            let path: KnownKeyPath = serde_json::from_slice(&data).map_err(|_| WalletError::Internal(anyhow::anyhow!("unsupported wallet key path")))?;
            if path.subpath[0] > 1 || path.subpath[1] >= (1 << 31) { return Err(WalletError::Internal(anyhow::anyhow!("unsupported wallet key path"))); }
        }
        let record: crate::services::wallet_security::StoredWallet = serde_json::from_slice(&mk_row.derivation_data).map_err(|_| WalletError::Internal(anyhow::anyhow!("invalid secure wallet record")))?;
        if record.format != "wallet-envelope-v1" { return Err(WalletError::Internal(anyhow::anyhow!("unsupported wallet format"))); }
        let context = crate::security::envelope::WalletContext { wallet_id: record.wallet_id, xpub: record.xpub.clone(), derivation: record.derivation.clone() };
        let ks = keystore::KeyStoreData { xpub: record.xpub, xprv: String::new(), seed_type: "bundle-v1".into(), derivation: record.derivation, seed: String::new(), passphrase: None };
        (ks, Some(crate::state::SecureWallet { context, envelope: record.envelope.into_bytes(), bundle: None, generation: 0, needs_reopen: false, pending_totp: None }))
    } else {
        let ks = keystore::keystore_data_from_bytes(&mk_row.derivation_data).map_err(|e| WalletError::Internal(anyhow::anyhow!("Failed to parse keystore data: {}", e)))?;
        (ks, None)
    };

    // Read account
    let account = repositories::get_first_account(&pool).await?;
    let (account_name, account_id) = match account {
        Some(a) => (a.account_name, a.account_id),
        None => ("Unknown".to_string(), 0),
    };

    // Extract wallet name from path
    let wallet_name = Path::new(&wallet_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Set as active wallet (locked)
    let active = ActiveWallet {
        instance_id: std::sync::Arc::new(()),
        instance_token: instance_token.clone(),
        wallet_lock,
        wallet_path: wallet_path.clone(),
        wallet_name: wallet_name.clone(),
        db_pool: pool,
        keystore_data: ks_data,
        account_id,
        decrypted_xprv: None, // locked
        secure_wallet,
        legacy_pending_totp: None,
        #[cfg(test)] commit_barrier: None,
        #[cfg(test)] migration_write_fail: false,
    };

    retire_active_wallet(state).await?;
    let mut guard = state.active_wallet.lock().unwrap();
    *guard = Some(active);

    log::info!("Wallet opened: {} (locked)", wallet_path);

    Ok(OpenWalletResult {
        wallet_instance_token: instance_token,
        wallet_path,
        wallet_name: wallet_name.clone(),
        account_name,
        is_unlocked: false,
    })
}

/// Close the currently open wallet.
async fn retire_active_wallet(state: &AppState) -> Result<bool, WalletError> {
    let active = state.active_wallet.lock().unwrap().take();
    if let Some(wallet) = active {
        wallet.db_pool.close().await;
        wallet.wallet_lock.unlock().map_err(|e| WalletError::Internal(e.into()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub async fn close_wallet(state: &AppState) -> Result<(), WalletError> {
    let _operation = state.wallet_operation.try_lock().map_err(|_| WalletError::Busy)?;
    if !retire_active_wallet(state).await? { return Err(WalletError::NoWalletOpen); }
    log::info!("Wallet closed");
    Ok(())
}

/// Unlock the currently open wallet by decrypting the xprv with the password.
pub fn unlock_wallet(state: &AppState, password: &str) -> Result<(), WalletError> {
    let _operation = state.wallet_operation.try_lock().map_err(|_| WalletError::Busy)?;
    let mut guard = state.active_wallet.lock().unwrap();
    let active = guard.as_mut().ok_or(WalletError::NoWalletOpen)?;

    if active.secure_wallet.is_some() { return Err(WalletError::Internal(anyhow::anyhow!("secure wallets require authorized async unlock"))); }
    if active.is_unlocked() {
        return Err(WalletError::AlreadyUnlocked);
    }

    if !keystore::verify_password(&active.keystore_data, password) { return Err(WalletError::WrongPassword); }
    let xprv = keystore::decrypt_xprv(&active.keystore_data, password)?;
    active.decrypted_xprv = Some(xprv);

    log::info!("Wallet unlocked: {}", active.wallet_name);
    Ok(())
}

/// Unlock only after the same password and TOTP checks used by every frontend.
pub async fn unlock_wallet_authorized(state: &AppState, password: &str, code: Option<&str>) -> Result<(), String> {
    let _operation = state.wallet_operation.lock().await;
    if crate::services::wallet_security::unlock_locked(state, &_operation, password, code).await?.is_some() { return Ok(()); }
    let (pool, instance_id) = {
        let guard = state.active_wallet.lock().map_err(|_| "wallet state unavailable")?;
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        if !keystore::verify_password(&active.keystore_data, password) { return Err("incorrect password".into()); }
        (active.db_pool.clone(), active.instance_id.clone())
    };
    if let Some(secret) = repositories::load_totp_secret(&pool).await.map_err(|e| e.to_string())? {
        let code = code.filter(|c| !c.is_empty()).ok_or("TOTP code required")?;
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").map_err(|e| e.to_string())?;
        if !totp.verify_current(code).map_err(|e| e.to_string())? { return Err("invalid TOTP code".into()); }
    }
    finish_authorized_unlock(state, &instance_id, password)
}

fn finish_authorized_unlock(state: &AppState, instance_id: &std::sync::Arc<()>, password: &str) -> Result<(), String> {
    let mut guard = state.active_wallet.lock().map_err(|_| "wallet state unavailable")?;
    let active = guard.as_mut().ok_or("no wallet is currently open")?;
    if !std::sync::Arc::ptr_eq(&active.instance_id, instance_id) { return Err("wallet changed during authentication".into()); }
    if active.is_unlocked() { return Err("wallet is already unlocked".into()); }
    active.decrypted_xprv = Some(keystore::decrypt_xprv(&active.keystore_data, password).map_err(|e| e.to_string())?);
    Ok(())
}

/// Get the status of the currently open wallet.
pub fn get_wallet_status(state: &AppState) -> WalletStatus {
    let guard = state.active_wallet.lock().unwrap();
    match &*guard {
        None => WalletStatus {
            wallet_instance_token: None,
            is_open: false,
            wallet_name: None,
            is_unlocked: false,
            account_id: None,
            xpub: None,
            wallet_format: None,
        },
        Some(active) => WalletStatus {
            wallet_instance_token: Some(active.instance_token.clone()),
            is_open: true,
            wallet_name: Some(active.wallet_name.clone()),
            is_unlocked: active.is_unlocked(),
            account_id: Some(active.account_id),
            xpub: Some(active.keystore_data.xpub.clone()),
            wallet_format: Some(if active.secure_wallet.is_some() { 34 } else { 33 }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_test_state(test_name: &str) -> AppState {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir().join(format!("electrumsv_mc_ws_{}_{}", test_name, id));
        // Clean up any leftover from previous test runs
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir).ok();
        }
        std::fs::create_dir_all(&temp_dir).unwrap();
        // Construct AppState directly with the unique data_dir
        AppState {
            data_dir: temp_dir.to_string_lossy().to_string(),
            active_wallet: std::sync::Mutex::new(None),
            network: std::sync::Mutex::new(crate::state::NetworkState::new()),
            pending_plans: std::sync::Mutex::new(std::collections::HashMap::new()),
            wallet_operation: tokio::sync::Mutex::new(()),
        }
    }

    #[tokio::test]
    async fn test_authorized_unlock_rejects_changed_wallet_instance() {
        let state = make_test_state("auth_switch");
        create_wallet(&state, "a", "same-password", None, None).await.unwrap();
        let first_id = state.active_wallet.lock().unwrap().as_ref().unwrap().instance_id.clone();
        close_wallet(&state).await.unwrap();
        create_wallet(&state, "b", "same-password", None, None).await.unwrap();
        close_wallet(&state).await.unwrap();
        open_wallet(&state, "b").await.unwrap();
        assert!(finish_authorized_unlock(&state, &first_id, "same-password").is_err());
        assert!(!get_wallet_status(&state).is_unlocked);
        close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_wallet_generates_mnemonic() {
        let state = make_test_state("gen_mnemonic");
        let result = create_wallet(&state, "test_create", "password123", None, None)
            .await
            .unwrap();

        assert!(result.is_new_mnemonic);
        assert!(!result.mnemonic.is_empty());
        let words: Vec<&str> = result.mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        assert_eq!(result.account_id, 1);

        // Wallet should be open and unlocked
        let status = get_wallet_status(&state);
        assert!(status.is_open);
        assert!(status.is_unlocked);
        assert_eq!(status.wallet_name, Some("test_create".to_string()));

        close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_wallet_with_existing_mnemonic() {
        let state = make_test_state("existing_mnemonic");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let result = create_wallet(&state, "test_existing", "password123", Some(mnemonic), None)
            .await
            .unwrap();

        assert!(!result.is_new_mnemonic);
        assert_eq!(result.mnemonic, mnemonic);

        close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_wallet_invalid_mnemonic() {
        let state = make_test_state("invalid_mnemonic");
        let result = create_wallet(
            &state,
            "test_invalid",
            "password123",
            Some("not a valid mnemonic"),
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_wallet_no_password() {
        let state = make_test_state("no_password");
        let result = create_wallet(&state, "test_no_pw", "", None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_wallet_duplicate_name() {
        let state = make_test_state("dup_name");
        create_wallet(&state, "test_dup", "password123", None, None)
            .await
            .unwrap();
        close_wallet(&state).await.unwrap();

        let result = create_wallet(&state, "test_dup", "password123", None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_open_wallet_locked() {
        let state = make_test_state("open_locked");
        create_wallet(&state, "test_open", "password123", None, None)
            .await
            .unwrap();
        close_wallet(&state).await.unwrap();

        // Wallet should not be open
        let status = get_wallet_status(&state);
        assert!(!status.is_open);

        // Open it
        let wallet_path = join_path(&state.data_dir, "test_open.sqlite");
        let result = open_wallet(&state, &wallet_path).await.unwrap();
        assert!(!result.is_unlocked);

        let status = get_wallet_status(&state);
        assert!(status.is_open);
        assert!(!status.is_unlocked);

        close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn low_level_unlock_rejects_empty_password_for_encrypted_wallet() {
        let state = make_test_state("unlock_empty_protected");
        create_wallet(&state, "protected", "secret", None, None).await.unwrap();
        close_wallet(&state).await.unwrap();
        open_wallet(&state, "protected").await.unwrap();
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        let original = repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data;
        assert!(unlock_wallet(&state, "").is_err());
        assert!(!get_wallet_status(&state).is_unlocked);
        assert!(unlock_wallet_authorized(&state, "", None).await.is_err());
        assert!(!get_wallet_status(&state).is_unlocked);
        assert_eq!(repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data, original);
        drop(pool);
        unlock_wallet_authorized(&state, "secret", None).await.unwrap();
        close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_unlock_wallet_correct_password() {
        let state = make_test_state("unlock_correct");
        create_wallet(&state, "test_unlock", "password123", None, None)
            .await
            .unwrap();
        close_wallet(&state).await.unwrap();

        let wallet_path = join_path(&state.data_dir, "test_unlock.sqlite");
        open_wallet(&state, &wallet_path).await.unwrap();

        // Should be locked
        let status = get_wallet_status(&state);
        assert!(!status.is_unlocked);

        // Unlock
        unlock_wallet_authorized(&state, "password123", None).await.unwrap();

        let status = get_wallet_status(&state);
        assert!(status.is_unlocked);

        close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_unlock_wallet_wrong_password() {
        let state = make_test_state("unlock_wrong");
        create_wallet(&state, "test_wrong_pw", "password123", None, None)
            .await
            .unwrap();
        close_wallet(&state).await.unwrap();

        let wallet_path = join_path(&state.data_dir, "test_wrong_pw.sqlite");
        open_wallet(&state, &wallet_path).await.unwrap();

        let result = unlock_wallet(&state, "wrong_password");
        assert!(result.is_err());

        // Should still be locked
        let status = get_wallet_status(&state);
        assert!(!status.is_unlocked);

        close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_full_lifecycle() {
        let state = make_test_state("lifecycle");

        // 1. Create
        let create_result = create_wallet(&state, "test_lifecycle", "mypass", None, None)
            .await
            .unwrap();
        assert!(create_result.is_new_mnemonic);
        assert!(get_wallet_status(&state).is_unlocked);

        // 2. Close
        close_wallet(&state).await.unwrap();
        assert!(!get_wallet_status(&state).is_open);

        // 3. Open
        let wallet_path = join_path(&state.data_dir, "test_lifecycle.sqlite");
        open_wallet(&state, &wallet_path).await.unwrap();
        assert!(get_wallet_status(&state).is_open);
        assert!(!get_wallet_status(&state).is_unlocked);

        // 4. Unlock
        unlock_wallet_authorized(&state, "mypass", None).await.unwrap();
        assert!(get_wallet_status(&state).is_unlocked);

        // 5. Close
        close_wallet(&state).await.unwrap();
        assert!(!get_wallet_status(&state).is_open);
    }

    #[tokio::test]
    async fn test_open_nonexistent_wallet() {
        let state = make_test_state("nonexistent");
        let result = open_wallet(&state, "/nonexistent/wallet.sqlite").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unlock_no_wallet_open() {
        let state = make_test_state("unlock_none");
        let result = unlock_wallet(&state, "password");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_close_no_wallet_open() {
        let state = make_test_state("close_none");
        let result = close_wallet(&state).await;
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod secure_wallet_lifecycle_tests {
    use super::*;
    async fn raw_pool(path: &std::path::Path) -> sqlx::SqlitePool {
        sqlx::sqlite::SqlitePoolOptions::new().max_connections(1)
            .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(path).create_if_missing(false)).await.unwrap()
    }
    #[tokio::test]
    async fn new_secure_wallet_reopens_and_unlocks() {
        let dir = std::env::temp_dir().join(format!("wallet-secure-test-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = AppState::new(); state.data_dir = dir.to_string_lossy().into();
        create_wallet(&state, "synthetic", "password", Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), Some("passphrase")).await.unwrap();
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        assert_eq!(repositories::get_wallet_data(&pool, "migration").await.unwrap().as_deref(), Some("34"));
        close_wallet(&state).await.unwrap();
        open_wallet(&state, "synthetic").await.unwrap();
        assert!(unlock_wallet_authorized(&state, "wrong", None).await.is_err());
        assert!(!get_wallet_status(&state).is_unlocked);
        unlock_wallet_authorized(&state, "password", None).await.unwrap();
        assert!(get_wallet_status(&state).is_unlocked);
        close_wallet(&state).await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn rejects_missing_marker_changed_metadata_and_unknown_key_inventory() {
        let dir = std::env::temp_dir().join(format!("wallet-secure-mutation-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = AppState::new(); state.data_dir = dir.to_string_lossy().into();
        create_wallet(&state, "synthetic", "password", Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), None).await.unwrap();
        close_wallet(&state).await.unwrap();
        let pool = raw_pool(&dir.join("synthetic.sqlite")).await;
        sqlx::query("DELETE FROM WalletData WHERE key='crypto-format'").execute(&pool).await.unwrap();
        assert!(open_wallet(&state, "synthetic").await.is_err());
        sqlx::query("INSERT INTO WalletData(key,value,date_created,date_updated) VALUES('crypto-format','wallet-envelope-v1',0,0)").execute(&pool).await.unwrap();
        let (original,): (Vec<u8>,) = sqlx::query_as("SELECT derivation_data FROM MasterKeys").fetch_one(&pool).await.unwrap();
        let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
        record["xpub"] = serde_json::json!("changed-public-key");
        sqlx::query("UPDATE MasterKeys SET derivation_data=?").bind(serde_json::to_vec(&record).unwrap()).execute(&pool).await.unwrap();
        open_wallet(&state, "synthetic").await.unwrap();
        assert!(unlock_wallet_authorized(&state, "password", None).await.is_err());
        close_wallet(&state).await.unwrap();
        sqlx::query("UPDATE MasterKeys SET derivation_data=?").bind(original).execute(&pool).await.unwrap();
        sqlx::query("UPDATE Accounts SET default_script_type=999").execute(&pool).await.unwrap();
        assert!(open_wallet(&state, "synthetic").await.is_err());
        sqlx::query("UPDATE Accounts SET default_script_type=2").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO KeyInstances(account_id,masterkey_id,derivation_type,derivation_data,script_type,flags,date_created,date_updated) VALUES(1,1,3,?,2,0,0,0)").bind(br#"{"subpath":[0,7]}"#.as_slice()).execute(&pool).await.unwrap();
        open_wallet(&state, "synthetic").await.unwrap();
        close_wallet(&state).await.unwrap();
        sqlx::query("UPDATE KeyInstances SET script_type=999").execute(&pool).await.unwrap();
        assert!(open_wallet(&state, "synthetic").await.is_err());
        sqlx::query("UPDATE KeyInstances SET script_type=2,derivation_data=?").bind(br#"{"subpath":[0,7],"unexpected":true}"#.as_slice()).execute(&pool).await.unwrap();
        assert!(open_wallet(&state, "synthetic").await.is_err());
        sqlx::query("UPDATE KeyInstances SET derivation_data=?").bind(br#"{"subpath":[2,7]}"#.as_slice()).execute(&pool).await.unwrap();
        assert!(open_wallet(&state, "synthetic").await.is_err());
        pool.close().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn secure_setup_backup_rotation_and_locked_recovery() {
        use crate::commands::{wallet, extra};
        let dir = std::env::temp_dir().join(format!("wallet-secure-flow-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = AppState::new(); state.data_dir = dir.to_string_lossy().into();
        create_wallet(&state, "synthetic", "old", Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), None).await.unwrap();
        let setup = wallet::begin_totp_setup_inner(&state, "old").await.unwrap();
        let secret = totp_rs::Secret::Encoded(setup.secret_base32).to_bytes().unwrap();
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").unwrap();
        let fresh_code = || totp.generate_current().unwrap();
        assert!(wallet::confirm_totp_setup_inner(&state, "old", "invalid").await.is_err());
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        sqlx::query("CREATE TRIGGER reject_secure_update BEFORE UPDATE ON MasterKeys BEGIN SELECT RAISE(ABORT,'test failure'); END").execute(&pool).await.unwrap();
        assert!(wallet::confirm_totp_setup_inner(&state, "old", &fresh_code()).await.is_err());
        sqlx::query("DROP TRIGGER reject_secure_update").execute(&pool).await.unwrap();
        wallet::confirm_totp_setup_inner(&state, "old", &fresh_code()).await.unwrap();
        assert!(wallet::begin_totp_setup_inner(&state, "old").await.is_err());
        let codes = wallet::generate_totp_recovery_codes_inner(&state, "old".into(), fresh_code()).await.unwrap();
        assert_eq!(codes.len(), 10);
        let backup = dir.join("backup.sqlite").to_string_lossy().to_string();
        assert!(extra::backup_wallet_authorized(&state, backup.clone(), "old".into(), None).await.is_err());
        extra::backup_wallet_authorized(&state, backup, "old".into(), Some(fresh_code())).await.unwrap();
        assert!(wallet::change_password_authorized(&state, "old", "new", None).await.is_err());
        wallet::change_password_authorized(&state, "old", "new", Some(&fresh_code())).await.unwrap();
        close_wallet(&state).await.unwrap(); open_wallet(&state, "synthetic").await.unwrap();
        assert!(unlock_wallet_authorized(&state, "old", Some(&fresh_code())).await.is_err());
        assert!(unlock_wallet_authorized(&state, "new", None).await.is_err());
        assert!(wallet::recover_totp_inner(&state, "wrong", &codes[0]).await.is_err());
        wallet::recover_totp_inner(&state, "new", &codes[0]).await.unwrap();
        assert!(!get_wallet_status(&state).is_unlocked);
        assert!(wallet::recover_totp_inner(&state, "new", &codes[0]).await.is_err());
        unlock_wallet_authorized(&state, "new", None).await.unwrap();
        close_wallet(&state).await.unwrap();
        open_wallet(&state, "backup").await.unwrap();
        assert!(unlock_wallet_authorized(&state, "new", Some(&fresh_code())).await.is_err());
        unlock_wallet_authorized(&state, "old", Some(&fresh_code())).await.unwrap();
        {
            let guard = state.wallet_operation.lock().await;
            assert_eq!(crate::services::wallet_security::status_locked(&state, &guard).unwrap(), Some(Some(true)));
            assert_eq!(crate::services::wallet_security::recovery_count_locked(&state, &guard).unwrap(), Some(Some(10)));
        }
        close_wallet(&state).await.unwrap();
        open_wallet(&state, "synthetic").await.unwrap();
        assert!(unlock_wallet_authorized(&state, "old", None).await.is_err());
        unlock_wallet_authorized(&state, "new", None).await.unwrap();
        close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn legacy_new_setup_and_locked_recovery_keep_schema_33() {
        use crate::commands::wallet;
        let dir = std::env::temp_dir().join(format!("wallet-legacy-flow-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = AppState::new(); state.data_dir = dir.to_string_lossy().into();
        create_legacy_fixture(&state, "synthetic", "pw", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None).await.unwrap();
        let setup = wallet::begin_totp_setup_inner(&state, "pw").await.unwrap();
        let secret = totp_rs::Secret::Encoded(setup.secret_base32).to_bytes().unwrap();
        let code = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").unwrap().generate_current().unwrap();
        assert!(wallet::confirm_totp_setup_inner(&state, "pw", "invalid").await.is_err());
        wallet::confirm_totp_setup_inner(&state, "pw", &code).await.unwrap();
        assert!(wallet::begin_totp_setup_inner(&state, "pw").await.is_err());
        let codes = wallet::generate_totp_recovery_codes_inner(&state, "pw".into(), code).await.unwrap();
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        assert_eq!(repositories::get_wallet_data(&pool, "migration").await.unwrap().as_deref(), Some("33"));
        close_wallet(&state).await.unwrap(); open_wallet(&state, "synthetic").await.unwrap();
        assert!(wallet::recover_totp_inner(&state, "wrong", &codes[0]).await.is_err());
        wallet::recover_totp_inner(&state, "pw", &codes[0]).await.unwrap();
        assert!(!get_wallet_status(&state).is_unlocked);
        assert!(wallet::recover_totp_inner(&state, "pw", &codes[0]).await.is_err());
        unlock_wallet_authorized(&state, "pw", None).await.unwrap();
        close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn cancelled_secure_rotation_requires_reopen_and_uses_committed_db() {
        use crate::commands::wallet;
        for after_commit in [false, true] {
            let dir = std::env::temp_dir().join(format!("wallet-commit-{}-{}-{after_commit}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
            std::fs::create_dir_all(&dir).unwrap();
            let mut s = AppState::new(); s.data_dir = dir.to_string_lossy().into();
            let state = std::sync::Arc::new(s);
            create_wallet(&state, "synthetic", "old", Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), None).await.unwrap();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (_resume_tx, resume_rx) = tokio::sync::oneshot::channel();
            state.active_wallet.lock().unwrap().as_mut().unwrap().commit_barrier = Some(crate::state::TestCommitBarrier { after_commit, started: started_tx, resume: resume_rx });
            let worker = state.clone();
            let task = tokio::spawn(async move { wallet::change_password_authorized(&worker, "old", "new", None).await });
            tokio::time::timeout(std::time::Duration::from_secs(90), started_rx).await.unwrap().unwrap();
            task.abort(); let _ = task.await;
            assert!(!get_wallet_status(&state).is_unlocked);
            assert!(unlock_wallet_authorized(&state, "old", None).await.unwrap_err().contains("reopen"));
            close_wallet(&state).await.unwrap(); open_wallet(&state, "synthetic").await.unwrap();
            let (correct, wrong) = if after_commit { ("new", "old") } else { ("old", "new") };
            assert!(unlock_wallet_authorized(&state, wrong, None).await.is_err());
            unlock_wallet_authorized(&state, correct, None).await.unwrap();
            close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn cancelled_legacy_confirm_locks_session_and_reopen_reads_database() {
        use crate::commands::wallet;
        for after_commit in [false, true] {
            let dir = std::env::temp_dir().join(format!("wallet-legacy-commit-{}-{}-{after_commit}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
            std::fs::create_dir_all(&dir).unwrap();
            let mut s = AppState::new(); s.data_dir = dir.to_string_lossy().into();
            let state = std::sync::Arc::new(s);
            create_legacy_fixture(&state, "synthetic", "pw", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None).await.unwrap();
            let setup = wallet::begin_totp_setup_inner(&state, "pw").await.unwrap();
            let secret = totp_rs::Secret::Encoded(setup.secret_base32).to_bytes().unwrap();
            let code = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").unwrap().generate_current().unwrap();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel(); let (_resume_tx, resume_rx) = tokio::sync::oneshot::channel();
            state.active_wallet.lock().unwrap().as_mut().unwrap().commit_barrier = Some(crate::state::TestCommitBarrier { after_commit, started: started_tx, resume: resume_rx });
            let worker = state.clone(); let task = tokio::spawn(async move { wallet::confirm_totp_setup_inner(&worker, "pw", &code).await });
            tokio::time::timeout(std::time::Duration::from_secs(30), started_rx).await.unwrap().unwrap();
            task.abort(); let _ = task.await;
            assert!(!get_wallet_status(&state).is_unlocked);
            close_wallet(&state).await.unwrap(); open_wallet(&state, "synthetic").await.unwrap();
            assert_eq!(wallet::is_totp_enabled_inner(&state).await.unwrap(), Some(after_commit));
            close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn pending_setup_cancel_expiry_switch_and_password_change() {
        use crate::commands::wallet;
        let dir = std::env::temp_dir().join(format!("wallet-pending-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
        std::fs::create_dir_all(&dir).unwrap(); let mut state = AppState::new(); state.data_dir = dir.to_string_lossy().into();
        create_wallet(&state, "one", "old", Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), None).await.unwrap();
        wallet::begin_totp_setup_inner(&state, "old").await.unwrap();
        wallet::cancel_totp_setup_inner(&state).await.unwrap();
        assert!(wallet::confirm_totp_setup_inner(&state, "old", "000000").await.is_err());
        wallet::begin_totp_setup_inner(&state, "old").await.unwrap();
        state.active_wallet.lock().unwrap().as_mut().unwrap().secure_wallet.as_mut().unwrap().pending_totp.as_mut().unwrap().expires = std::time::Instant::now();
        assert!(wallet::confirm_totp_setup_inner(&state, "old", "000000").await.unwrap_err().contains("expired"));
        wallet::begin_totp_setup_inner(&state, "old").await.unwrap();
        wallet::change_password_authorized(&state, "old", "new", None).await.unwrap();
        assert!(wallet::confirm_totp_setup_inner(&state, "new", "000000").await.is_err());
        wallet::begin_totp_setup_inner(&state, "new").await.unwrap();
        create_wallet(&state, "two", "pw", Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), None).await.unwrap();
        open_wallet(&state, "one").await.unwrap();
        assert!(wallet::confirm_totp_setup_inner(&state, "new", "000000").await.is_err());
        close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn stale_authenticated_snapshot_cannot_replace_database_record() {
        let dir = std::env::temp_dir().join(format!("wallet-cas-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
        std::fs::create_dir_all(&dir).unwrap(); let mut state = AppState::new(); state.data_dir = dir.to_string_lossy().into();
        create_wallet(&state, "one", "old", Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), None).await.unwrap();
        let guard = state.wallet_operation.lock().await;
        let auth = crate::services::wallet_security::authenticate_locked(&state, &guard, "old", None, true).await.unwrap().unwrap();
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        let (mut record,): (Vec<u8>,) = sqlx::query_as("SELECT derivation_data FROM MasterKeys").fetch_one(&pool).await.unwrap();
        record.push(b' ');
        sqlx::query("UPDATE MasterKeys SET derivation_data=?").bind(&record).execute(&pool).await.unwrap();
        assert!(crate::services::wallet_security::rotate_password_locked(&state, &guard, auth, "new").await.is_err());
        let (after,): (Vec<u8>,) = sqlx::query_as("SELECT derivation_data FROM MasterKeys").fetch_one(&pool).await.unwrap(); assert_eq!(after, record);
        drop(guard); close_wallet(&state).await.unwrap(); open_wallet(&state, "one").await.unwrap();
        unlock_wallet_authorized(&state, "old", None).await.unwrap();
        close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(dir).unwrap();
    }
}

/// Synthetic legacy fixtures for compatibility tests; never used by production creation.
#[cfg(test)]
pub(crate) async fn create_legacy_fixture(state: &AppState, name: &str, password: &str, phrase: &str, passphrase: Option<&str>) -> Result<CreateWalletResult, WalletError> {
    let _operation = state.wallet_operation.lock().await;
    if password.is_empty() { return Err(WalletError::PasswordRequired); }
    mnemonic::validate_mnemonic(phrase).map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
    let wallet_path = join_path(&state.data_dir, &format!("{name}.sqlite"));
    let wallet_lock = std::sync::Arc::new(lock_wallet(Path::new(&wallet_path))?);
    let seed = mnemonic::mnemonic_to_seed(phrase, passphrase.unwrap_or("")).map_err(|e| WalletError::BsvSdk(e.to_string()))?;
    let derived = keystore::derive_keys_from_seed(&seed)?;
    let ks_data = keystore::create_keystore_data(phrase, passphrase, password, &derived);
    connection::create_wallet_db(&wallet_path).await?;
    let pool = connection::open_wallet_db_locked(&wallet_path, wallet_lock.clone()).await?;
    let masterkey_id = repositories::insert_master_key(&pool, None, keystore::DERIVATION_TYPE_BIP32, &keystore::keystore_data_to_bytes(&ks_data)).await?;
    let account_id = repositories::insert_account(&pool, Some(masterkey_id), repositories::script_type::P2PKH, "Standard account").await?;
    repositories::set_wallet_data(&pool, "password-token", &encryption::pw_encode("synthetic-token", password)).await?;
    repositories::set_wallet_data(&pool, "next_masterkey_id", "2").await?;
    repositories::set_wallet_data(&pool, "next_account_id", "2").await?;
    let instance_token = new_instance_token()?;
    let active = ActiveWallet { instance_id: std::sync::Arc::new(()), instance_token: instance_token.clone(), wallet_lock, wallet_path: wallet_path.clone(), wallet_name: name.into(), db_pool: pool, keystore_data: ks_data, account_id, decrypted_xprv: Some(derived.xprv), secure_wallet: None, legacy_pending_totp: None, commit_barrier: None, migration_write_fail: false };
    retire_active_wallet(state).await?;
    *state.active_wallet.lock().unwrap() = Some(active);
    Ok(CreateWalletResult { wallet_instance_token: instance_token, mnemonic: phrase.into(), wallet_path, account_id, is_new_mnemonic: false })
}
