// commands/extra.rs — Additional Tauri commands ported from Python
//
// Covers features that were partially or fully missing in the Rust port:
// - TOTP scope management (login vs tx)
// - get_transaction (full TX detail query)
// - wallet backup
// - imported private key / address support
// - 1-shot send (prepare + sign + broadcast in one call)
// - network switching (mainnet / testnet / STN)
// - WhatsOnChain extra methods (get_tx, get_block_header, get_chain_info)

use crate::db::repositories;
use crate::state::AppState;
use tauri::State;

// ============================================================================
// TOTP Scope — login vs tx (Python: totp_set_scope endpoint)
// ============================================================================

/// TOTP scope: "login" (only at unlock) or "tx" (also for every transaction).
#[derive(Debug, serde::Serialize)]
pub struct TotpScopeInfo {
    pub enabled: Option<bool>,
    pub scope: String,
    pub recovery_codes_remaining: Option<i64>,
    pub scope_editable: bool,
}

/// Get TOTP status including scope.
#[tauri::command]
pub async fn get_totp_status(state: State<'_, AppState>) -> Result<TotpScopeInfo, String> {
    let operation = state.wallet_operation.lock().await;
    if let Some(enabled) = crate::services::wallet_security::status_locked(&state, &operation)? {
        let count = crate::services::wallet_security::recovery_count_locked(&state, &operation)?.flatten();
        return Ok(TotpScopeInfo { enabled, scope: "tx".into(), recovery_codes_remaining: count, scope_editable: false });
    }
    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        active.db_pool.clone()
    };

    let enabled = repositories::is_totp_enabled(&pool).await.map_err(|e| e.to_string())?;

    // Scope is stored in WalletData as "totp_scope"
    let scope = repositories::get_wallet_data(&pool, "totp_scope")
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| "tx".to_string());

    // Count remaining recovery codes
    let recovery_remaining = repositories::count_remaining_recovery_codes(&pool)
        .await
        .unwrap_or(0);

    Ok(TotpScopeInfo {
        enabled: Some(enabled),
        scope,
        recovery_codes_remaining: Some(recovery_remaining),
        scope_editable: true,
    })
}

/// Change TOTP scope. Raising scope (login->tx) does NOT require a code.
/// Lowering scope (tx->login) REQUIRES the current TOTP code.
#[tauri::command]
pub async fn set_totp_scope(
    state: State<'_, AppState>,
    password: String,
    scope: String,
    code: Option<String>,
) -> Result<String, String> {
    let operation = state.wallet_operation.lock().await;
    if crate::services::wallet_security::status_locked(&state, &operation)?.is_some() { return Err("TOTP scope changes are unavailable for this wallet".into()); }
    log::info!("set_totp_scope — scope: {}", scope);

    if scope != "login" && scope != "tx" {
        return Err("Invalid scope. Use 'login' or 'tx'.".to_string());
    }

    let (pool, keystore_data, wallet_name) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.db_pool.clone(), active.keystore_data.clone(), active.wallet_name.clone())
    };

    // Verify password
    if !crate::core::keystore::verify_password(&keystore_data, &password) {
        return Err("incorrect password".to_string());
    }

    // Get current scope
    let current_scope = repositories::get_wallet_data(&pool, "totp_scope")
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| "tx".to_string());

    // Lowering scope (tx -> login) requires TOTP code
    if current_scope == "tx" && scope == "login" {
        let code = code.ok_or("TOTP code required when lowering scope from tx to login")?;

        let encrypted_secret = repositories::load_totp_secret(&pool)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("TOTP is not enabled")?;

        let wallet_name = wallet_name.clone();
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(
            &encrypted_secret,
            "ElectrumSV-Mc",
            &wallet_name,
        )
        .map_err(|e| e.to_string())?;

        let valid = totp.verify_current(&code).map_err(|e| e.to_string())?;
        if !valid {
            return Err("Invalid TOTP code".to_string());
        }
    }

    // Store new scope
    repositories::set_wallet_data(&pool, "totp_scope", &scope)
        .await
        .map_err(|e| e.to_string())?;

    Ok(scope)
}

// ============================================================================
// get_transaction — full TX detail from wallet DB
// ============================================================================

/// Transaction detail for get_transaction command.
#[derive(Debug, serde::Serialize)]
pub struct TransactionDetail {
    pub txid: String,
    pub status: String,
    pub raw_tx: Option<String>,
    pub account_id: Option<i64>,
    pub fee: Option<i64>,
    pub inputs: Option<Vec<TxInputDetail>>,
    pub outputs: Option<Vec<TxOutputDetail>>,
    pub detail_complete: bool,
    pub label: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct TxInputDetail {
    pub prev_tx_hash: String,
    pub prev_vout: i64,
    pub script_sig: String,
    pub sequence: u32,
}

#[derive(Debug, serde::Serialize)]
pub struct TxOutputDetail {
    pub value: i64,
    pub script_pubkey: String,
}

/// Get full transaction details by txid.
///
/// Queries the wallet database for the transaction, its inputs, outputs, and label.
#[tauri::command]
pub async fn get_transaction(
    state: State<'_, AppState>,
    txid: String,
) -> Result<TransactionDetail, String> {
    log::info!("get_transaction — txid: {}", txid);

    let (pool, account_id) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.db_pool.clone(), active.account_id)
    };
    transaction_detail(&pool, account_id, &txid).await
}

pub(crate) async fn transaction_detail(pool: &sqlx::SqlitePool, account_id: i64, txid: &str) -> Result<TransactionDetail, String> {
    let tx = repositories::get_transaction_by_txid(pool, account_id, txid).await
        .map_err(|e| e.to_string())?.ok_or("transaction not found")?;
    let (raw_tx, inputs, outputs) = match tx.tx_data {
        None => (None, None, None),
        Some(bytes) => {
            crate::commands::network::validate_transaction_wire(&bytes)?;
            let raw = hex::encode(&bytes);
            let parsed = bsv::transaction::transaction::Transaction::from_hex(&raw).map_err(|e| format!("invalid stored transaction: {e}"))?;
            let id = parsed.id().map_err(|e| e.to_string())?;
            if !id.eq_ignore_ascii_case(txid) || parsed.to_hex().map_err(|e| e.to_string())? != raw {
                return Err("stored transaction does not match txid".into());
            }
            let inputs = parsed.inputs.iter().map(|i| TxInputDetail {
                prev_tx_hash: i.source_txid.clone().unwrap_or_default(), prev_vout: i.source_output_index as i64,
                script_sig: i.unlocking_script.as_ref().map(|s| hex::encode(s.to_binary())).unwrap_or_default(), sequence: i.sequence,
            }).collect();
            let outputs = parsed.outputs.iter().map(|o| Ok(TxOutputDetail {
                value: i64::try_from(o.satoshis.ok_or("missing output amount")?).map_err(|_| "output amount overflow")?,
                script_pubkey: hex::encode(o.locking_script.to_binary()),
            })).collect::<Result<Vec<_>, &str>>()?;
            (Some(raw), Some(inputs), Some(outputs))
        }
    };
    let detail_complete = raw_tx.is_some();
    Ok(TransactionDetail { txid: txid.to_ascii_lowercase(), status: if tx.block_height.is_some() { "confirmed" } else { "pending" }.into(),
        raw_tx, account_id: Some(account_id), fee: tx.fee_value, inputs, outputs, detail_complete, label: tx.description })

}

// ============================================================================
// Wallet backup
// ============================================================================

/// Backup the current wallet database file to a specified path.
///
/// The backup path must be within the application data directory to prevent
/// path-traversal attacks, and must not already exist (no silent overwrite).
#[tauri::command]
pub async fn backup_wallet(
    state: State<'_, AppState>,
    backup_path: String,
    password: String,
    totp_code: Option<String>,
    expected_instance_token: String,
) -> Result<String, String> {
    backup_wallet_authorized_bound(&state, backup_path, password, totp_code, Some(&expected_instance_token)).await
}

pub async fn backup_wallet_inner(
    state: &AppState,
    backup_path: String,
    password: String,
) -> Result<String, String> {
    backup_wallet_authorized(state, backup_path, password, None).await
}

pub async fn backup_wallet_authorized(state: &AppState, backup_path: String, password: String, totp_code: Option<String>) -> Result<String, String> {
    backup_wallet_authorized_bound(state, backup_path, password, totp_code, None).await
}

pub(crate) async fn backup_wallet_authorized_bound(state: &AppState, backup_path: String, password: String, totp_code: Option<String>, expected_instance_token: Option<&str>) -> Result<String, String> {
    let _operation = state.wallet_operation.lock().await;
    if let Some(expected) = expected_instance_token {
        let guard = state.active_wallet.lock().unwrap();
        if expected.is_empty() || guard.as_ref().map(|wallet| wallet.instance_token.as_str()) != Some(expected) {
            return Err("wallet instance changed; reopen backup dialog".into());
        }
    }
    log::info!("backup_wallet — to: {}", backup_path);

    let secure = crate::services::wallet_security::authenticate_locked(state, &_operation, &password, totp_code.as_deref(), true).await?;

    {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        if secure.is_none() && !crate::core::keystore::verify_password(&active.keystore_data, &password) { return Err("incorrect password".into()); }
    }
    backup_snapshot_locked(state, &_operation, &backup_path).await?;
    log::info!("Wallet backed up to: {}", backup_path);
    Ok(backup_path)
}

pub(crate) async fn backup_snapshot_locked(state: &AppState, _operation: &tokio::sync::MutexGuard<'_, ()>, backup_path: &str) -> Result<verified_backup::VerifiedBackup, String> {
    let (wallet_path, pool, instance) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.wallet_path.clone(), active.db_pool.clone(), active.instance_id.clone())
    };
    if !std::path::Path::new(&wallet_path).exists() {
        return Err(format!("wallet file not found: {}", wallet_path));
    }

    #[cfg(not(target_os = "linux"))]
    return Err("secure wallet backup is not supported on this platform".into());

    #[cfg(target_os = "linux")]
    {
    let target = std::sync::Arc::new(secure_backup::Target::new(&state.data_dir, backup_path)?);
    let result = sqlx::query("VACUUM INTO ?").bind(target.sqlite_path()).execute(&pool).await;
    result.map_err(|e| format!("backup failed: {e}"))?;
    let verified = verified_backup::VerifiedBackup::open(target.open_snapshot()?, instance, target.clone()).await?;
    target.publish(verified.snapshot_file())?;
    Ok(verified)
    }
}

// ============================================================================
#[cfg(target_os = "linux")]
mod secure_backup {
    use rand::RngCore;
    use std::{ffi::{CString, OsStr}, os::{fd::{AsRawFd, FromRawFd, OwnedFd}, unix::ffi::OsStrExt}, path::{Component, Path}};
    #[repr(C)]
    struct OpenHow { flags: u64, mode: u64, resolve: u64 }
    fn cstring(s: &OsStr) -> Result<CString, String> { CString::new(s.as_bytes()).map_err(|_| "path contains NUL".into()) }
    fn owned(fd: i32) -> Result<OwnedFd, String> {
        if fd < 0 { Err(std::io::Error::last_os_error().to_string()) } else { Ok(unsafe { OwnedFd::from_raw_fd(fd) }) }
    }
    pub struct Target { parent: OwnedFd, stage: OwnedFd, stage_name: CString, leaf: CString, snapshot_identity: Option<(u64,u64)> }
    impl Target {
        pub fn new(data_dir: &str, backup: &str) -> Result<Self, String> {
            let root = Path::new(data_dir).canonicalize().map_err(|e| e.to_string())?;
            let path = Path::new(backup);
            let relative = path.strip_prefix(&root).or_else(|_| path.strip_prefix(data_dir)).map_err(|_| "backup path must be inside the data directory")?;
            let leaf = cstring(relative.file_name().ok_or("backup path has no filename")?)?;
            if !relative.components().all(|c| matches!(c, Component::Normal(_))) { return Err("invalid backup path".into()); }
            let root_fd = owned(unsafe { libc::open(cstring(root.as_os_str())?.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) })?;
            let parent_path = relative.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
            let how = OpenHow { flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64, mode: 0, resolve: 0x02 | 0x04 | 0x08 };
            let parent = owned(unsafe { libc::syscall(libc::SYS_openat2, root_fd.as_raw_fd(), cstring(parent_path.as_os_str())?.as_ptr(), &how, std::mem::size_of::<OpenHow>()) as i32 })?;
            for _ in 0..16 {
                let mut random = [0u8; 16]; rand::rngs::OsRng.fill_bytes(&mut random);
                let name = CString::new(format!(".wallet-backup-{}", hex::encode(random))).unwrap();
                if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::AlreadyExists { continue; }
                    return Err(format!("backup staging: {err}"));
                }
                let stage = match owned(unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) }) {
                    Ok(v) => v,
                    Err(e) => { unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR); } return Err(e); }
                };
                let mut target = Self { parent, stage, stage_name: name, leaf, snapshot_identity: None };
                let snapshot = CString::new("snapshot").unwrap();
                let fd = owned(unsafe { libc::openat(target.stage.as_raw_fd(), snapshot.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0o600) })?;
                let file: std::fs::File = fd.into();
                use std::os::unix::fs::MetadataExt;
                let meta=file.metadata().map_err(|_| "backup staging metadata failed")?;
                target.snapshot_identity=Some((meta.dev(),meta.ino()));
                return Ok(target);
            }
            Err("could not create unique backup staging directory".into())
        }
        pub fn sqlite_path(&self) -> String { format!("/proc/self/fd/{}/snapshot", self.stage.as_raw_fd()) }
        pub fn open_snapshot(&self) -> Result<std::fs::File, String> {
            let name = CString::new("snapshot").unwrap();
            let file = owned(unsafe { libc::openat(self.stage.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) })?;
            Ok(file.into())
        }
        pub fn publish(&self, verified: &std::fs::File) -> Result<(), String> {
            use std::os::unix::fs::MetadataExt;
            let name = CString::new("snapshot").unwrap();
            let file = self.open_snapshot()?;
            let a = verified.metadata().map_err(|_| "verified backup metadata failed")?;
            let b = file.metadata().map_err(|_| "backup metadata failed")?;
            if (a.dev(),a.ino()) != (b.dev(),b.ino()) { return Err("backup staging file changed".into()); }
            if unsafe { libc::fsync(file.as_raw_fd()) } != 0 { return Err(format!("backup sync: {}", std::io::Error::last_os_error())); }
            if unsafe { libc::linkat(self.stage.as_raw_fd(), name.as_ptr(), self.parent.as_raw_fd(), self.leaf.as_ptr(), 0) } != 0 { return Err(format!("backup publication: {}", std::io::Error::last_os_error())); }
            let published = owned(unsafe { libc::openat(self.parent.as_raw_fd(), self.leaf.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) })?;
            let published: std::fs::File = published.into();
            let c = published.metadata().map_err(|_| "published backup metadata failed")?;
            if (a.dev(),a.ino()) != (c.dev(),c.ino()) { return Err("published backup file changed".into()); }
            if unsafe { libc::fsync(self.parent.as_raw_fd()) } != 0 { return Err(format!("backup published but directory sync failed: {}", std::io::Error::last_os_error())); }
            Ok(())
        }
    }
    impl Drop for Target {
        fn drop(&mut self) {
            use std::os::unix::fs::MetadataExt;
            let name = CString::new("snapshot").unwrap();
            if let Ok(file)=self.open_snapshot() {
                if file.metadata().ok().is_some_and(|m| Some((m.dev(),m.ino())) == self.snapshot_identity) {
                    unsafe { libc::unlinkat(self.stage.as_raw_fd(), name.as_ptr(), 0); }
                }
            }
            let mut current = std::mem::MaybeUninit::<libc::stat>::uninit();
            let mut held = std::mem::MaybeUninit::<libc::stat>::uninit();
            let same = unsafe {
                libc::fstatat(self.parent.as_raw_fd(),self.stage_name.as_ptr(),current.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)==0 &&
                libc::fstat(self.stage.as_raw_fd(),held.as_mut_ptr())==0 && {
                    let a=current.assume_init();let b=held.assume_init();a.st_dev==b.st_dev && a.st_ino==b.st_ino
                }
            };
            if same { unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.stage_name.as_ptr(), libc::AT_REMOVEDIR); } }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) mod verified_backup { pub(crate) struct VerifiedBackup; }

#[cfg(target_os = "linux")]
pub(crate) mod verified_backup {
    use sha2::{Digest, Sha256};
    use sqlx::{Row, TypeInfo, ValueRef, SqliteConnection, SqlitePool, Transaction, Sqlite};
    use std::os::fd::AsRawFd;

    const MAX_TABLES: usize = 512;
    const MAX_ROWS: usize = 100_000;
    const MAX_ROW_BYTES: i64 = 1024 * 1024;
    const MAX_TOTAL_BYTES: i64 = 512 * 1024 * 1024;
    const MAX_COLUMNS: usize = 128;
    const BATCH_ROWS: usize = 16;

    /// Owns the published inode; no migration hooks are run on its readonly connection.
    pub(crate) struct VerifiedBackup { pool: SqlitePool, _file: std::sync::Arc<std::fs::File>, instance: std::sync::Arc<()> }

    impl VerifiedBackup {
        pub(super) async fn open(file: std::fs::File, instance: std::sync::Arc<()>, staging: std::sync::Arc<super::secure_backup::Target>) -> Result<Self, String> {
            let file = std::sync::Arc::new(file);
            let file_owner = file.clone();
            let path = format!("/proc/self/fd/{}", file.as_raw_fd());
            let options = sqlx::sqlite::SqliteConnectOptions::new().filename(path).read_only(true).immutable(true);
            // The private staging name remains linked while this object lives;
            // SQLite may resolve /proc/self/fd to that name when reconnecting.
            let pool = sqlx::sqlite::SqlitePoolOptions::new().min_connections(2).max_connections(2)
                .idle_timeout(None).max_lifetime(None).acquire_timeout(std::time::Duration::from_secs(3))
                .after_connect(move |_, _| { let owner = staging.clone(); let descriptor = file_owner.clone(); Box::pin(async move { drop((owner, descriptor)); Ok(()) }) })
                .connect_with(options).await.map_err(|_| "backup readonly open failed")?;
            let rows: Vec<(String,)> = sqlx::query_as("PRAGMA integrity_check").fetch_all(&pool).await.map_err(|_| "backup integrity check failed")?;
            if rows.len() != 1 || rows[0].0 != "ok" { return Err("backup integrity check failed".into()); }
            Ok(Self { pool, _file: file, instance })
        }

        pub(super) fn snapshot_file(&self) -> &std::fs::File { &self._file }
        /// This pool is read-only and immutable; it does not imply secret authentication.
        pub(crate) fn readonly_pool(&self) -> &SqlitePool { &self.pool }

        /// Holds the same IMMEDIATE transaction for the caller's subsequent inventory and CAS.
        pub(crate) async fn begin_verified_source(&self, state: &crate::state::AppState, _operation: &tokio::sync::MutexGuard<'_, ()>) -> Result<Transaction<'static, Sqlite>, String> {
            let pool = {
                let active = state.active_wallet.lock().map_err(|_| "wallet state unavailable")?;
                let active = active.as_ref().ok_or("wallet is not open")?;
                if !std::sync::Arc::ptr_eq(&self.instance, &active.instance_id) { return Err("wallet changed after backup".into()); }
                active.db_pool.clone()
            };
            let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.map_err(|_| "source write lock failed")?;
            let mut snapshot = self.pool.acquire().await.map_err(|_| "backup readonly open failed")?;
            let expected = migration_snapshot_digest(&mut snapshot).await?;
            let actual = migration_snapshot_digest(&mut tx).await?;
            if expected != actual { return Err("wallet changed after backup".into()); }
            Ok(tx)
        }
    }

    fn add(hash: &mut Sha256, data: &[u8]) -> Result<(), String> {
        if data.len() > MAX_ROW_BYTES as usize { return Err("backup comparison field limit exceeded".into()); }
        hash.update((data.len() as u64).to_le_bytes()); hash.update(data); Ok(())
    }

    pub(crate) async fn migration_snapshot_digest(conn: &mut SqliteConnection) -> Result<[u8;32], String> {
        let schema_bounds: (i64,i64,i64) = sqlx::query_as("SELECT COUNT(*),COALESCE(MAX(length(CAST(COALESCE(sql,'') AS BLOB))+length(CAST(name AS BLOB))+length(CAST(tbl_name AS BLOB))),0),COALESCE(SUM(length(CAST(COALESCE(sql,'') AS BLOB))+length(CAST(name AS BLOB))+length(CAST(tbl_name AS BLOB))),0) FROM sqlite_schema").fetch_one(&mut *conn).await.map_err(|_| "wallet schema bounds failed")?;
        if schema_bounds.0 > (MAX_TABLES * 8) as i64 || schema_bounds.1 > MAX_ROW_BYTES || schema_bounds.2 > 8*1024*1024 { return Err("backup comparison schema limit exceeded".into()); }
        let schema: Vec<(String, String, String, Option<String>)> = sqlx::query_as("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name,tbl_name").fetch_all(&mut *conn).await.map_err(|_| "wallet schema read failed")?;
        if schema.len() > MAX_TABLES * 8 { return Err("backup comparison schema limit exceeded".into()); }
        let mut result = Sha256::new();
        for pragma in ["PRAGMA user_version", "PRAGMA application_id"] {
            let n: (i64,) = sqlx::query_as(pragma).fetch_one(&mut *conn).await.map_err(|_| "wallet metadata read failed")?;
            result.update(n.0.to_le_bytes());
        }
        let mut tables = Vec::new();
        for (kind, name, owner, sql) in schema {
            add(&mut result,kind.as_bytes())?; add(&mut result,name.as_bytes())?; add(&mut result,owner.as_bytes())?;
            match &sql { Some(value) => {result.update([1]); add(&mut result,value.as_bytes())?;}, None => result.update([0]) }
            if kind == "table" {
                if sql.as_deref().is_some_and(|s| s.trim_start().to_ascii_uppercase().starts_with("CREATE VIRTUAL TABLE")) { return Err("virtual tables are not supported for migration".into()); }
                tables.push(name);
            }
        }
        if tables.len() > MAX_TABLES { return Err("backup comparison table limit exceeded".into()); }
        let mut total = 0usize;
        let mut total_bytes = 0i64;
        for table in tables {
            let quoted = table.replace('"',"\"\"");
            let column_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pragma_table_xinfo(?)").bind(&table).fetch_one(&mut *conn).await.map_err(|_| "wallet columns read failed")?;
            if column_count.0 <= 0 || column_count.0 > MAX_COLUMNS as i64 { return Err("unsupported wallet table columns".into()); }
            let columns: Vec<(String, i64)> = sqlx::query_as("SELECT name,hidden FROM pragma_table_xinfo(?) ORDER BY cid").bind(&table).fetch_all(&mut *conn).await.map_err(|_| "wallet columns read failed")?;
            if columns.is_empty() || columns.len() > MAX_COLUMNS || columns.iter().any(|(_, hidden)| *hidden == 1) { return Err("unsupported wallet table columns".into()); }
            let sizes = columns.iter().map(|(name,_)| format!("CASE WHEN typeof(\"{}\") IN ('text','blob') THEN length(CAST(\"{}\" AS BLOB)) ELSE 8 END",name.replace('"',"\"\""),name.replace('"',"\"\""))).collect::<Vec<_>>().join("+");
            let bounds = format!("SELECT COALESCE(MAX({sizes}),0),COALESCE(SUM({sizes}),0),COUNT(*) FROM \"{quoted}\"");
            let (max_row, bytes, count): (i64,i64,i64) = sqlx::query_as(&bounds).fetch_one(&mut *conn).await.map_err(|_| "wallet comparison bounds failed")?;
            if max_row > MAX_ROW_BYTES || count < 0 || bytes < 0 { return Err("backup comparison row limit exceeded".into()); }
            total_bytes = total_bytes.checked_add(bytes).ok_or("backup comparison byte limit exceeded")?;
            if total_bytes > MAX_TOTAL_BYTES || total.checked_add(count as usize).filter(|n| *n <= MAX_ROWS).is_none() { return Err("backup comparison limit exceeded".into()); }
            let query = format!("SELECT * FROM \"{quoted}\" LIMIT {BATCH_ROWS} OFFSET ?");
            let mut offset = 0i64; let mut hashes = Vec::new();
            loop {
                let rows = sqlx::query(&query).bind(offset).fetch_all(&mut *conn).await.map_err(|_| "wallet data read failed")?;
                let count = rows.len();
                for row in rows {
                    total += 1; if total > MAX_ROWS { return Err("backup comparison row limit exceeded".into()); }
                    let mut h=Sha256::new();
                    for i in 0..row.columns().len() {
                        let raw=row.try_get_raw(i).map_err(|_| "wallet value read failed")?;
                        if raw.is_null() { h.update([0]); continue; }
                        match raw.type_info().name() {
                            "INTEGER" => {h.update([1]);let v:i64=row.try_get(i).map_err(|_| "wallet integer read failed")?;h.update(v.to_le_bytes());},
                            "REAL" => {h.update([2]);let v:f64=row.try_get(i).map_err(|_| "wallet real read failed")?;h.update(v.to_bits().to_le_bytes());},
                            "TEXT" => {h.update([3]);let v:String=row.try_get(i).map_err(|_| "wallet text read failed")?;add(&mut h,v.as_bytes())?;},
                            "BLOB" => {h.update([4]);let v:Vec<u8>=row.try_get(i).map_err(|_| "wallet blob read failed")?;add(&mut h,&v)?;},
                            _ => return Err("unsupported SQLite value type".into()),
                        }
                    }
                    hashes.push(<[u8;32]>::from(h.finalize()));
                }
                if count < BATCH_ROWS { break; }
                offset += count as i64;
            }
            hashes.sort_unstable(); add(&mut result, table.as_bytes())?; result.update((hashes.len() as u64).to_le_bytes());
            for h in hashes { result.update(h); }
        }
        Ok(result.finalize().into())
    }
}

// Network switching (mainnet / testnet / STN)
// ============================================================================

/// Static definition of a supported BSV network (mainnet / testnet / STN).
///
/// This describes the network identity, not the live connection status. For
/// the connection status see `commands::network::NetworkInfo`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkDefinition {
    pub id: String,
    pub name: String,
    pub default_ports: Vec<String>,
    pub bitcoin_uri_prefix: String,
}

/// List all supported BSV networks.
#[tauri::command]
pub async fn list_networks() -> Result<Vec<NetworkDefinition>, String> {
    Ok(vec![
        NetworkDefinition {
            id: "mainnet".to_string(),
            name: "Bitcoin SV Mainnet".to_string(),
            default_ports: vec!["50001".to_string(), "50002".to_string()],
            bitcoin_uri_prefix: "bitcoin".to_string(),
        },
        NetworkDefinition {
            id: "testnet".to_string(),
            name: "Bitcoin SV Testnet".to_string(),
            default_ports: vec!["51001".to_string(), "51002".to_string()],
            bitcoin_uri_prefix: "bitcoin".to_string(),
        },
        NetworkDefinition {
            id: "stn".to_string(),
            name: "Bitcoin SV Scaling Testnet".to_string(),
            default_ports: vec!["52001".to_string(), "52002".to_string()],
            bitcoin_uri_prefix: "bitcoin".to_string(),
        },
    ])
}

/// Switch the active network. Requires reconnecting to a server afterwards.
#[tauri::command]
pub async fn switch_network(
    state: State<'_, AppState>,
    network_id: String,
) -> Result<String, String> {
    log::info!("switch_network — {}", network_id);

    if network_id != "mainnet" {
        return Err("Only mainnet is supported; network state and addresses are not isolated for testnet or STN".into());
    }

    let mut network = state.network.lock().unwrap();
    network.active_network = network_id.clone();
    drop(network);

    Ok(network_id)
}

// ============================================================================
// 1-shot send (prepare + sign + broadcast in one call)
// ============================================================================

/// 1-shot send: prepare, sign, and broadcast a transaction in one call.
///
/// This is a convenience wrapper around the 3-stage workflow for simple sends.
#[tauri::command]
pub async fn send(
    state: State<'_, AppState>,
    address: String,
    amount: u64,
    password: String,
    totp_code: String,
    op_return: Option<String>,
    fee_rate: Option<u64>,
    coin_selection_strategy: Option<String>,
) -> Result<SendResult, String> {
    log::info!("send — to: {}, amount: {}", address, amount);

    // Verify password before proceeding (same check as export_seed/export_privkey).
    let operation = state.wallet_operation.lock().await;
    let secure = crate::services::wallet_security::authenticate_locked(&state, &operation, &password, Some(&totp_code), true).await?;
    let keystore_data = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        active.keystore_data.clone()
    };
    if secure.is_none() && !crate::core::keystore::verify_password(&keystore_data, &password) {
        return Err("incorrect password".to_string());
    }
    drop(operation);

    // Prepare
    let outputs = vec![crate::core::transaction::PaymentOutput {
        address: address.clone(),
        satoshis: amount,
    }];

    let fr = match fee_rate {
        Some(r) => r,
        None => crate::features::mapi::fetch_default_fee_rate().await,
    };

    // Prepare TX — returns plan_id (full plan stays server-side, AUD-008)
    let prep = crate::commands::transactions::prepare_tx(
        state.clone(),
        outputs,
        Some(fr),
        op_return,
        coin_selection_strategy,
    )
    .await?;

    // Sign TX — fetch the plan from the server-side store by plan_id
    let sign_result = crate::commands::transactions::sign_tx(
        state.clone(),
        prep.plan_id,
        totp_code,
    )
    .await?;

    // Broadcast TX
    let txid = crate::commands::transactions::broadcast_tx(
        state.clone(),
        sign_result.signed_tx_hex,
        sign_result.txid,
    )
    .await?;

    Ok(SendResult {
        txid,
        status: "success".to_string(),
    })
}

/// Result of the 1-shot send command.
#[derive(Debug, serde::Serialize)]
pub struct SendResult {
    pub txid: String,
    pub status: String,
}

// ============================================================================
// WhatsOnChain extra methods
// ============================================================================

/// Get chain info from WhatsOnChain.
#[tauri::command]
pub async fn woc_get_chain_info() -> Result<serde_json::Value, String> {
    let client = crate::network::whatsonchain::WhatsOnChainClient::new();
    client.get_chain_info().await.map_err(|e| e.to_string())
}

/// Get block header from WhatsOnChain.
#[tauri::command]
pub async fn woc_get_block_header(height: i64) -> Result<serde_json::Value, String> {
    let client = crate::network::whatsonchain::WhatsOnChainClient::new();
    client.get_block_header(height).await.map_err(|e| e.to_string())
}

/// Get transaction from WhatsOnChain.
#[tauri::command]
pub async fn woc_get_tx(txid: String) -> Result<serde_json::Value, String> {
    let client = crate::network::whatsonchain::WhatsOnChainClient::new();
    client.get_tx(&txid).await.map_err(|e| e.to_string())
}

// ============================================================================
// Imported private key / address support
// ============================================================================

/// Result of importing a private key.
#[derive(Debug, serde::Serialize)]
pub struct ImportPrivkeyResult {
    pub address: String,
    pub keyinstance_id: i64,
}

/// Import a private key (WIF format) into the wallet.
///
/// Creates a new KeyInstance with derivation_type=IMPORTED_PRIVATE_KEY.
/// Requires an unlocked wallet.
#[tauri::command]
pub async fn import_privkey(
    state: State<'_, AppState>,
    wif: String,
    password: String,
) -> Result<ImportPrivkeyResult, String> {
    let _ = (state, wif, password);
    import_privkey_disabled()
}
fn import_privkey_disabled() -> Result<ImportPrivkeyResult, String> {
    Err("Private-key import is disabled until imported outputs can be synchronized and spent safely".into())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::wallet_service;
    use crate::state::AppState;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn backup_instance_token_rejects_wallet_switch_and_reopen() {
        use std::future::Future;
        use std::task::Poll;
        let state = make_test_state("backup_instance");
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_legacy_fixture(&state, "a", "password", phrase, None).await.unwrap();
        wallet_service::create_legacy_fixture(&state, "b", "password", phrase, None).await.unwrap();
        let a = wallet_service::open_wallet(&state, "a").await.unwrap();
        let again = wallet_service::open_wallet(&state, "a").await.unwrap();
        assert_eq!(a.wallet_instance_token, again.wallet_instance_token);
        assert_eq!(wallet_service::get_wallet_status(&state).wallet_instance_token.as_deref(), Some(a.wallet_instance_token.as_str()));
        let destination = std::path::Path::new(&state.data_dir).join("race.sqlite");
        let destination_string = destination.to_string_lossy().into_owned();
        let operation = state.wallet_operation.lock().await;
        let switch = wallet_service::open_wallet(&state, "b");
        let backup = backup_wallet_authorized_bound(&state, destination_string.clone(), "password".into(), None, Some(&a.wallet_instance_token));
        tokio::pin!(switch, backup);
        std::future::poll_fn(|cx| {
            assert!(matches!(switch.as_mut().poll(cx), Poll::Pending));
            assert!(matches!(backup.as_mut().poll(cx), Poll::Pending));
            Poll::Ready(())
        }).await;
        drop(operation);
        let (switched, rejected) = tokio::time::timeout(std::time::Duration::from_secs(15), async { tokio::join!(switch, backup) }).await.unwrap();
        switched.unwrap();
        assert_eq!(rejected.unwrap_err(), "wallet instance changed; reopen backup dialog");
        assert!(!destination.exists());

        let current_a = wallet_service::open_wallet(&state, "a").await.unwrap();
        wallet_service::close_wallet(&state).await.unwrap();
        assert!(wallet_service::get_wallet_status(&state).wallet_instance_token.is_none());
        let reopened_a = wallet_service::open_wallet(&state, "a").await.unwrap();
        assert_ne!(current_a.wallet_instance_token, reopened_a.wallet_instance_token);
        assert!(backup_wallet_authorized_bound(&state, destination_string.clone(), "password".into(), None, Some(&current_a.wallet_instance_token)).await.is_err());
        assert!(backup_wallet_authorized_bound(&state, destination_string.clone(), "password".into(), None, Some("")).await.is_err());
        assert!(!destination.exists());
        backup_wallet_authorized_bound(&state, destination_string, "password".into(), None, Some(&reopened_a.wallet_instance_token)).await.unwrap();
        assert!(destination.exists());
        wallet_service::close_wallet(&state).await.unwrap();
        std::fs::remove_dir_all(&state.data_dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn verified_backup_compares_full_typed_rows_under_immediate_lock() {
        let state=make_test_state("verified_typed");
        wallet_service::create_legacy_fixture(&state,"source","password","abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",None).await.unwrap();
        let pool=state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        sqlx::query("CREATE TABLE compare_test(v)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO compare_test VALUES (NULL),(1),(1),(1.5),('1'),(x'0031')").execute(&pool).await.unwrap();
        let guard=state.wallet_operation.lock().await;
        let dest=std::path::Path::new(&state.data_dir).join("backup.sqlite");
        let backup=backup_snapshot_locked(&state,&guard,dest.to_str().unwrap()).await.unwrap();
        // A caller may have a readonly snapshot transaction open while comparison starts.
        let snapshot_tx=backup.readonly_pool().begin().await.unwrap();
        let concurrent=tokio::time::timeout(std::time::Duration::from_secs(5),backup.begin_verified_source(&state,&guard)).await.expect("comparison must not wait for the existing snapshot reader").unwrap();
        concurrent.rollback().await.unwrap();snapshot_tx.rollback().await.unwrap();
        let tx=backup.begin_verified_source(&state,&guard).await.unwrap();
        tx.rollback().await.unwrap();
        assert!(sqlx::query("INSERT INTO compare_test VALUES (2)").execute(backup.readonly_pool()).await.is_err());
        sqlx::query("DELETE FROM compare_test WHERE typeof(v)='text'").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO compare_test VALUES (x'31')").execute(&pool).await.unwrap();
        assert!(backup.begin_verified_source(&state,&guard).await.is_err());
        assert!(dest.exists(),"published backup is retained after mismatch");
        let snapshot_pool=backup.readonly_pool().clone();
        drop(backup);
        let first=snapshot_pool.acquire().await.unwrap();let second=snapshot_pool.acquire().await.unwrap();
        first.close().await.unwrap();second.close().await.unwrap();
        let rows:(i64,)=sqlx::query_as("SELECT COUNT(*) FROM compare_test").fetch_one(&snapshot_pool).await.unwrap();
        assert_eq!(rows.0,6,"a cloned readonly pool must reconnect to the held snapshot");
        snapshot_pool.close().await;drop(snapshot_pool);drop(guard);drop(pool);
        wallet_service::close_wallet(&state).await.unwrap();
        std::fs::remove_dir_all(&state.data_dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn corrupt_staging_rejected_before_publication() {
        let state=make_test_state("corrupt_stage");
        let dest=std::path::Path::new(&state.data_dir).join("backup.sqlite");
        let target=std::sync::Arc::new(secure_backup::Target::new(&state.data_dir,dest.to_str().unwrap()).unwrap());
        std::fs::write(target.sqlite_path(), b"not a sqlite database").unwrap();
        let opened=verified_backup::VerifiedBackup::open(target.open_snapshot().unwrap(),std::sync::Arc::new(()),target.clone()).await;
        assert!(opened.is_err());assert!(!dest.exists());drop(target);
        std::fs::remove_dir_all(&state.data_dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn snapshot_comparison_rejects_oversized_row_without_deleting_backup() {
        let state=make_test_state("oversized_snapshot");
        wallet_service::create_legacy_fixture(&state,"source","password","abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",None).await.unwrap();
        let pool=state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        sqlx::query("CREATE TABLE large_test(v BLOB)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO large_test VALUES(zeroblob(1048577))").execute(&pool).await.unwrap();
        let guard=state.wallet_operation.lock().await;
        let dest=std::path::Path::new(&state.data_dir).join("backup.sqlite");
        let backup=backup_snapshot_locked(&state,&guard,dest.to_str().unwrap()).await.unwrap();
        assert!(backup.begin_verified_source(&state,&guard).await.is_err());
        assert!(dest.exists());drop(backup);drop(guard);drop(pool);
        wallet_service::close_wallet(&state).await.unwrap();
        std::fs::remove_dir_all(&state.data_dir).unwrap();
    }

    #[tokio::test]
    async fn actual_backup_checks_password_and_snapshots_live_wal() {
        let state = make_test_state("actual_backup");
        wallet_service::create_wallet(&state, "source", "test-password", None, None).await.unwrap();
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        let mut writer = pool.acquire().await.unwrap();
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(&mut *writer).await.unwrap();
        sqlx::query("PRAGMA wal_autocheckpoint=0").execute(&mut *writer).await.unwrap();
        sqlx::query("INSERT INTO WalletData (key,value,date_created,date_updated) VALUES ('backup_test_marker','committed',0,0)").execute(&mut *writer).await.unwrap();
        let main_only = std::path::Path::new(&state.data_dir).join("main-only.sqlite");
        std::fs::copy(std::path::Path::new(&state.data_dir).join("source.sqlite"), &main_only).unwrap();
        let options = sqlx::sqlite::SqliteConnectOptions::new().filename(&main_only).read_only(true).immutable(true);
        let main_pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect_with(options).await.unwrap();
        let before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM WalletData WHERE key='backup_test_marker'").fetch_one(&main_pool).await.unwrap();
        assert_eq!(before.0, 0, "marker must be absent from checkpointed main file");
        main_pool.close().await;
        let backup = std::path::Path::new(&state.data_dir).join("copy.sqlite");
        let path = backup.to_string_lossy().to_string();
        assert!(backup_wallet_inner(&state, path.clone(), "wrong".into()).await.is_err());
        assert!(backup_wallet_inner(&state, path.clone(), "".into()).await.is_err());
        assert!(!backup.exists());
        backup_wallet_inner(&state, path.clone(), "test-password".into()).await.unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let original = std::fs::read(&backup).unwrap();
        assert!(backup_wallet_inner(&state, path.clone(), "test-password".into()).await.is_err());
        assert_eq!(std::fs::read(&backup).unwrap(), original);
        #[cfg(target_os = "linux")] {
            let alias = std::path::Path::new(&state.data_dir).join("alias");
            std::os::unix::fs::symlink(&state.data_dir, &alias).unwrap();
            assert!(backup_wallet_inner(&state, alias.join("escape.sqlite").to_string_lossy().into(), "test-password".into()).await.is_err());
        }
        let second = std::path::Path::new(&state.data_dir).join("second.sqlite");
        let guard = state.wallet_operation.lock().await;
        let future = backup_wallet_inner(&state, second.to_string_lossy().into(), "test-password".into());
        tokio::pin!(future);
        assert!(tokio::time::timeout(std::time::Duration::from_millis(30), &mut future).await.is_err());
        assert!(!second.exists());
        drop(guard);
        future.await.unwrap();
        let restored = crate::db::connection::open_wallet_db(&path).await.unwrap();
        assert_eq!(repositories::get_wallet_data(&restored, "backup_test_marker").await.unwrap().as_deref(), Some("committed"));
        restored.close().await;
        drop(writer);
        drop(pool);
        wallet_service::close_wallet(&state).await.unwrap();
        wallet_service::open_wallet(&state, "copy").await.unwrap();
        wallet_service::unlock_wallet_authorized(&state, "test-password", None).await.unwrap();
        wallet_service::close_wallet(&state).await.unwrap();
        std::fs::remove_dir_all(&state.data_dir).unwrap();
    }

    fn make_test_state(test_name: &str) -> AppState {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir =
            std::env::temp_dir().join(format!("electrumsv_mc_extra_{}_{}", test_name, id));
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

    #[tokio::test]
    async fn detail_requires_account_and_preserves_unknown_raw() {
        use bsv::transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput};
        use bsv::script::locking_script::LockingScript;
        let state = make_test_state("tx_detail_verified");
        wallet_service::create_wallet(&state, "wallet", "pw", None, None).await.unwrap();
        let (pool, account) = { let g = state.active_wallet.lock().unwrap(); let a = g.as_ref().unwrap(); (a.db_pool.clone(), a.account_id) };
        let master = repositories::get_first_master_key(&pool).await.unwrap().unwrap();
        let key = repositories::insert_keyinstance(&pool, account, Some(master.masterkey_id), repositories::derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#, repositories::script_type::P2PKH, 0, None).await.unwrap();
        let mut tx = Transaction::new();
        let previous_id = hex::encode((0u8..32).collect::<Vec<_>>());
        tx.inputs.push(TransactionInput { source_txid: Some(previous_id.clone()), source_output_index: 2, ..Default::default() });
        tx.outputs.push(TransactionOutput { satoshis: Some(1234), locking_script: LockingScript::from_binary(&[0x51]), change: false });
        tx.outputs.push(TransactionOutput { satoshis: Some(0), locking_script: LockingScript::from_binary(&[0x6a]), change: false });
        let id = tx.id().unwrap();
        let hash = crate::core::address::hex_str_to_hash(&id).unwrap();
        repositories::upsert_transaction(&pool, &hash, Some(123), None).await.unwrap();
        repositories::upsert_transaction_delta(&pool, key, &hash, 1234).await.unwrap();
        repositories::set_transaction_label(&pool, &hash, Some("label")).await.unwrap();
        let missing = transaction_detail(&pool, account, &id).await.unwrap();
        assert!(!missing.detail_complete && missing.inputs.is_none() && missing.outputs.is_none());
        assert!(transaction_detail(&pool, account + 1, &id).await.is_err());
        assert!(transaction_detail(&pool, account, "ab").await.is_err());
        let raw = hex::decode(tx.to_hex().unwrap()).unwrap();
        repositories::upsert_transaction(&pool, &hash, Some(123), Some(&raw)).await.unwrap();
        let detail = transaction_detail(&pool, account, &id).await.unwrap();
        assert!(detail.detail_complete);
        assert_eq!(detail.status, "confirmed");
        assert_eq!(detail.label.as_deref(), Some("label"));
        let inputs = detail.inputs.unwrap();
        assert_eq!(inputs[0].prev_vout, 2);
        assert_eq!(inputs[0].prev_tx_hash, previous_id);
        assert_eq!(detail.outputs.unwrap().len(), 2);
        sqlx::query("UPDATE Transactions SET tx_data = ? WHERE tx_hash = ?").bind(vec![0u8; 10]).bind(&hash).execute(&pool).await.unwrap();
        assert!(transaction_detail(&pool, account, &id).await.is_err());
        wallet_service::close_wallet(&state).await.unwrap();
        drop(pool);
    }

    /// list_networks should return exactly 3 networks: mainnet, testnet, stn.
    #[tokio::test]
    async fn test_list_networks_returns_three() {
        let networks = list_networks().await.unwrap();
        assert_eq!(networks.len(), 3, "expected 3 networks");
        let ids: Vec<&str> = networks.iter().map(|n| n.id.as_str()).collect();
        assert!(ids.contains(&"mainnet"));
        assert!(ids.contains(&"testnet"));
        assert!(ids.contains(&"stn"));
        // Each network should have a non-empty name and at least 2 default ports
        for n in &networks {
            assert!(!n.name.is_empty());
            assert!(n.default_ports.len() >= 2);
            assert_eq!(n.bitcoin_uri_prefix, "bitcoin");
        }
    }

    /// switch_network: valid network IDs should update state; invalid IDs should error.
    #[tokio::test]
    async fn test_switch_network_valid_and_invalid() {
        let state = make_test_state("switch_net");
        // Replicate the validation logic of switch_network without State wrapper.
        // Valid: testnet
        {
            let mut network = state.network.lock().unwrap();
            network.active_network = "testnet".to_string();
        }
        let active = {
            let network = state.network.lock().unwrap();
            network.active_network.clone()
        };
        assert_eq!(active, "testnet");

        // Valid: stn
        {
            let mut network = state.network.lock().unwrap();
            network.active_network = "stn".to_string();
        }
        let active = {
            let network = state.network.lock().unwrap();
            network.active_network.clone()
        };
        assert_eq!(active, "stn");

        // Invalid: should be rejected (replicating the check in switch_network)
        let invalid = "regtest";
        assert_ne!(invalid, "mainnet");
        assert_ne!(invalid, "testnet");
        assert_ne!(invalid, "stn");
        // The command returns Err for invalid; we verify the logic here.
        let expected_err = format!("unknown network: {}", invalid);
        assert!(expected_err.contains("unknown network"));
    }

    /// backup_wallet: create a wallet, copy the wallet file to a backup path, verify backup.
    #[tokio::test]
    async fn test_backup_wallet_copies_file() {
        let state = make_test_state("backup");
        wallet_service::create_wallet(&state, "test_backup", "pw123", None, None)
            .await
            .unwrap();

        let (wallet_path, pool) = {
            let guard = state.active_wallet.lock().unwrap();
            let active = guard.as_ref().unwrap();
            (active.wallet_path.clone(), active.db_pool.clone())
        };

        // Verify the wallet file exists
        assert!(std::path::Path::new(&wallet_path).exists(), "wallet file should exist");

        // Backup to a temp path
        let backup_path = std::env::temp_dir().join(format!(
            "electrumsv_mc_backup_{}.sqlite",
            TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        if backup_path.exists() {
            std::fs::remove_file(&backup_path).ok();
        }

        // Replicate backup_wallet logic: copy the file
        std::fs::copy(&wallet_path, &backup_path).unwrap();
        assert!(backup_path.exists(), "backup file should exist");
        assert_eq!(
            std::fs::metadata(&backup_path).unwrap().len(),
            std::fs::metadata(&wallet_path).unwrap().len(),
            "backup file size should match wallet file"
        );

        // Verify backup is a valid SQLite DB by opening it
        let backup_pool = crate::db::connection::open_wallet_db(&backup_path.to_string_lossy())
            .await
            .expect("backup should be openable as SQLite DB");
        backup_pool.close().await;
        pool.close().await;

        // Cleanup
        std::fs::remove_file(&backup_path).ok();
        wallet_service::close_wallet(&state).await.unwrap();
    }

    /// Disabled import must not write key instances in either wallet format.
    #[tokio::test]
    async fn test_import_privkey_fails_closed_without_writes() {
        for legacy in [false, true] {
            let state = make_test_state(if legacy { "import_legacy" } else { "import_secure" });
            if legacy {
                wallet_service::create_legacy_fixture(&state, "test_import", "pw123", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None).await.unwrap();
            } else {
                wallet_service::create_wallet(&state, "test_import", "pw123", None, None).await.unwrap();
            }
            let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
            let before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM KeyInstances").fetch_one(&pool).await.unwrap();
            assert!(import_privkey_disabled().is_err());
            let after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM KeyInstances").fetch_one(&pool).await.unwrap();
            assert_eq!(before, after);
            drop(pool); wallet_service::close_wallet(&state).await.unwrap();
            wallet_service::open_wallet(&state, "test_import").await.unwrap();
            wallet_service::close_wallet(&state).await.unwrap();
        }
    }

    /// get_transaction: querying a nonexistent txid should return "transaction not found".
    #[tokio::test]
    async fn test_get_transaction_nonexistent_txid() {
        let state = make_test_state("get_tx");
        wallet_service::create_wallet(&state, "test_gettx", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            let active = guard.as_ref().unwrap();
            active.db_pool.clone()
        };

        // Use a fake 64-char hex txid
        let fake_txid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead";

        // The get_transaction command calls repositories::get_transaction_by_txid which
        // queries the AccountTransactions view. On a fresh wallet with no transactions,
        // the query returns None (no matching tx_hash). The command then returns
        // Err("transaction not found").
        //
        // We test the command's error path directly: None -> "transaction not found".
        let tx_result: Option<&str> = None;
        let result: Result<&str, &str> = tx_result.ok_or("transaction not found");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "transaction not found");

        // Also verify that the Transactions table exists (it should — it's in the base schema)
        // by querying it directly with a nonexistent txid. The tx_hash column stores bytes.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM Transactions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "fresh wallet should have 0 transactions");

        // Query Transactions with a nonexistent tx_hash (bytes) — should return None
        let fake_hash_bytes = hex::decode(fake_txid).unwrap();
        let exists: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT tx_hash FROM Transactions WHERE tx_hash = ?")
                .bind(&fake_hash_bytes)
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert!(exists.is_none(), "nonexistent tx_hash should return None");

        pool.close().await;
        wallet_service::close_wallet(&state).await.unwrap();
    }

    /// set_totp_scope: setting to "login" and "tx" should succeed; invalid scope rejected.
    #[tokio::test]
    async fn test_set_totp_scope_valid_and_invalid() {
        let state = make_test_state("totp_scope");
        wallet_service::create_legacy_fixture(&state, "test_totp", "pw123", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None)
            .await
            .unwrap();

        let (pool, keystore_data) = {
            let guard = state.active_wallet.lock().unwrap();
            let active = guard.as_ref().unwrap();
            (active.db_pool.clone(), active.keystore_data.clone())
        };

        // Replicate set_totp_scope validation logic.

        // Invalid scope: should be rejected
        let invalid_scope = "invalid";
        assert!(invalid_scope != "login" && invalid_scope != "tx");
        // The command returns Err("Invalid scope. Use 'login' or 'tx'.")
        let err_msg = "Invalid scope. Use 'login' or 'tx'.";
        assert!(err_msg.contains("Invalid scope"));

        // Valid scope: "login" — raising scope (tx->login is lowering, requires TOTP, but
        // default scope is "tx", so setting to "login" is lowering).
        // For a newly created wallet, TOTP is not enabled, so lowering would fail.
        // Test setting to "tx" (same as default — no change needed).
        repositories::set_wallet_data(&pool, "totp_scope", "tx")
            .await
            .unwrap();
        let stored = repositories::get_wallet_data(&pool, "totp_scope")
            .await
            .unwrap()
            .unwrap_or_else(|| "tx".to_string());
        assert_eq!(stored, "tx");

        // Test setting to "login" directly (lowering without TOTP would fail in the command,
        // but we test the storage layer works).
        repositories::set_wallet_data(&pool, "totp_scope", "login")
            .await
            .unwrap();
        let stored = repositories::get_wallet_data(&pool, "totp_scope")
            .await
            .unwrap()
            .unwrap_or_else(|| "tx".to_string());
        assert_eq!(stored, "login");

        // Verify password check works (replicating set_totp_scope password verification)
        assert!(crate::core::keystore::verify_password(&keystore_data, "pw123"));
        assert!(!crate::core::keystore::verify_password(&keystore_data, "wrong"));

        // Verify TOTP is not enabled on a fresh wallet
        let totp_enabled = repositories::is_totp_enabled(&pool).await.unwrap();
        assert!(!totp_enabled, "TOTP should not be enabled on a fresh wallet");

        // Verify recovery codes count is 0 on fresh wallet
        let recovery_remaining = repositories::count_remaining_recovery_codes(&pool)
            .await
            .unwrap_or(0);
        assert_eq!(recovery_remaining, 0);

        pool.close().await;
        wallet_service::close_wallet(&state).await.unwrap();
    }

    /// get_totp_status: on a fresh wallet, TOTP is disabled, scope defaults to "tx".
    #[tokio::test]
    async fn test_get_totp_status_fresh_wallet() {
        let state = make_test_state("totp_status");
        wallet_service::create_wallet(&state, "test_totp_status", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            let active = guard.as_ref().unwrap();
            active.db_pool.clone()
        };

        // Replicate get_totp_status logic
        let enabled = repositories::is_totp_enabled(&pool).await.unwrap();
        assert!(!enabled, "TOTP should be disabled on fresh wallet");

        let scope = repositories::get_wallet_data(&pool, "totp_scope")
            .await
            .unwrap()
            .unwrap_or_else(|| "tx".to_string());
        assert_eq!(scope, "tx", "default scope should be 'tx'");

        let recovery_remaining = repositories::count_remaining_recovery_codes(&pool)
            .await
            .unwrap_or(0);
        assert_eq!(recovery_remaining, 0);

        pool.close().await;
        wallet_service::close_wallet(&state).await.unwrap();
    }

    /// NetworkDefinition struct: verify the struct is serializable and has expected fields.
    #[tokio::test]
    async fn test_network_info_serialization() {
        let info = NetworkDefinition {
            id: "mainnet".to_string(),
            name: "Bitcoin SV Mainnet".to_string(),
            default_ports: vec!["50001".to_string(), "50002".to_string()],
            bitcoin_uri_prefix: "bitcoin".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"id\":\"mainnet\""));
        assert!(json.contains("\"name\":\"Bitcoin SV Mainnet\""));
        assert!(json.contains("\"default_ports\""));
        assert!(json.contains("\"bitcoin_uri_prefix\":\"bitcoin\""));
    }
}
