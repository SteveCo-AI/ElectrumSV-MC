// db/repositories.rs — SQL queries for MasterKeys, Accounts, WalletData
//
// Provides typed database operations for the wallet tables.
// All queries use sqlx async SQLite.

use sqlx::SqlitePool;

/// Script type constants (matches Python ScriptType.IntEnum).
pub mod script_type {
    pub const NONE: i32 = 0;
    pub const COINBASE: i32 = 1;
    pub const P2PKH: i32 = 2;
    pub const P2PK: i32 = 3;
    /// Multisig account using accumulator-style m-of-n script (see core/multisig.rs).
    pub const MULTISIG: i32 = 4;
}

/// Derivation type constants (matches Python DerivationType.IntEnum).
pub mod derivation_type {
    pub const BIP32: i32 = 3;
}

/// A MasterKey row from the database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct MasterKeyRow {
    pub masterkey_id: i64,
    pub parent_masterkey_id: Option<i64>,
    pub derivation_type: i32,
    pub derivation_data: Vec<u8>,
    pub date_created: i64,
    pub date_updated: i64,
}

/// An Account row from the database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct AccountRow {
    pub account_id: i64,
    pub default_masterkey_id: Option<i64>,
    pub default_script_type: i32,
    pub account_name: String,
    pub date_created: i64,
    pub date_updated: i64,
}

/// Insert a master key into the MasterKeys table.
pub async fn insert_master_key(
    pool: &SqlitePool,
    parent_masterkey_id: Option<i64>,
    derivation_type: i32,
    derivation_data: &[u8],
) -> anyhow::Result<i64> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO MasterKeys (parent_masterkey_id, derivation_type, derivation_data, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(parent_masterkey_id)
    .bind(derivation_type)
    .bind(derivation_data)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Insert an account into the Accounts table.
pub async fn insert_account(
    pool: &SqlitePool,
    default_masterkey_id: Option<i64>,
    default_script_type: i32,
    account_name: &str,
) -> anyhow::Result<i64> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO Accounts (default_masterkey_id, default_script_type, account_name, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(default_masterkey_id)
    .bind(default_script_type)
    .bind(account_name)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Get a single WalletData value by key.
pub async fn get_wallet_data(pool: &SqlitePool, key: &str) -> anyhow::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM WalletData WHERE key=?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(v,)| v))
}

/// Set a WalletData value (insert or update).
pub async fn set_wallet_data(pool: &SqlitePool, key: &str, value: &str) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO WalletData (key, value, date_created, date_updated) VALUES (?, ?, ?, ?) \
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, date_updated=excluded.date_updated",
    )
    .bind(key)
    .bind(value)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Read the first master key from the database (the primary wallet key).
pub async fn get_first_master_key(pool: &SqlitePool) -> anyhow::Result<Option<MasterKeyRow>> {
    let row =
        sqlx::query_as::<_, MasterKeyRow>("SELECT * FROM MasterKeys ORDER BY masterkey_id LIMIT 1")
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// Read the first account from the database.
pub async fn get_first_account(pool: &SqlitePool) -> anyhow::Result<Option<AccountRow>> {
    let row = sqlx::query_as::<_, AccountRow>("SELECT * FROM Accounts ORDER BY account_id LIMIT 1")
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

// ============================================================================
// KeyInstance queries (Milestone 3)
// ============================================================================

/// A KeyInstance row from the database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct KeyInstanceRow {
    pub keyinstance_id: i64,
    pub account_id: i64,
    pub masterkey_id: Option<i64>,
    pub derivation_type: i32,
    pub derivation_data: Vec<u8>,
    pub script_type: i32,
    pub flags: i32,
    pub description: Option<String>,
    pub date_created: i64,
    pub date_updated: i64,
}

/// Get all KeyInstances for a given account.
pub async fn get_keyinstances_for_account(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<Vec<KeyInstanceRow>> {
    let rows = sqlx::query_as::<_, KeyInstanceRow>(
        "SELECT * FROM KeyInstances WHERE account_id = ? ORDER BY keyinstance_id",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_keyinstances_for_account_bounded(pool: &SqlitePool, account_id: i64, max: u32) -> anyhow::Result<Vec<KeyInstanceRow>> {
    let rows = sqlx::query_as::<_, KeyInstanceRow>("SELECT * FROM KeyInstances WHERE account_id = ? ORDER BY keyinstance_id LIMIT ?")
        .bind(account_id).bind(i64::from(max) + 1).fetch_all(pool).await?;
    if rows.len() > max as usize { anyhow::bail!("scan key limit exceeded"); }
    Ok(rows)
}

/// Get a single KeyInstance by ID.
pub async fn get_keyinstance(
    pool: &SqlitePool,
    keyinstance_id: i64,
) -> anyhow::Result<Option<KeyInstanceRow>> {
    let row =
        sqlx::query_as::<_, KeyInstanceRow>("SELECT * FROM KeyInstances WHERE keyinstance_id = ?")
            .bind(keyinstance_id)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// Insert a new KeyInstance.
pub async fn insert_keyinstance(
    pool: &SqlitePool,
    account_id: i64,
    masterkey_id: Option<i64>,
    derivation_type: i32,
    derivation_data: &[u8],
    script_type: i32,
    flags: i32,
    description: Option<&str>,
) -> anyhow::Result<i64> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO KeyInstances \
         (account_id, masterkey_id, derivation_type, derivation_data, script_type, flags, description, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(account_id)
    .bind(masterkey_id)
    .bind(derivation_type)
    .bind(derivation_data)
    .bind(script_type)
    .bind(flags)
    .bind(description)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Get the next keyinstance index for an account.
/// Returns (receiving_count, change_count) based on existing KeyInstances.
pub async fn get_keyinstance_counts(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<(i64, i64)> {
    // Count KeyInstances by parsing derivation_data JSON for subpath type
    // subpath[0] = 0 → receiving, subpath[0] = 1 → change
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT derivation_data FROM KeyInstances WHERE account_id = ? AND derivation_type = ?",
    )
    .bind(account_id)
    .bind(derivation_type::BIP32)
    .fetch_all(pool)
    .await?;

    let mut receiving = 0i64;
    let mut change = 0i64;

    for (data,) in &rows {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
            if let Some(subpath) = json.get("subpath").and_then(|s| s.as_array()) {
                if let Some(type_idx) = subpath.first().and_then(|t| t.as_i64()) {
                    if type_idx == 0 {
                        receiving += 1;
                    } else if type_idx == 1 {
                        change += 1;
                    }
                }
            }
        }
    }

    Ok((receiving, change))
}

pub async fn next_keyinstance_index(pool: &SqlitePool, account_id: i64, chain: i64) -> anyhow::Result<i64> {
    let keys = get_keyinstances_for_account(pool, account_id).await?;
    let mut next = 0;
    for key in keys {
        if key.derivation_type != derivation_type::BIP32 { continue; }
        let json: serde_json::Value = serde_json::from_slice(&key.derivation_data)?;
        let path = json.get("subpath").and_then(|v| v.as_array()).ok_or_else(|| anyhow::anyhow!("invalid key path"))?;
        if path.first().and_then(|v| v.as_i64()) == Some(chain) {
            let index = path.get(1).and_then(|v| v.as_i64()).filter(|i| *i >= 0).ok_or_else(|| anyhow::anyhow!("invalid key index"))?;
            next = next.max(index.checked_add(1).ok_or_else(|| anyhow::anyhow!("key index overflow"))?);
        }
    }
    Ok(next)
}

// ============================================================================
// TransactionOutput queries (Milestone 3)
// ============================================================================

/// TransactionOutput flag constants (matches Python TransactionOutputFlag).
pub mod txo_flags {
    /// Output is coinbase (bit 0).
    pub const IS_COINBASE: i32 = 1;
    /// Output is spent (bit 1).
    pub const IS_SPENT: i32 = 2;
}

/// A TransactionOutput row from the database.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TransactionOutputRow {
    pub tx_hash: Vec<u8>,
    pub tx_index: i64,
    pub value: i64,
    pub keyinstance_id: i64,
    pub flags: i32,
    pub date_created: i64,
    pub date_updated: i64,
    /// Locking script hex (added in migration 0031; NULL for old rows).
    pub script_pubkey: Option<String>,
}

/// Get all unspent TransactionOutputs (UTXOs) for KeyInstances of an account.
///
/// UTXO = TransactionOutputs where flags & IS_SPENT == 0
pub async fn get_utxos_for_account(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<Vec<TransactionOutputRow>> {
    let rows = sqlx::query_as::<_, TransactionOutputRow>(
        "SELECT txo.* FROM TransactionOutputs txo \
         INNER JOIN KeyInstances ki ON txo.keyinstance_id = ki.keyinstance_id \
         WHERE ki.account_id = ? AND (txo.flags & ?) = 0 \
         ORDER BY txo.date_created",
    )
    .bind(account_id)
    .bind(txo_flags::IS_SPENT)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Get the balance (sum of UTXO values) for an account.
///
/// Returns (confirmed, unconfirmed, total).
/// confirmed = UTXOs where the corresponding Transaction has a block_height
/// unconfirmed = UTXOs where the Transaction has no block_height
pub async fn get_balance_for_account(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<(i64, i64, i64)> {
    let rows: Vec<(i64, Option<i64>)> = sqlx::query_as(
        "SELECT txo.value, tx.block_height \
         FROM TransactionOutputs txo \
         INNER JOIN KeyInstances ki ON txo.keyinstance_id = ki.keyinstance_id \
         INNER JOIN Transactions tx ON txo.tx_hash = tx.tx_hash \
         WHERE ki.account_id = ? AND (txo.flags & ?) = 0",
    )
    .bind(account_id)
    .bind(txo_flags::IS_SPENT)
    .fetch_all(pool)
    .await?;

    let mut confirmed = 0i64;
    let mut unconfirmed = 0i64;

    for (value, block_height) in &rows {
        if block_height.is_some() {
            confirmed += value;
        } else {
            unconfirmed += value;
        }
    }

    Ok((confirmed, unconfirmed, confirmed + unconfirmed))
}

// ============================================================================
// TransactionDelta queries (Milestone 3)
// ============================================================================

/// A TransactionDelta row joined with Transaction data for history.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TxDeltaHistoryRow {
    /// Display hex txid (reversed byte order, AUD-014 fix)
    pub tx_hash_hex: String,
    /// Net value delta for this account (sum of deltas)
    pub value_delta: Option<i64>,
    /// Transaction creation timestamp
    pub date_created: i64,
    /// Block height (None = unconfirmed)
    pub block_height: Option<i64>,
    /// Transaction description (if any)
    pub description: Option<String>,
}

/// Get transaction history (deltas) for an account.
///
/// Joins TransactionDeltas with Transactions, grouped by tx_hash.
/// Uses hash_to_hex_str for proper byte-order conversion (AUD-014).
pub async fn get_tx_history_for_account(
    pool: &SqlitePool,
    account_id: i64,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<TxDeltaHistoryRow>> {
    // First get the raw deltas joined with transactions
    let rows: Vec<(Vec<u8>, Option<i64>, i64, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT td.tx_hash, CASE WHEN MIN(td.value_known) = 1 THEN SUM(td.value_delta) ELSE NULL END as value_delta, \
         MIN(tx.date_created) as date_created, \
         tx.block_height, tx.description \
         FROM TransactionDeltas td \
         INNER JOIN KeyInstances ki ON td.keyinstance_id = ki.keyinstance_id \
         INNER JOIN Transactions tx ON td.tx_hash = tx.tx_hash \
         WHERE ki.account_id = ? \
         GROUP BY td.tx_hash \
         ORDER BY MIN(tx.date_created) DESC \
         LIMIT ? OFFSET ?",
    )
    .bind(account_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    // Convert tx_hash bytes to display hex (reversed)
    let result: Vec<TxDeltaHistoryRow> = rows
        .into_iter()
        .map(
            |(tx_hash, value_delta, date_created, block_height, description)| TxDeltaHistoryRow {
                tx_hash_hex: crate::core::address::hash_to_hex_str(&tx_hash),
                value_delta,
                date_created,
                block_height,
                description,
            },
        )
        .collect();

    Ok(result)
}

/// UTXO info for API responses (with display hex txid).
#[derive(Debug, Clone, serde::Serialize)]
pub struct UtxoInfo {
    /// Display hex txid (reversed byte order, AUD-014 fix)
    pub tx_hash_hex: String,
    pub tx_index: i64,
    pub value: i64,
    pub keyinstance_id: i64,
    pub is_coinbase: bool,
    /// Locking script hex (empty string if not available — old rows).
    pub script_pubkey: String,
}

/// Get UTXOs for an account as serializable UtxoInfo.
pub async fn get_utxo_infos_for_account(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<Vec<UtxoInfo>> {
    let rows = get_utxos_for_account(pool, account_id).await?;

    let result: Vec<UtxoInfo> = rows
        .into_iter()
        .map(|row| UtxoInfo {
            tx_hash_hex: crate::core::address::hash_to_hex_str(&row.tx_hash),
            tx_index: row.tx_index,
            value: row.value,
            keyinstance_id: row.keyinstance_id,
            is_coinbase: (row.flags & txo_flags::IS_COINBASE) != 0,
            script_pubkey: row.script_pubkey.unwrap_or_default(),
        })
        .collect();

    Ok(result)
}

// ============================================================================
// Transaction / TransactionOutput / TransactionDelta upserts (Milestone 4 Teil 4)
// ============================================================================

/// Transaction flag constants (matches Python TransactionFlag).
pub mod tx_flags {
    /// Transaction is unconfirmed (bit 0).
    pub const IS_UNCONFIRMED: i32 = 1;
    /// Transaction is coinbase (bit 1).
    pub const IS_COINBASE: i32 = 2;
}

/// Upsert a Transaction row (insert or update by tx_hash).
///
/// `tx_hash` is the internal byte order hash (not display/reversed).
/// `block_height` is None for unconfirmed transactions.
/// `tx_data` is the raw transaction bytes (optional — we don't fetch full tx yet).
pub async fn upsert_transaction(
    pool: &SqlitePool,
    tx_hash: &[u8],
    block_height: Option<i64>,
    tx_data: Option<&[u8]>,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    let flags = if block_height.is_none() {
        tx_flags::IS_UNCONFIRMED
    } else {
        0
    };

    sqlx::query(
        "INSERT INTO Transactions (tx_hash, tx_data, block_height, flags, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT(tx_hash) DO UPDATE SET \
            block_height = excluded.block_height, \
            flags = excluded.flags, \
            tx_data = COALESCE(excluded.tx_data, Transactions.tx_data), \
            date_updated = excluded.date_updated",
    )
    .bind(tx_hash)
    .bind(tx_data)
    .bind(block_height)
    .bind(flags)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Upsert a TransactionOutput row (insert or update by (tx_hash, tx_index)).
///
/// `tx_hash` is the internal byte order hash.
/// `keyinstance_id` links to the KeyInstance that owns this output.
/// `value` is in satoshis. `flags` uses txo_flags constants.
pub async fn upsert_transaction_output(
    pool: &SqlitePool,
    tx_hash: &[u8],
    tx_index: i64,
    value: i64,
    keyinstance_id: i64,
    flags: i32,
    script_pubkey: Option<&str>,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();

    sqlx::query(
        "INSERT INTO TransactionOutputs (tx_hash, tx_index, value, keyinstance_id, flags, script_pubkey, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(tx_hash, tx_index) DO UPDATE SET \
            value = excluded.value, \
            keyinstance_id = excluded.keyinstance_id, \
            flags = excluded.flags, \
            script_pubkey = COALESCE(excluded.script_pubkey, TransactionOutputs.script_pubkey), \
            date_updated = excluded.date_updated",
    )
    .bind(tx_hash)
    .bind(tx_index)
    .bind(value)
    .bind(keyinstance_id)
    .bind(flags)
    .bind(script_pubkey)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Upsert a TransactionDelta row (insert or update by (keyinstance_id, tx_hash)).
///
/// `tx_hash` is the internal byte order hash.
/// `value_delta` is the net change in satoshis (positive = received, negative = sent).
pub async fn upsert_transaction_delta(
    pool: &SqlitePool,
    keyinstance_id: i64,
    tx_hash: &[u8],
    value_delta: i64,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();

    sqlx::query(
        "INSERT INTO TransactionDeltas (keyinstance_id, tx_hash, value_delta, date_created, date_updated, value_known) \
         VALUES (?, ?, ?, ?, ?, 1) \
         ON CONFLICT(keyinstance_id, tx_hash) DO UPDATE SET \
            value_delta = excluded.value_delta, value_known = 1, \
            date_updated = excluded.date_updated",
    )
    .bind(keyinstance_id)
    .bind(tx_hash)
    .bind(value_delta)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Mark a TransactionOutput as spent (set IS_SPENT flag).
///
/// Called during sync when the server's UTXO list no longer includes
/// an output that we previously had as unspent.
pub async fn mark_output_spent(
    pool: &SqlitePool,
    tx_hash: &[u8],
    tx_index: i64,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();

    sqlx::query(
        "UPDATE TransactionOutputs \
         SET flags = flags | ?, date_updated = ? \
         WHERE tx_hash = ? AND tx_index = ?",
    )
    .bind(txo_flags::IS_SPENT)
    .bind(now)
    .bind(tx_hash)
    .bind(tx_index)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get all TransactionOutputs for a set of keyinstance_ids.
///
/// Used during sync to compare local UTXOs against server-reported UTXOs.
pub async fn get_outputs_for_keyinstances(
    pool: &SqlitePool,
    keyinstance_ids: &[i64],
) -> anyhow::Result<Vec<TransactionOutputRow>> {
    if keyinstance_ids.is_empty() {
        return Ok(Vec::new());
    }

    // Build IN clause placeholders
    let placeholders: Vec<String> = (0..keyinstance_ids.len())
        .map(|_| "?".to_string())
        .collect();
    let in_clause = placeholders.join(",");

    let sql = format!(
        "SELECT * FROM TransactionOutputs WHERE keyinstance_id IN ({}) AND (flags & ?) = 0",
        in_clause
    );

    let mut query = sqlx::query_as::<_, TransactionOutputRow>(&sql).bind(txo_flags::IS_SPENT);
    for id in keyinstance_ids {
        query = query.bind(id);
    }

    let rows = query.fetch_all(pool).await?;
    Ok(rows)
}

pub struct SyncTransaction {
    pub hash: Vec<u8>,
    pub height: Option<i64>,
    pub raw: std::sync::Arc<[u8]>,
    pub delta: Option<i64>,
}
pub struct SyncOutput {
    pub hash: Vec<u8>,
    pub height: Option<i64>,
    pub index: i64,
    pub value: i64,
    pub coinbase: bool,
    pub script_pubkey: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncKeyRef {
    Existing(i64),
    Discovered(usize),
}

pub struct SyncKeySnapshot {
    pub key_id: SyncKeyRef,
    pub transactions: Vec<SyncTransaction>,
    pub outputs: Vec<SyncOutput>,
}

#[derive(Clone)]
pub(crate) struct ScanDerivationSource {
    pub account_id: i64,
    pub master: MasterKeyRow,
}

pub(crate) async fn load_scan_derivation_source(pool: &SqlitePool, account_id: i64) -> anyhow::Result<ScanDerivationSource> {
    let master: MasterKeyRow = sqlx::query_as("SELECT m.* FROM Accounts a JOIN MasterKeys m ON m.masterkey_id=a.default_masterkey_id WHERE a.account_id=?")
        .bind(account_id).fetch_one(pool).await?;
    Ok(ScanDerivationSource { account_id, master })
}

pub(crate) fn validate_scan_inventory(
    source: &ScanDerivationSource, keys: &[KeyInstanceRow], discovered: &[(u64,u64)],
    end: u32, deadline: tokio::time::Instant,
) -> anyhow::Result<std::collections::HashMap<SyncKeyRef,(u64,u64)>> {
    use std::collections::{HashMap,HashSet};
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct KeyPath { subpath: [u32;2] }
    if !(1..=1000).contains(&end) || source.master.derivation_type != derivation_type::BIP32 || source.master.parent_masterkey_id.is_some() {
        anyhow::bail!("unsupported scan derivation source or range");
    }
    let mut paths = HashMap::new();
    let mut unique = HashSet::new();
    for key in keys {
        if tokio::time::Instant::now() >= deadline { anyhow::bail!("scan deadline exceeded"); }
        if key.account_id != source.account_id || key.masterkey_id != Some(source.master.masterkey_id)
            || key.derivation_type != derivation_type::BIP32 || key.script_type != script_type::P2PKH || key.derivation_data.len() > 256 {
            anyhow::bail!("unsupported scan key inventory");
        }
        let path: KeyPath = serde_json::from_slice(&key.derivation_data).map_err(|_| anyhow::anyhow!("unsupported scan key path"))?;
        let (chain,index) = (u64::from(path.subpath[0]),u64::from(path.subpath[1]));
        if chain > 1 || index >= (1 << 31) || !unique.insert((chain,index)) { anyhow::bail!("unsupported or duplicate scan key path"); }
        paths.insert(SyncKeyRef::Existing(key.keyinstance_id),(chain,index));
    }
    for (position,&(chain,index)) in discovered.iter().enumerate() {
        if tokio::time::Instant::now() >= deadline { anyhow::bail!("scan deadline exceeded"); }
        if chain > 1 || index >= u64::from(end) || !unique.insert((chain,index)) { anyhow::bail!("unsupported or duplicate discovered path"); }
        paths.insert(SyncKeyRef::Discovered(position),(chain,index));
    }
    Ok(paths)
}

/// Atomically replace one account's previously fetched and validated sync snapshot.
pub async fn replace_sync_snapshot(
    pool: &SqlitePool, account_id: i64, expected_keys: &[KeyInstanceRow],
    discovered: Option<&[(u64, u64)]>, snapshots: &[SyncKeySnapshot],
) -> anyhow::Result<()> {
    let expected_ids: std::collections::HashSet<SyncKeyRef> = expected_keys.iter().map(|key| SyncKeyRef::Existing(key.keyinstance_id))
        .chain((0..discovered.map_or(0, |paths| paths.len())).map(SyncKeyRef::Discovered)).collect();
    let snapshot_ids: std::collections::HashSet<SyncKeyRef> = snapshots.iter().map(|snapshot| snapshot.key_id).collect();
    if expected_ids.len() != expected_keys.len() + discovered.map_or(0, |paths| paths.len()) ||
        snapshot_ids.len() != snapshots.len() || snapshot_ids != expected_ids {
        anyhow::bail!("snapshot must contain every account key exactly once");
    }
    if let Some(paths) = discovered {
        let unique: std::collections::HashSet<_> = paths.iter().collect();
        if unique.len() != paths.len() { anyhow::bail!("duplicate discovered derivation path"); }
    }
    let mut outpoints = std::collections::HashSet::new();
    for snapshot in snapshots {
        for output in &snapshot.outputs {
            if !outpoints.insert((output.hash.as_slice(), output.index)) {
                anyhow::bail!("duplicate UTXO outpoint in snapshot");
            }
        }
    }
    let mut tx = pool.begin().await?;
    let current = sqlx::query_as::<_, KeyInstanceRow>(
        "SELECT * FROM KeyInstances WHERE account_id = ? ORDER BY keyinstance_id")
        .bind(account_id).fetch_all(&mut *tx).await?;
    if current.len() != expected_keys.len() || current.iter().zip(expected_keys).any(|(a, b)|
        a.keyinstance_id != b.keyinstance_id || a.account_id != b.account_id ||
        a.derivation_type != b.derivation_type || a.derivation_data != b.derivation_data ||
        a.masterkey_id != b.masterkey_id || a.script_type != b.script_type ||
        a.flags != b.flags || a.description != b.description ||
        a.date_created != b.date_created || a.date_updated != b.date_updated) {
        anyhow::bail!("account keys changed during synchronization");
    }
    let now = chrono::Utc::now().timestamp();
    let mut new_ids = Vec::new();
    if let Some(paths) = discovered {
        let master: (i64,) = sqlx::query_as("SELECT default_masterkey_id FROM Accounts WHERE account_id = ? AND default_masterkey_id IS NOT NULL")
            .bind(account_id).fetch_one(&mut *tx).await?;
        for (chain, index) in paths {
            let data = serde_json::json!({"subpath": [chain, index]}).to_string().into_bytes();
            let inserted = sqlx::query("INSERT INTO KeyInstances (account_id, masterkey_id, derivation_type, derivation_data, script_type, flags, description, date_created, date_updated) VALUES (?, ?, ?, ?, ?, 0, NULL, ?, ?)")
                .bind(account_id).bind(master.0).bind(derivation_type::BIP32).bind(data).bind(script_type::P2PKH).bind(now).bind(now)
                .execute(&mut *tx).await?;
            new_ids.push(inserted.last_insert_rowid());
        }
        let marker = format!("address_discovery_v1_{account_id}");
        sqlx::query("INSERT INTO WalletData (key, value, date_created, date_updated) VALUES (?, 'done', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, date_updated = excluded.date_updated")
            .bind(marker).bind(now).bind(now).execute(&mut *tx).await?;
    }
    let resolve = |key: SyncKeyRef| -> anyhow::Result<i64> {
        match key {
            SyncKeyRef::Existing(id) => Ok(id),
            SyncKeyRef::Discovered(index) => new_ids.get(index).copied().ok_or_else(|| anyhow::anyhow!("invalid discovered key")),
        }
    };
    // Reject ownership conflicts before deleting any existing account outputs.
    for snapshot in snapshots {
        let id = resolve(snapshot.key_id)?;
        for output in &snapshot.outputs {
            let owner: Option<(i64,)> = sqlx::query_as("SELECT keyinstance_id FROM TransactionOutputs WHERE tx_hash = ? AND tx_index = ?")
                .bind(&output.hash).bind(output.index).fetch_optional(&mut *tx).await?;
            if owner.is_some_and(|owner| owner.0 != id) {
                anyhow::bail!("UTXO belongs to a different keyinstance");
            }
        }
    }
    for snapshot in snapshots {
        let id = resolve(snapshot.key_id)?;
        let incoming: std::collections::HashSet<(&[u8], i64)> = snapshot.outputs.iter()
            .map(|output| (output.hash.as_slice(), output.index)).collect();
        let stored: Vec<(Vec<u8>, i64)> = sqlx::query_as("SELECT tx_hash, tx_index FROM TransactionOutputs WHERE keyinstance_id = ?")
            .bind(id).fetch_all(&mut *tx).await?;
        for (hash, index) in stored {
            if !incoming.contains(&(hash.as_slice(), index)) {
                sqlx::query("DELETE FROM TransactionOutputs WHERE keyinstance_id = ? AND tx_hash = ? AND tx_index = ?")
                    .bind(id).bind(hash).bind(index).execute(&mut *tx).await?;
            }
        }
        sqlx::query("DELETE FROM TransactionDeltas WHERE keyinstance_id = ?").bind(id).execute(&mut *tx).await?;
        for item in &snapshot.transactions {
            sync_upsert_transaction(&mut tx, &item.hash, item.height, Some(item.raw.as_ref()), now).await?;
            sqlx::query("INSERT INTO TransactionDeltas (keyinstance_id, tx_hash, value_delta, date_created, date_updated, value_known) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(keyinstance_id, tx_hash) DO UPDATE SET value_delta = excluded.value_delta, value_known = excluded.value_known, date_updated = excluded.date_updated")
                .bind(id).bind(&item.hash).bind(item.delta.unwrap_or(0)).bind(now).bind(now).bind(i32::from(item.delta.is_some())).execute(&mut *tx).await?;
        }
        for output in &snapshot.outputs {
            sync_upsert_transaction(&mut tx, &output.hash, output.height, None, now).await?;
            let flags = if output.coinbase { txo_flags::IS_COINBASE } else { 0 };
            sqlx::query("INSERT INTO TransactionOutputs (tx_hash, tx_index, value, keyinstance_id, flags, script_pubkey, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(tx_hash, tx_index) DO UPDATE SET value = excluded.value, flags = (TransactionOutputs.flags & ?) | excluded.flags, script_pubkey = excluded.script_pubkey, date_updated = excluded.date_updated")
                .bind(&output.hash).bind(output.index).bind(output.value).bind(id).bind(flags).bind(&output.script_pubkey).bind(now).bind(now)
                .bind(!(txo_flags::IS_COINBASE | txo_flags::IS_SPENT)).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

async fn sync_upsert_transaction(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, hash: &[u8], height: Option<i64>, raw: Option<&[u8]>, now: i64) -> anyhow::Result<()> {
    let flags = if height.is_none() { tx_flags::IS_UNCONFIRMED } else { 0 };
    sqlx::query("INSERT INTO Transactions (tx_hash, tx_data, block_height, flags, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(tx_hash) DO UPDATE SET tx_data = COALESCE(excluded.tx_data, Transactions.tx_data), block_height = excluded.block_height, flags = (Transactions.flags & ?) | excluded.flags, date_updated = excluded.date_updated")
        .bind(hash).bind(raw).bind(height).bind(flags).bind(now).bind(now).bind(!tx_flags::IS_UNCONFIRMED).execute(&mut **tx).await?;
    Ok(())
}

/// Merge snapshots whose script-to-key ownership was validated by the scan collector.
pub(crate) async fn merge_explicit_scan_snapshot(
    pool: &SqlitePool, account_id: i64, expected_keys: &[KeyInstanceRow],
    source: &ScanDerivationSource, discovered: &[(u64, u64)], snapshots: &[SyncKeySnapshot], end: u32, deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
    merge_explicit_scan_impl(pool, account_id, expected_keys, source, discovered, snapshots, end, deadline, #[cfg(test)] None).await
}

#[cfg(test)]
struct ScanTestBarrier { started: tokio::sync::oneshot::Sender<()>, resume: tokio::sync::oneshot::Receiver<()> }

async fn merge_explicit_scan_impl(
    pool: &SqlitePool, account_id: i64, expected_keys: &[KeyInstanceRow],
    source: &ScanDerivationSource, discovered: &[(u64, u64)], snapshots: &[SyncKeySnapshot], end: u32, deadline: tokio::time::Instant,
    #[cfg(test)] barrier: Option<ScanTestBarrier>,
) -> anyhow::Result<()> {
    use std::collections::{HashMap, HashSet};
    if expected_keys.len() > 100_000 || discovered.len() > 2000 { anyhow::bail!("scan key limit exceeded"); }
    let key_paths = validate_scan_inventory(source, expected_keys, discovered, end, deadline)?;
    let record: serde_json::Value = serde_json::from_slice(&source.master.derivation_data).map_err(|_| anyhow::anyhow!("invalid scan derivation source"))?;
    let xpub = record.get("xpub").and_then(|value| value.as_str()).ok_or_else(|| anyhow::anyhow!("invalid scan derivation source"))?;
    let account_key = bsv::compat::bip32::ExtendedKey::from_string(xpub).map_err(|_| anyhow::anyhow!("invalid scan derivation source"))?;
    let expected: HashSet<SyncKeyRef> = expected_keys.iter().map(|k| SyncKeyRef::Existing(k.keyinstance_id))
        .chain((0..discovered.len()).map(SyncKeyRef::Discovered)).collect();
    let provided: HashSet<SyncKeyRef> = snapshots.iter().map(|s| s.key_id).collect();
    if expected.len() != expected_keys.len() + discovered.len() || provided.len() != snapshots.len() || expected != provided {
        anyhow::bail!("scan snapshot must contain every key exactly once");
    }
    if discovered.iter().collect::<HashSet<_>>().len() != discovered.len() { anyhow::bail!("duplicate discovered derivation path"); }
    let mut outpoints = HashSet::new();
    let mut raw_by_hash: HashMap<&[u8], &[u8]> = HashMap::new();
    let mut heights: HashMap<&[u8], Option<i64>> = HashMap::new();
    let mut history_count = 0usize;
    for snapshot in snapshots {
        if tokio::time::Instant::now() >= deadline { anyhow::bail!("scan deadline exceeded before commit"); }
        for item in &snapshot.transactions {
            history_count = history_count.checked_add(1).ok_or_else(|| anyhow::anyhow!("scan history count overflow"))?;
            if history_count > 100_000 || item.raw.len() > 4 * 1024 * 1024 { anyhow::bail!("scan history or transaction size limit exceeded"); }
            if item.raw.is_empty() { anyhow::bail!("scan transaction has no validated raw data"); }
            if let Some(old) = raw_by_hash.insert(&item.hash, &item.raw) {
                if old != item.raw.as_ref() { anyhow::bail!("conflicting scan transaction data"); }
            }
            if let Some(old) = heights.insert(&item.hash, item.height) {
                if old != item.height { anyhow::bail!("inconsistent scan transaction heights"); }
            }
        }
        let history: HashSet<&[u8]> = snapshot.transactions.iter().map(|item| item.hash.as_slice()).collect();
        if history.len() != snapshot.transactions.len() { anyhow::bail!("duplicate scan history entry"); }
        for output in &snapshot.outputs {
            if tokio::time::Instant::now() >= deadline { anyhow::bail!("scan deadline exceeded before commit"); }
            if !outpoints.insert((output.hash.as_slice(), output.index)) { anyhow::bail!("duplicate UTXO outpoint in scan"); }
            if outpoints.len() > 100_000 { anyhow::bail!("scan output limit exceeded"); }
            if !history.contains(output.hash.as_slice()) { anyhow::bail!("scan output missing validated history"); }
        }
    }
    if raw_by_hash.len() > 4096 || raw_by_hash.values().try_fold(0usize, |total, raw| total.checked_add(raw.len())).is_none_or(|size| size > 64 * 1024 * 1024) {
        anyhow::bail!("scan raw transaction limit exceeded");
    }
    let mut parsed_by_hash = HashMap::new();
    for (hash, raw) in &raw_by_hash {
        if tokio::time::Instant::now() >= deadline { anyhow::bail!("scan deadline exceeded before commit"); }
        crate::core::transaction::validate_transaction_wire(raw).map_err(anyhow::Error::msg)?;
        let raw_hex = hex::encode(raw);
        let parsed = bsv::transaction::transaction::Transaction::from_hex(&raw_hex).map_err(|e| anyhow::anyhow!("invalid scan transaction: {e}"))?;
        if parsed.id().map_err(|e| anyhow::anyhow!("invalid scan transaction ID: {e}"))? != crate::core::address::hash_to_hex_str(hash)
            || parsed.to_hex().map_err(|e| anyhow::anyhow!("invalid scan transaction: {e}"))? != raw_hex {
            anyhow::bail!("scan transaction ID or encoding mismatch");
        }
        parsed_by_hash.insert(*hash, parsed);
    }
    for snapshot in snapshots {
        if tokio::time::Instant::now() >= deadline { anyhow::bail!("scan deadline exceeded before commit"); }
        let expected_script = if snapshot.outputs.is_empty() { None } else {
            use bsv::script::templates::{p2pkh::P2PKH, ScriptTemplateLock};
            let (chain,index) = key_paths.get(&snapshot.key_id).ok_or_else(|| anyhow::anyhow!("invalid scan key"))?;
            let public = account_key.derive(&format!("{chain}/{index}")).map_err(|_| anyhow::anyhow!("invalid scan key derivation"))?
                .public_key().map_err(|_| anyhow::anyhow!("invalid scan key derivation"))?;
            let address = crate::core::address::pubkey_to_p2pkh_address(&public);
            Some(P2PKH::from_address(&address).map_err(|_| anyhow::anyhow!("invalid scan key address"))?
                .lock().map_err(|_| anyhow::anyhow!("invalid scan key script"))?.to_binary())
        };
        for output in &snapshot.outputs {
            let parsed = parsed_by_hash.get(output.hash.as_slice()).ok_or_else(|| anyhow::anyhow!("missing scan transaction"))?;
            let index = usize::try_from(output.index).map_err(|_| anyhow::anyhow!("invalid output index"))?;
            let actual = parsed.outputs.get(index).ok_or_else(|| anyhow::anyhow!("scan output index out of range"))?;
            if Some(actual.locking_script.to_binary()) != expected_script { anyhow::bail!("scan output does not belong to key"); }
            if i64::try_from(actual.satoshis.ok_or_else(|| anyhow::anyhow!("missing output value"))?).ok() != Some(output.value)
                || !hex::encode(actual.locking_script.to_binary()).eq_ignore_ascii_case(&output.script_pubkey) {
                anyhow::bail!("scan output does not match raw transaction");
            }
            let coinbase = parsed.inputs.len() == 1 && parsed.inputs[0].source_output_index == u32::MAX
                && parsed.inputs[0].source_txid.as_deref().is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b == b'0'));
            if output.coinbase != coinbase { anyhow::bail!("scan output coinbase mismatch"); }
        }
    }
    let tx = tokio::time::timeout_at(deadline, async {
    let mut tx = pool.begin().await?;
    if source.account_id != account_id { anyhow::bail!("scan derivation source changed"); }
    let master: Option<MasterKeyRow> = sqlx::query_as("SELECT m.* FROM Accounts a JOIN MasterKeys m ON m.masterkey_id=a.default_masterkey_id WHERE a.account_id=?")
        .bind(account_id).fetch_optional(&mut *tx).await?;
    if !master.as_ref().is_some_and(|m| m.masterkey_id == source.master.masterkey_id &&
        m.parent_masterkey_id == source.master.parent_masterkey_id && m.derivation_type == source.master.derivation_type &&
        m.derivation_data == source.master.derivation_data && m.date_created == source.master.date_created && m.date_updated == source.master.date_updated) {
        anyhow::bail!("scan derivation source changed");
    }
    let current = sqlx::query_as::<_, KeyInstanceRow>("SELECT * FROM KeyInstances WHERE account_id=? ORDER BY keyinstance_id LIMIT 100001")
        .bind(account_id).fetch_all(&mut *tx).await?;
    if current.len() != expected_keys.len() || current.iter().zip(expected_keys).any(|(a,b)|
        a.keyinstance_id != b.keyinstance_id || a.account_id != b.account_id || a.masterkey_id != b.masterkey_id ||
        a.derivation_type != b.derivation_type || a.derivation_data != b.derivation_data || a.script_type != b.script_type ||
        a.flags != b.flags || a.description != b.description || a.date_created != b.date_created || a.date_updated != b.date_updated) {
        anyhow::bail!("account keys changed during scan");
    }
    let now = chrono::Utc::now().timestamp();
    let mut new_ids = Vec::new();
    if !discovered.is_empty() {
        let master: (i64,) = sqlx::query_as("SELECT default_masterkey_id FROM Accounts WHERE account_id=? AND default_masterkey_id IS NOT NULL")
            .bind(account_id).fetch_one(&mut *tx).await?;
        for (chain, index) in discovered {
            let data = serde_json::json!({"subpath":[chain,index]}).to_string().into_bytes();
            let inserted = sqlx::query("INSERT INTO KeyInstances (account_id,masterkey_id,derivation_type,derivation_data,script_type,flags,description,date_created,date_updated) VALUES (?,?,?,?,?,0,NULL,?,?)")
                .bind(account_id).bind(master.0).bind(derivation_type::BIP32).bind(data).bind(script_type::P2PKH).bind(now).bind(now).execute(&mut *tx).await?;
            new_ids.push(inserted.last_insert_rowid());
        }
    }
    #[cfg(test)]
    if let Some(barrier) = barrier {
        let _ = barrier.started.send(());
        let _ = barrier.resume.await;
    }
    let resolve = |key: SyncKeyRef| -> anyhow::Result<i64> {
        match key { SyncKeyRef::Existing(id) => Ok(id), SyncKeyRef::Discovered(index) => new_ids.get(index).copied().ok_or_else(|| anyhow::anyhow!("invalid discovered key")) }
    };
    for snapshot in snapshots {
        let id = resolve(snapshot.key_id)?;
        let incoming_outputs: HashSet<(&[u8], i64)> = snapshot.outputs.iter().map(|o| (o.hash.as_slice(),o.index)).collect();
        let stored_outputs: Vec<(Vec<u8>, i64, i32)> = sqlx::query_as("SELECT tx_hash,tx_index,flags FROM TransactionOutputs WHERE keyinstance_id=?")
            .bind(id).fetch_all(&mut *tx).await?;
        for (hash, index, flags) in stored_outputs {
            if flags & txo_flags::IS_SPENT == 0 && !incoming_outputs.contains(&(hash.as_slice(), index)) {
                anyhow::bail!("scan conflict: existing unspent output is missing");
            }
        }
        let incoming_history: HashSet<&[u8]> = snapshot.transactions.iter().map(|item| item.hash.as_slice()).collect();
        let stored_history: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT tx_hash FROM TransactionDeltas WHERE keyinstance_id=?")
            .bind(id).fetch_all(&mut *tx).await?;
        if stored_history.iter().any(|(hash,)| !incoming_history.contains(hash.as_slice())) {
            anyhow::bail!("scan conflict: existing history owner is missing");
        }
        for output in &snapshot.outputs {
            let old: Option<(i64,i64,i32,Option<String>)> = sqlx::query_as("SELECT keyinstance_id,value,flags,script_pubkey FROM TransactionOutputs WHERE tx_hash=? AND tx_index=?")
                .bind(&output.hash).bind(output.index).fetch_optional(&mut *tx).await?;
            if let Some((owner,value,flags,script)) = old {
                if owner != id || value != output.value || flags & txo_flags::IS_SPENT != 0 ||
                    script.as_deref().filter(|s| !s.is_empty()).is_some_and(|s| !s.eq_ignore_ascii_case(&output.script_pubkey)) {
                    anyhow::bail!("scan conflict: existing output differs or is spent");
                }
            }
        }
        for item in &snapshot.transactions {
            let old_raw: Option<(Option<Vec<u8>>,)> = sqlx::query_as("SELECT tx_data FROM Transactions WHERE tx_hash=?")
                .bind(&item.hash).fetch_optional(&mut *tx).await?;
            if old_raw.and_then(|row| row.0).filter(|raw| !raw.is_empty()).is_some_and(|raw| raw.as_slice() != item.raw.as_ref()) {
                anyhow::bail!("scan conflict: existing transaction bytes differ");
            }
            let old_delta: Option<(i64,i64)> = sqlx::query_as("SELECT value_delta,value_known FROM TransactionDeltas WHERE keyinstance_id=? AND tx_hash=?")
                .bind(id).bind(&item.hash).fetch_optional(&mut *tx).await?;
            if let Some((value, known)) = old_delta {
                if known != 0 && item.delta.is_some_and(|delta| delta != value) { anyhow::bail!("scan conflict: existing known delta differs"); }
            }
        }
    }
    for snapshot in snapshots {
        let id = resolve(snapshot.key_id)?;
        for item in &snapshot.transactions {
            let flags = if item.height.is_none() { tx_flags::IS_UNCONFIRMED } else { 0 };
            sqlx::query("INSERT INTO Transactions (tx_hash,tx_data,block_height,flags,date_created,date_updated) VALUES (?,?,?,?,?,?) ON CONFLICT(tx_hash) DO UPDATE SET tx_data=CASE WHEN Transactions.tx_data IS NULL OR length(Transactions.tx_data)=0 THEN excluded.tx_data ELSE Transactions.tx_data END")
                .bind(&item.hash).bind(item.raw.as_ref()).bind(item.height).bind(flags).bind(now).bind(now).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO TransactionDeltas (keyinstance_id,tx_hash,value_delta,date_created,date_updated,value_known) VALUES (?,?,?,?,?,?) ON CONFLICT(keyinstance_id,tx_hash) DO UPDATE SET value_delta=CASE WHEN TransactionDeltas.value_known=0 AND excluded.value_known=1 THEN excluded.value_delta ELSE TransactionDeltas.value_delta END,value_known=CASE WHEN TransactionDeltas.value_known=0 AND excluded.value_known=1 THEN 1 ELSE TransactionDeltas.value_known END")
                .bind(id).bind(&item.hash).bind(item.delta.unwrap_or(0)).bind(now).bind(now).bind(i32::from(item.delta.is_some())).execute(&mut *tx).await?;
        }
        for output in &snapshot.outputs {
            let flags = if output.coinbase { txo_flags::IS_COINBASE } else { 0 };
            sqlx::query("INSERT INTO TransactionOutputs (tx_hash,tx_index,value,keyinstance_id,flags,script_pubkey,date_created,date_updated) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(tx_hash,tx_index) DO UPDATE SET script_pubkey=CASE WHEN TransactionOutputs.script_pubkey IS NULL OR TransactionOutputs.script_pubkey='' THEN excluded.script_pubkey ELSE TransactionOutputs.script_pubkey END")
                .bind(&output.hash).bind(output.index).bind(output.value).bind(id).bind(flags).bind(&output.script_pubkey).bind(now).bind(now).execute(&mut *tx).await?;
        }
    }
    Ok::<_, anyhow::Error>(tx)
    }).await.map_err(|_| anyhow::anyhow!("scan deadline exceeded before commit"))??;
    if tokio::time::Instant::now() >= deadline { anyhow::bail!("scan deadline exceeded before commit"); }
    tx.commit().await?;
    Ok(())
}

/// Delete all TransactionOutputs and TransactionDeltas for a set of keyinstance_ids.
///
/// This is used during sync to clear stale data before re-populating from
/// the server's fresh UTXO list. Transactions themselves are not deleted
/// (they may be referenced by other keyinstances).
pub async fn clear_outputs_and_deltas_for_keyinstances(
    pool: &SqlitePool,
    keyinstance_ids: &[i64],
) -> anyhow::Result<()> {
    if keyinstance_ids.is_empty() {
        return Ok(());
    }

    let placeholders: Vec<String> = (0..keyinstance_ids.len())
        .map(|_| "?".to_string())
        .collect();
    let in_clause = placeholders.join(",");

    let del_outputs = format!(
        "DELETE FROM TransactionOutputs WHERE keyinstance_id IN ({})",
        in_clause
    );
    let mut q1 = sqlx::query(&del_outputs);
    for id in keyinstance_ids {
        q1 = q1.bind(id);
    }
    q1.execute(pool).await?;

    let placeholders2: Vec<String> = (0..keyinstance_ids.len())
        .map(|_| "?".to_string())
        .collect();
    let in_clause2 = placeholders2.join(",");

    let del_deltas = format!(
        "DELETE FROM TransactionDeltas WHERE keyinstance_id IN ({})",
        in_clause2
    );
    let mut q2 = sqlx::query(&del_deltas);
    for id in keyinstance_ids {
        q2 = q2.bind(id);
    }
    q2.execute(pool).await?;

    Ok(())
}

// ============================================================================
// TOTP Secret queries (Milestone 5)
// ============================================================================

/// Store a TOTP secret in the TotpSecrets table.
///
/// The secret should be AES-CBC encrypted with the wallet password before storing.
/// This function stores the raw (already-encrypted) bytes.
/// The TotpSecrets table has a single row (id=1 CHECK constraint).
pub async fn store_totp_secret(pool: &SqlitePool, secret_encrypted: &[u8]) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();

    // Upsert: if row exists, update; otherwise insert
    sqlx::query(
        "INSERT INTO TotpSecrets (id, secret_encrypted, nonce, scope, date_created, date_updated) \
         VALUES (1, ?, '', 'login', ?, ?) \
         ON CONFLICT(id) DO UPDATE SET secret_encrypted = excluded.secret_encrypted, date_updated = excluded.date_updated",
    )
    .bind(secret_encrypted)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Load the TOTP secret from the TotpSecrets table.
///
/// Returns None if no TOTP secret is stored (TOTP not enabled).
pub async fn load_totp_secret(pool: &SqlitePool) -> anyhow::Result<Option<Vec<u8>>> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT secret_encrypted FROM TotpSecrets WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(secret,)| secret))
}

/// Delete the TOTP secret (disable TOTP).
pub async fn delete_totp_secret(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM TotpSecrets WHERE id = 1")
        .execute(pool)
        .await?;
    Ok(())
}

/// Check if TOTP is enabled (a secret exists in the TotpSecrets table).
pub async fn is_totp_enabled(pool: &SqlitePool) -> anyhow::Result<bool> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM TotpSecrets WHERE id = 1")
        .fetch_one(pool)
        .await?;
    Ok(count.0 > 0)
}

// ============================================================================
// Hardware wallet enabled flag (Milestone 5)
// ============================================================================

/// WalletData key for hardware wallet enabled flag.
pub const HW_WALLET_ENABLED_KEY: &str = "hardware_wallet_enabled";

/// Get whether hardware wallet support is enabled in this wallet.
///
/// Default: false (disabled). Uses WalletData key-value store.
pub async fn get_hardware_wallet_enabled(pool: &SqlitePool) -> anyhow::Result<bool> {
    let value = get_wallet_data(pool, HW_WALLET_ENABLED_KEY).await?;
    Ok(value.map(|v| v == "true").unwrap_or(false))
}

/// Set the hardware wallet enabled flag.
pub async fn set_hardware_wallet_enabled(pool: &SqlitePool, enabled: bool) -> anyhow::Result<()> {
    set_wallet_data(
        pool,
        HW_WALLET_ENABLED_KEY,
        if enabled { "true" } else { "false" },
    )
    .await
}

// ============================================================================
// Contact queries (Milestone 6 — contacts, labels, payment requests, config)
// ============================================================================

/// Contact identity system_id constants (matches Python ContactIdentityType).
pub mod contact_identity_system {
    /// On-chain address identity.
    pub const ONCHAIN: i64 = 1;
    /// Paymail handle identity.
    pub const PAYMAIL: i64 = 2;
}

/// A Contacts row from the database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ContactRow {
    pub contact_id: i64,
    pub label: String,
    pub date_created: i64,
    pub date_updated: i64,
}

/// A ContactIdentities row from the database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ContactIdentityRow {
    pub identity_id: Vec<u8>,
    pub contact_id: i64,
    pub system_id: i64,
    pub system_data: String,
    pub last_verified: Option<i64>,
    pub date_created: i64,
    pub date_updated: i64,
}

/// Get all contacts ordered by contact_id.
pub async fn get_all_contacts(pool: &SqlitePool) -> anyhow::Result<Vec<ContactRow>> {
    let rows =
        sqlx::query_as::<_, ContactRow>("SELECT * FROM Contacts ORDER BY contact_id")
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// Get a single contact by ID.
pub async fn get_contact_by_id(
    pool: &SqlitePool,
    contact_id: i64,
) -> anyhow::Result<Option<ContactRow>> {
    let row =
        sqlx::query_as::<_, ContactRow>("SELECT * FROM Contacts WHERE contact_id = ?")
            .bind(contact_id)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// Insert a new contact and return its contact_id.
pub async fn insert_contact(pool: &SqlitePool, label: &str) -> anyhow::Result<i64> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO Contacts (label, date_created, date_updated) VALUES (?, ?, ?)",
    )
    .bind(label)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

/// Update a contact's label.
pub async fn update_contact_label(
    pool: &SqlitePool,
    contact_id: i64,
    label: &str,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE Contacts SET label = ?, date_updated = ? WHERE contact_id = ?")
        .bind(label)
        .bind(now)
        .bind(contact_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete a contact by ID (ContactIdentities cascade-deleted via FK).
pub async fn delete_contact(pool: &SqlitePool, contact_id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM Contacts WHERE contact_id = ?")
        .bind(contact_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get all identities for a contact.
pub async fn get_contact_identities(
    pool: &SqlitePool,
    contact_id: i64,
) -> anyhow::Result<Vec<ContactIdentityRow>> {
    let rows = sqlx::query_as::<_, ContactIdentityRow>(
        "SELECT * FROM ContactIdentities WHERE contact_id = ? ORDER BY date_created",
    )
    .bind(contact_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Insert a new contact identity with a random 16-byte identity_id.
pub async fn insert_contact_identity(
    pool: &SqlitePool,
    contact_id: i64,
    system_id: i64,
    system_data: &str,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    // Generate a random 16-byte identity_id
    let identity_id: [u8; 16] = rand::random();
    sqlx::query(
        "INSERT INTO ContactIdentities \
         (identity_id, contact_id, system_id, system_data, last_verified, date_created, date_updated) \
         VALUES (?, ?, ?, ?, NULL, ?, ?)",
    )
    .bind(&identity_id[..])
    .bind(contact_id)
    .bind(system_id)
    .bind(system_data)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Check if a label is already in use by any contact.
pub async fn check_label_in_use(pool: &SqlitePool, label: &str) -> anyhow::Result<bool> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM Contacts WHERE label = ?")
        .bind(label)
        .fetch_one(pool)
        .await?;
    Ok(count.0 > 0)
}

// ============================================================================
// Label queries (description column on KeyInstances and Transactions)
// ============================================================================

/// Set or clear the label (description) on a KeyInstance.
pub async fn set_keyinstance_label(
    pool: &SqlitePool,
    keyinstance_id: i64,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE KeyInstances SET description = ?, date_updated = ? WHERE keyinstance_id = ?")
        .bind(label)
        .bind(now)
        .bind(keyinstance_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Set or clear the label (description) on a Transaction.
pub async fn set_transaction_label(
    pool: &SqlitePool,
    tx_hash: &[u8],
    label: Option<&str>,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE Transactions SET description = ?, date_updated = ? WHERE tx_hash = ?")
        .bind(label)
        .bind(now)
        .bind(tx_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get the label (description) of a KeyInstance.
pub async fn get_keyinstance_label(
    pool: &SqlitePool,
    keyinstance_id: i64,
) -> anyhow::Result<Option<String>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT description FROM KeyInstances WHERE keyinstance_id = ?")
            .bind(keyinstance_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(v,)| v))
}

/// Get the label (description) of a Transaction.
pub async fn get_transaction_label(
    pool: &SqlitePool,
    tx_hash: &[u8],
) -> anyhow::Result<Option<String>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT description FROM Transactions WHERE tx_hash = ?")
            .bind(tx_hash)
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(v,)| v))
}

/// Get all KeyInstance labels (where description IS NOT NULL).
///
/// Returns `(keyinstance_id, description, date_updated)` for every KeyInstance
/// that has a non-NULL description.  The caller is responsible for deriving
/// the address from the keyinstance's derivation data (which requires the
/// xprv); when the xprv is not unlocked, the keyinstance_id can be used as a
/// placeholder identifier.
pub async fn get_all_key_labels(
    pool: &SqlitePool,
) -> anyhow::Result<Vec<(i64, String, i64)>> {
    let rows: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT keyinstance_id, description, date_updated \
         FROM KeyInstances WHERE description IS NOT NULL ORDER BY keyinstance_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Get all Transaction labels (where description IS NOT NULL).
///
/// Returns `(tx_hash_hex, description, date_updated)` where `tx_hash_hex` is
/// the **display** hex (reversed byte order) of the internal `tx_hash` BLOB.
pub async fn get_all_tx_labels(
    pool: &SqlitePool,
) -> anyhow::Result<Vec<(String, String, i64)>> {
    // tx_hash is stored as a BLOB in internal byte order; reverse to get the
    // display hex txid (same pattern as the `set_tx_label` command).
    let rows: Vec<(Vec<u8>, String, i64)> = sqlx::query_as(
        "SELECT tx_hash, description, date_updated \
         FROM Transactions WHERE description IS NOT NULL ORDER BY date_updated",
    )
    .fetch_all(pool)
    .await?;

    let result = rows
        .into_iter()
        .map(|(mut hash, label, updated)| {
            hash.reverse();
            (hex::encode(&hash), label, updated)
        })
        .collect();
    Ok(result)
}

// ============================================================================
// Payment request queries (PaymentRequests table from migration 0022)
// ============================================================================

/// A PaymentRequests row from the database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct PaymentRequestRow {
    pub paymentrequest_id: i64,
    pub keyinstance_id: i64,
    pub state: i32,
    pub description: Option<String>,
    pub expiration: Option<i64>,
    pub value: Option<i64>,
    pub date_created: i64,
    pub date_updated: i64,
}

/// Insert a new payment request and return its paymentrequest_id.
///
/// `state` defaults to 0 (pending). `expiration` is None (no expiry).
pub async fn insert_payment_request(
    pool: &SqlitePool,
    keyinstance_id: i64,
    value: Option<i64>,
    description: Option<&str>,
) -> anyhow::Result<i64> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO PaymentRequests \
         (keyinstance_id, state, description, expiration, value, date_created, date_updated) \
         VALUES (?, 0, ?, NULL, ?, ?, ?)",
    )
    .bind(keyinstance_id)
    .bind(description)
    .bind(value)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

/// Get all payment requests ordered by paymentrequest_id.
pub async fn get_payment_requests(pool: &SqlitePool) -> anyhow::Result<Vec<PaymentRequestRow>> {
    let rows = sqlx::query_as::<_, PaymentRequestRow>(
        "SELECT * FROM PaymentRequests ORDER BY paymentrequest_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ============================================================================
// Config queries (WalletData key-value store aliases)
// ============================================================================

/// Read all WalletData rows and return them as a JSON object.
pub async fn get_all_config(pool: &SqlitePool) -> anyhow::Result<serde_json::Value> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM WalletData ORDER BY key")
            .fetch_all(pool)
            .await?;
    let mut map = serde_json::Map::new();
    for (key, value) in rows {
        map.insert(key, serde_json::Value::String(value));
    }
    Ok(serde_json::Value::Object(map))
}

/// Get a config value by key (alias for get_wallet_data).
pub async fn get_config_value(pool: &SqlitePool, key: &str) -> anyhow::Result<Option<String>> {
    get_wallet_data(pool, key).await
}

/// Set a config value by key (alias for set_wallet_data).
pub async fn set_config_value(pool: &SqlitePool, key: &str, value: &str) -> anyhow::Result<()> {
    set_wallet_data(pool, key, value).await
}

// ============================================================================
// Account queries (for get_accounts command)
// ============================================================================

/// Get all accounts ordered by account_id.
pub async fn get_all_accounts(pool: &SqlitePool) -> anyhow::Result<Vec<AccountRow>> {
    let rows =
        sqlx::query_as::<_, AccountRow>("SELECT * FROM Accounts ORDER BY account_id")
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// Get a single account by ID.
pub async fn get_account_by_id(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<Option<AccountRow>> {
    let row =
        sqlx::query_as::<_, AccountRow>("SELECT * FROM Accounts WHERE account_id = ?")
            .bind(account_id)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

// ============================================================================
// Multisig configuration (Task 5 — Multisig account type)
// ============================================================================

/// A MultisigConfigs row from the database.
///
/// `public_keys` is deserialised from the stored JSON array of hex-encoded
/// public keys into a `Vec<String>` for convenience.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct MultisigConfigRow {
    pub account_id: i64,
    pub threshold: i64,
    /// Hex-encoded public keys (deserialised from the JSON array in DB).
    pub public_keys: Vec<String>,
    pub date_created: i64,
    pub date_updated: i64,
}

/// Insert a multisig configuration row for an account.
///
/// `public_keys_json` is a JSON array of hex-encoded public keys, e.g.
/// `["02ab...", "03cd..."]`. The caller is responsible for serialising the
/// array; this function stores it verbatim.
pub async fn insert_multisig_config(
    pool: &SqlitePool,
    account_id: i64,
    threshold: i64,
    public_keys_json: &str,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO MultisigConfigs (account_id, threshold, public_keys, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(account_id)
    .bind(threshold)
    .bind(public_keys_json)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Get the multisig configuration for an account.
///
/// Returns `None` if the account has no multisig config (i.e. is not a
/// multisig account). The `public_keys` JSON array in the DB is decoded
/// into a `Vec<String>` of hex strings.
pub async fn get_multisig_config(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<Option<MultisigConfigRow>> {
    // Fetch the raw row with public_keys as TEXT, then decode JSON.
    let row: Option<(i64, i64, String, i64, i64)> = sqlx::query_as(
        "SELECT account_id, threshold, public_keys, date_created, date_updated \
         FROM MultisigConfigs WHERE account_id = ?",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((account_id, threshold, public_keys_json, date_created, date_updated)) => {
            let public_keys: Vec<String> = serde_json::from_str(&public_keys_json)?;
            Ok(Some(MultisigConfigRow {
                account_id,
                threshold,
                public_keys,
                date_created,
                date_updated,
            }))
        }
        None => Ok(None),
    }
}

// ============================================================================
// TOTP Recovery codes (Milestone 8-C)
// ============================================================================

/// WalletData key for TOTP recovery codes (stored as JSON array of SHA256 hashes).
pub const TOTP_RECOVERY_CODES_KEY: &str = "totp_recovery_codes";

/// Store hashed recovery codes in WalletData.
///
/// Each code should already be SHA256-hashed by the caller. The hashes are
/// stored as a JSON array string under the `totp_recovery_codes` key.
pub async fn store_recovery_codes(pool: &SqlitePool, hashed_codes: &[String]) -> anyhow::Result<()> {
    let json = serde_json::to_string(hashed_codes)?;
    set_wallet_data(pool, TOTP_RECOVERY_CODES_KEY, &json).await
}

/// Load the hashed recovery codes from WalletData.
///
/// Returns an empty vector if no recovery codes are stored.
pub async fn load_recovery_codes(pool: &SqlitePool) -> anyhow::Result<Vec<String>> {
    let value = get_wallet_data(pool, TOTP_RECOVERY_CODES_KEY).await?;
    match value {
        Some(json) => {
            let codes: Vec<String> = serde_json::from_str(&json)?;
            Ok(codes)
        }
        None => Ok(Vec::new()),
    }
}

/// Delete all recovery codes from WalletData.
pub async fn delete_recovery_codes(pool: &SqlitePool) -> anyhow::Result<()> {
    set_wallet_data(pool, TOTP_RECOVERY_CODES_KEY, "[]").await
}

/// Consume a recovery code: check if the given plaintext code matches any
/// stored hash (SHA256 compare). If matched, remove that hash from the list
/// and return true. If none match, return false.
pub async fn consume_recovery_code(pool: &SqlitePool, code_hash: &str) -> anyhow::Result<bool> {
    let mut codes = load_recovery_codes(pool).await?;
    if codes.is_empty() {
        return Ok(false);
    }

    let position = codes.iter().position(|h| h == code_hash);
    match position {
        Some(idx) => {
            codes.remove(idx);
            store_recovery_codes(pool, &codes).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

pub async fn recover_totp_atomically(pool: &SqlitePool, code_hash: &str) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;
    if !recover_totp_in_transaction(&mut tx, code_hash).await? { return Ok(false); }
    tx.commit().await?;
    Ok(true)
}

pub(crate) async fn recover_totp_in_transaction(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, code_hash: &str) -> anyhow::Result<bool> {
    let stored: Option<(String,)> = sqlx::query_as("SELECT value FROM WalletData WHERE key = ?").bind(TOTP_RECOVERY_CODES_KEY).fetch_optional(&mut **tx).await?;
    let Some((json,)) = stored else { return Ok(false); };
    let codes: Vec<String> = serde_json::from_str(&json)?;
    if !codes.iter().any(|code| code == code_hash) { return Ok(false); }
    let updated = sqlx::query("UPDATE WalletData SET value = '[]', date_updated = ? WHERE key = ? AND value = ?")
        .bind(chrono::Utc::now().timestamp()).bind(TOTP_RECOVERY_CODES_KEY).bind(json).execute(&mut **tx).await?;
    if updated.rows_affected() != 1 { return Ok(false); }
    let deleted = sqlx::query("DELETE FROM TotpSecrets WHERE id = 1").execute(&mut **tx).await?;
    if deleted.rows_affected() != 1 { return Ok(false); }
    Ok(true)
}

// ============================================================================
// Extra repository functions for ported features
// ============================================================================

/// Get an account-owned transaction by display txid.
pub async fn get_transaction_by_txid(pool: &SqlitePool, account_id: i64, txid: &str) -> anyhow::Result<Option<TransactionRow>> {
    let hash = crate::core::address::hex_str_to_hash(txid)?;
    if hash.len() != 32 { anyhow::bail!("invalid transaction hash length"); }
    Ok(sqlx::query_as::<_, TransactionRow>(
        "SELECT t.tx_data, t.block_height, t.fee_value, t.description FROM Transactions t JOIN AccountTransactions a ON a.tx_hash = t.tx_hash WHERE t.tx_hash = ? AND a.account_id = ?")
        .bind(hash).bind(account_id).fetch_optional(pool).await?)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TransactionRow {
    pub tx_data: Option<Vec<u8>>,
    pub block_height: Option<i64>,
    pub fee_value: Option<i64>,
    pub description: Option<String>,
}

/// Query wallet-owned current outputs; this is not a full transaction detail.
pub async fn get_transaction_outputs(pool: &SqlitePool, txid: &str) -> anyhow::Result<Vec<TxOutputDetailRow>> {
    let hash = crate::core::address::hex_str_to_hash(txid)?;
    if hash.len() != 32 { anyhow::bail!("invalid transaction hash length"); }
    Ok(sqlx::query_as::<_, TxOutputDetailRow>("SELECT value, COALESCE(script_pubkey, '') AS script_pubkey FROM TransactionOutputs WHERE tx_hash = ? ORDER BY tx_index")
        .bind(hash).fetch_all(pool).await?)
}
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TxOutputDetailRow { pub value: i64, pub script_pubkey: String }

/// Count remaining (unused) TOTP recovery codes.
pub async fn count_remaining_recovery_codes(pool: &SqlitePool) -> anyhow::Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM TotpRecoveryCodes WHERE used = 0",
    )
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::connection;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn scan_test_master_record() -> Vec<u8> {
        let key = bsv::compat::bip32::ExtendedKey::from_seed(&[7;64]).unwrap();
        serde_json::json!({"xpub":key.to_public().unwrap().to_base58()}).to_string().into_bytes()
    }

    fn scan_test_script(chain: u32, index: u32) -> String {
        use bsv::script::templates::{p2pkh::P2PKH,ScriptTemplateLock};
        let key = bsv::compat::bip32::ExtendedKey::from_seed(&[7;64]).unwrap();
        let public = key.derive(&format!("{chain}/{index}")).unwrap().public_key().unwrap();
        let address = crate::core::address::pubkey_to_p2pkh_address(&public);
        hex::encode(P2PKH::from_address(&address).unwrap().lock().unwrap().to_binary())
    }

    async fn sync_db_snapshot(pool: &SqlitePool) -> Vec<Vec<String>> {
        let queries = [
            "SELECT quote(keyinstance_id)||','||quote(account_id)||','||quote(masterkey_id)||','||quote(derivation_type)||','||quote(derivation_data)||','||quote(script_type)||','||quote(flags)||','||quote(description)||','||quote(date_created)||','||quote(date_updated) FROM KeyInstances ORDER BY keyinstance_id",
            "SELECT quote(key)||','||quote(value)||','||quote(date_created)||','||quote(date_updated) FROM WalletData ORDER BY key",
            "SELECT quote(tx_hash)||','||quote(tx_data)||','||quote(proof_data)||','||quote(block_height)||','||quote(block_position)||','||quote(fee_value)||','||quote(flags)||','||quote(description)||','||quote(date_created)||','||quote(date_updated) FROM Transactions ORDER BY tx_hash",
            "SELECT quote(tx_hash)||','||quote(tx_index)||','||quote(value)||','||quote(keyinstance_id)||','||quote(flags)||','||quote(script_pubkey)||','||quote(date_created)||','||quote(date_updated) FROM TransactionOutputs ORDER BY tx_hash,tx_index",
            "SELECT quote(keyinstance_id)||','||quote(tx_hash)||','||quote(value_delta)||','||quote(value_known)||','||quote(date_created)||','||quote(date_updated) FROM TransactionDeltas ORDER BY keyinstance_id,tx_hash",
                "SELECT quote(account_id)||','||quote(default_masterkey_id)||','||quote(default_script_type)||','||quote(account_name)||','||quote(date_created)||','||quote(date_updated) FROM Accounts ORDER BY account_id",
                "SELECT quote(masterkey_id)||','||quote(parent_masterkey_id)||','||quote(derivation_type)||','||quote(derivation_data)||','||quote(date_created)||','||quote(date_updated) FROM MasterKeys ORDER BY masterkey_id",
        ];
        let mut all = Vec::new();
        for query in queries {
            let rows: Vec<(String,)> = sqlx::query_as(query).fetch_all(pool).await.unwrap();
            all.push(rows.into_iter().map(|row| row.0).collect());
        }
        all
    }

    async fn explicit_scan_fixture() -> (SqlitePool, i64, Vec<KeyInstanceRow>, Vec<u8>, Vec<u8>) {
        use bsv::script::locking_script::LockingScript;
        use bsv::transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput};
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        for migration in [include_str!("../../migrations/0022_create_database.sql"), include_str!("../../migrations/0031_txo_script_pubkey.sql"), include_str!("../../migrations/0032_transaction_delta_known.sql")] {
            sqlx::query(migration).execute(&pool).await.unwrap();
        }
        let master = insert_master_key(&pool, None, derivation_type::BIP32, &scan_test_master_record()).await.unwrap();
        let account = insert_account(&pool, Some(master), script_type::P2PKH, "synthetic").await.unwrap();
        sqlx::query("INSERT INTO KeyInstances (keyinstance_id,account_id,masterkey_id,derivation_type,derivation_data,script_type,flags,date_created,date_updated) VALUES (-1,?,?,?,?,?,0,1,1)")
            .bind(account).bind(master).bind(derivation_type::BIP32).bind(br#"{"subpath":[0,0]}"#.as_slice()).bind(script_type::P2PKH).execute(&pool).await.unwrap();
        let mut tx = Transaction::new();
        tx.inputs.push(TransactionInput { source_txid: Some("00".repeat(32)), source_output_index: u32::MAX, ..Default::default() });
        let script = scan_test_script(0,0);
        tx.outputs.push(TransactionOutput { satoshis: Some(50), locking_script: LockingScript::from_binary(&hex::decode(&script).unwrap()), change: false });
        let hash = crate::core::address::hex_str_to_hash(&tx.id().unwrap()).unwrap();
        let raw = hex::decode(tx.to_hex().unwrap()).unwrap();
        upsert_transaction(&pool, &hash, Some(9), Some(&raw)).await.unwrap();
        upsert_transaction_output(&pool, &hash, 0, 50, -1, txo_flags::IS_COINBASE, Some(&script)).await.unwrap();
        upsert_transaction_delta(&pool, -1, &hash, 50).await.unwrap();
        sqlx::query("UPDATE Transactions SET description='keep', proof_data=x'0102', flags=7 WHERE tx_hash=?").bind(&hash).execute(&pool).await.unwrap();
        let keys = get_keyinstances_for_account(&pool, account).await.unwrap();
        (pool, account, keys, hash, raw)
    }

    #[tokio::test]
    async fn explicit_scan_rejects_changed_account_or_master_for_empty_account() {
        for case in ["account", "master"] {
            let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
            for migration in [include_str!("../../migrations/0022_create_database.sql"), include_str!("../../migrations/0031_txo_script_pubkey.sql"), include_str!("../../migrations/0032_transaction_delta_known.sql")] {
                sqlx::query(migration).execute(&pool).await.unwrap();
            }
            let first = insert_master_key(&pool,None,derivation_type::BIP32,&scan_test_master_record()).await.unwrap();
            let second = insert_master_key(&pool,None,derivation_type::BIP32,b"second").await.unwrap();
            let account = insert_account(&pool,Some(first),script_type::P2PKH,"synthetic").await.unwrap();
            let source = load_scan_derivation_source(&pool,account).await.unwrap();
            if case == "account" { sqlx::query("UPDATE Accounts SET default_masterkey_id=? WHERE account_id=?").bind(second).bind(account).execute(&pool).await.unwrap(); }
            else { sqlx::query("UPDATE MasterKeys SET derivation_data=? WHERE masterkey_id=?").bind(b"changed".as_slice()).bind(first).execute(&pool).await.unwrap(); }
            let before = sync_db_snapshot(&pool).await;
            let snapshots = [SyncKeySnapshot { key_id:SyncKeyRef::Discovered(0), transactions:vec![], outputs:vec![] }];
            let error = merge_explicit_scan_snapshot(&pool,account,&[],&source,&[(1,25)],&snapshots,26,tokio::time::Instant::now()+std::time::Duration::from_secs(5)).await.unwrap_err();
            assert!(error.to_string().contains("derivation source changed"));
            assert_eq!(sync_db_snapshot(&pool).await,before);
            pool.close().await;
        }
    }

    fn explicit_scan_snapshot(hash: &[u8], raw: &[u8], delta: Option<i64>, output: bool) -> Vec<SyncKeySnapshot> {
        vec![SyncKeySnapshot { key_id: SyncKeyRef::Existing(-1),
            transactions: vec![SyncTransaction { hash: hash.to_vec(), height: Some(123), raw: raw.to_vec().into(), delta }],
            outputs: if output { vec![SyncOutput { hash: hash.to_vec(), height: Some(123), index: 0, value: 50, coinbase: true, script_pubkey: scan_test_script(0,0) }] } else { vec![] },
        }]
    }

    #[tokio::test]
    async fn explicit_scan_rejects_unsupported_inventory_and_paths_without_writes() {
        for case in ["missing_master","foreign_master","script_type","derivation_type","branch","hardened","extra_path","duplicate_existing","duplicate_discovered","duplicate_discovered_pair","invalid_discovered_branch","discovered_at_end"] {
            let (pool, account, _keys, _hash, _raw) = explicit_scan_fixture().await;
            let source = load_scan_derivation_source(&pool,account).await.unwrap();
            match case {
                "missing_master" => { sqlx::query("UPDATE KeyInstances SET masterkey_id=NULL WHERE keyinstance_id=-1").execute(&pool).await.unwrap(); }
                "foreign_master" => { let other = insert_master_key(&pool,None,derivation_type::BIP32,&scan_test_master_record()).await.unwrap(); sqlx::query("UPDATE KeyInstances SET masterkey_id=? WHERE keyinstance_id=-1").bind(other).execute(&pool).await.unwrap(); }
                "script_type" => { sqlx::query("UPDATE KeyInstances SET script_type=999 WHERE keyinstance_id=-1").execute(&pool).await.unwrap(); }
                "derivation_type" => { sqlx::query("UPDATE KeyInstances SET derivation_type=999 WHERE keyinstance_id=-1").execute(&pool).await.unwrap(); }
                "branch" => { sqlx::query("UPDATE KeyInstances SET derivation_data=? WHERE keyinstance_id=-1").bind(br#"{"subpath":[2,0]}"#.as_slice()).execute(&pool).await.unwrap(); }
                "hardened" => { sqlx::query("UPDATE KeyInstances SET derivation_data=? WHERE keyinstance_id=-1").bind(br#"{"subpath":[0,2147483648]}"#.as_slice()).execute(&pool).await.unwrap(); }
                "extra_path" => { sqlx::query("UPDATE KeyInstances SET derivation_data=? WHERE keyinstance_id=-1").bind(br#"{"subpath":[0,0],"extra":1}"#.as_slice()).execute(&pool).await.unwrap(); }
                "duplicate_existing" => { insert_keyinstance(&pool,account,Some(source.master.masterkey_id),derivation_type::BIP32,br#"{"subpath":[0,0]}"#,script_type::P2PKH,0,None).await.unwrap(); }
                _ => {}
            }
            let keys = get_keyinstances_for_account(&pool,account).await.unwrap();
            let mut snapshots = keys.iter().map(|key| SyncKeySnapshot { key_id:SyncKeyRef::Existing(key.keyinstance_id), transactions:vec![], outputs:vec![] }).collect::<Vec<_>>();
            let discovered = match case { "duplicate_discovered" => vec![(0,0)], "duplicate_discovered_pair" => vec![(1,25),(1,25)], "invalid_discovered_branch" => vec![(2,0)], "discovered_at_end" => vec![(0,26)], _ => vec![] };
            for index in 0..discovered.len() { snapshots.push(SyncKeySnapshot { key_id:SyncKeyRef::Discovered(index), transactions:vec![], outputs:vec![] }); }
            let before = sync_db_snapshot(&pool).await;
            let error = merge_explicit_scan_snapshot(&pool,account,&keys,&source,&discovered,&snapshots,26,tokio::time::Instant::now()+std::time::Duration::from_secs(5)).await.unwrap_err();
            assert!(error.to_string().contains("unsupported"), "{case}: {error}");
            assert_eq!(sync_db_snapshot(&pool).await,before,"{case}");
            pool.close().await;
        }
    }

    #[tokio::test]
    async fn explicit_scan_rejects_valid_foreign_script_for_existing_and_discovered() {
        use bsv::script::locking_script::LockingScript;
        for discovered in [false,true] {
            let (pool,account,keys,hash,raw) = explicit_scan_fixture().await;
            let source = load_scan_derivation_source(&pool,account).await.unwrap();
            let mut foreign = bsv::transaction::transaction::Transaction::from_hex(&hex::encode(&raw)).unwrap();
            foreign.outputs[0].locking_script = LockingScript::from_binary(&hex::decode(scan_test_script(0,2)).unwrap());
            let foreign_hash = crate::core::address::hex_str_to_hash(&foreign.id().unwrap()).unwrap();
            let foreign_raw = hex::decode(foreign.to_hex().unwrap()).unwrap();
            let foreign_snapshot = SyncKeySnapshot { key_id:if discovered { SyncKeyRef::Discovered(0) } else { SyncKeyRef::Existing(-1) },
                transactions:vec![SyncTransaction { hash:foreign_hash.clone(), height:Some(1), raw:foreign_raw.into(), delta:Some(50) }],
                outputs:vec![SyncOutput { hash:foreign_hash, height:Some(1), index:0, value:50, coinbase:true, script_pubkey:scan_test_script(0,2) }],
            };
            let mut snapshots = if discovered { explicit_scan_snapshot(&hash,&raw,Some(50),true) } else { vec![] };
            snapshots.push(foreign_snapshot);
            let paths = if discovered { vec![(1,25)] } else { vec![] };
            let before = sync_db_snapshot(&pool).await;
            let error = merge_explicit_scan_snapshot(&pool,account,&keys,&source,&paths,&snapshots,26,tokio::time::Instant::now()+std::time::Duration::from_secs(5)).await.unwrap_err();
            assert!(error.to_string().contains("does not belong to key"));
            assert_eq!(sync_db_snapshot(&pool).await,before);
            pool.close().await;
        }
    }

    #[tokio::test]
    async fn explicit_scan_conflicts_leave_all_tables_unchanged() {
        for case in ["missing_unspent", "revive_spent", "wrong_value", "wrong_script", "wrong_raw", "missing_history", "wrong_delta", "cross_owner", "stale_key", "deadline"] {
            let (pool, account, keys, hash, raw) = explicit_scan_fixture().await;
            let source = load_scan_derivation_source(&pool, account).await.unwrap();
            if case == "revive_spent" || case == "missing_history" {
                sqlx::query("UPDATE TransactionOutputs SET flags=flags|? WHERE tx_hash=?").bind(txo_flags::IS_SPENT).bind(&hash).execute(&pool).await.unwrap();
            }
            if case == "wrong_value" { sqlx::query("UPDATE TransactionOutputs SET value=49 WHERE tx_hash=?").bind(&hash).execute(&pool).await.unwrap(); }
            if case == "wrong_script" { sqlx::query("UPDATE TransactionOutputs SET script_pubkey='52' WHERE tx_hash=?").bind(&hash).execute(&pool).await.unwrap(); }
            if case == "wrong_raw" { sqlx::query("UPDATE Transactions SET tx_data=x'01' WHERE tx_hash=?").bind(&hash).execute(&pool).await.unwrap(); }
            if case == "stale_key" { sqlx::query("UPDATE KeyInstances SET flags=1 WHERE keyinstance_id=-1").execute(&pool).await.unwrap(); }
            if case == "cross_owner" {
                let master: (i64,) = sqlx::query_as("SELECT default_masterkey_id FROM Accounts WHERE account_id=?").bind(account).fetch_one(&pool).await.unwrap();
                let other = insert_account(&pool, Some(master.0), script_type::P2PKH, "other").await.unwrap();
                let other_key = insert_keyinstance(&pool, other, Some(master.0), derivation_type::BIP32, br#"{"subpath":[0,3]}"#, script_type::P2PKH, 0, None).await.unwrap();
                sqlx::query("UPDATE TransactionOutputs SET keyinstance_id=? WHERE tx_hash=?").bind(other_key).bind(&hash).execute(&pool).await.unwrap();
            }
            let mut snapshots = explicit_scan_snapshot(&hash, &raw, if case == "wrong_delta" { Some(51) } else { Some(50) }, case != "missing_unspent" && case != "missing_history");
            if case == "missing_history" { snapshots[0].transactions.clear(); }
            let before = sync_db_snapshot(&pool).await;
            let deadline = if case == "deadline" { tokio::time::Instant::now() } else { tokio::time::Instant::now() + std::time::Duration::from_secs(5) };
            let result = merge_explicit_scan_snapshot(&pool, account, &keys, &source, &[], &snapshots, 26, deadline).await;
            assert!(result.is_err(), "{case}");
            assert_eq!(sync_db_snapshot(&pool).await, before, "{case}");
            pool.close().await;
        }
    }

    #[tokio::test]
    async fn explicit_scan_preserves_spent_marker_status_and_enriches_only_missing_data() {
        for marker in [false,true] {
            let (pool, account, keys, hash, raw) = explicit_scan_fixture().await;
            let source = load_scan_derivation_source(&pool, account).await.unwrap();
            if marker { sqlx::query("INSERT INTO WalletData(key,value,date_created,date_updated) VALUES (?,?,1,1)").bind(format!("address_discovery_v1_{account}")).bind("done").execute(&pool).await.unwrap(); }
            sqlx::query("UPDATE Transactions SET tx_data=NULL WHERE tx_hash=?").bind(&hash).execute(&pool).await.unwrap();
            sqlx::query("UPDATE TransactionOutputs SET script_pubkey=NULL WHERE tx_hash=?").bind(&hash).execute(&pool).await.unwrap();
            sqlx::query("UPDATE TransactionDeltas SET value_known=0,value_delta=0 WHERE tx_hash=?").bind(&hash).execute(&pool).await.unwrap();
            let snapshots = explicit_scan_snapshot(&hash, &raw, Some(50), true);
            merge_explicit_scan_snapshot(&pool, account, &keys, &source, &[], &snapshots, 26, tokio::time::Instant::now()+std::time::Duration::from_secs(5)).await.unwrap();
            let stored: (Vec<u8>,Option<i64>,i32,Option<String>,Option<Vec<u8>>) = sqlx::query_as("SELECT tx_data,block_height,flags,description,proof_data FROM Transactions WHERE tx_hash=?").bind(&hash).fetch_one(&pool).await.unwrap();
            assert_eq!(stored, (raw.clone(),Some(9),7,Some("keep".into()),Some(vec![1,2])));
            let output: (Option<String>,) = sqlx::query_as("SELECT script_pubkey FROM TransactionOutputs WHERE tx_hash=?").bind(&hash).fetch_one(&pool).await.unwrap();
            assert_eq!(output.0.as_deref(), Some(scan_test_script(0,0).as_str()));
            let delta: (i64,i64) = sqlx::query_as("SELECT value_delta,value_known FROM TransactionDeltas WHERE tx_hash=?").bind(&hash).fetch_one(&pool).await.unwrap();
            assert_eq!(delta,(50,1));
            assert_eq!(get_wallet_data(&pool, &format!("address_discovery_v1_{account}")).await.unwrap().as_deref(), marker.then_some("done"));
            let before = sync_db_snapshot(&pool).await;
            let unknown = explicit_scan_snapshot(&hash, &raw, None, true);
            merge_explicit_scan_snapshot(&pool, account, &keys, &source, &[], &unknown, 26, tokio::time::Instant::now()+std::time::Duration::from_secs(5)).await.unwrap();
            assert_eq!(sync_db_snapshot(&pool).await, before);
            sqlx::query("UPDATE TransactionOutputs SET flags=flags|? WHERE tx_hash=?").bind(txo_flags::IS_SPENT).bind(&hash).execute(&pool).await.unwrap();
            let before = sync_db_snapshot(&pool).await;
            let missing_spent = explicit_scan_snapshot(&hash, &raw, Some(50), false);
            merge_explicit_scan_snapshot(&pool, account, &keys, &source, &[], &missing_spent, 26, tokio::time::Instant::now()+std::time::Duration::from_secs(5)).await.unwrap();
            assert_eq!(sync_db_snapshot(&pool).await, before);
            pool.close().await;
        }
    }

    #[tokio::test]
    async fn explicit_scan_rolls_back_inserted_key_on_sql_failure_and_cancel() {
        use std::{future::Future, task::Poll};
        let (pool, account, keys, hash, raw) = explicit_scan_fixture().await;
            let source = load_scan_derivation_source(&pool, account).await.unwrap();
        let mut snapshots = explicit_scan_snapshot(&hash, &raw, Some(50), true);
        snapshots.push(SyncKeySnapshot { key_id: SyncKeyRef::Discovered(0), transactions: vec![], outputs: vec![] });
        let before = sync_db_snapshot(&pool).await;
        sqlx::query("CREATE TRIGGER fail_scan BEFORE INSERT ON TransactionOutputs BEGIN SELECT RAISE(ABORT, 'synthetic scan failure'); END").execute(&pool).await.unwrap();
        let error = merge_explicit_scan_snapshot(&pool, account, &keys, &source, &[(1,25)], &snapshots, 26, tokio::time::Instant::now()+std::time::Duration::from_secs(5)).await.unwrap_err();
        assert!(format!("{error:#}").contains("synthetic scan failure"));
        assert_eq!(sync_db_snapshot(&pool).await, before);
        sqlx::query("DROP TRIGGER fail_scan").execute(&pool).await.unwrap();
        let hold = pool.begin().await.unwrap();
        let mut pending = Box::pin(merge_explicit_scan_snapshot(&pool, account, &keys, &source, &[(1,25)], &snapshots, 26, tokio::time::Instant::now()+std::time::Duration::from_secs(5)));
        assert!(std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx).is_pending())).await);
        drop(pending);
        hold.rollback().await.unwrap();
        assert_eq!(sync_db_snapshot(&pool).await, before);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let timeout_pool = pool.clone();
        let timeout_keys = keys.clone();
        let timeout_source = source.clone();
        let timeout_snapshots = explicit_scan_snapshot(&hash, &raw, Some(50), true);
        let mut timeout_snapshots = timeout_snapshots;
        timeout_snapshots.push(SyncKeySnapshot { key_id: SyncKeyRef::Discovered(0), transactions: vec![], outputs: vec![] });
        let timeout_task = tokio::spawn(async move {
            merge_explicit_scan_impl(&timeout_pool, account, &timeout_keys, &timeout_source, &[(1,25)], &timeout_snapshots,
                26, tokio::time::Instant::now()+std::time::Duration::from_millis(100),
                Some(ScanTestBarrier { started: started_tx, resume: resume_rx })).await
        });
        started_rx.await.unwrap();
        let error = timeout_task.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("deadline"));
        drop(resume_tx);
        assert_eq!(sync_db_snapshot(&pool).await, before);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let task_pool = pool.clone();
        let task = tokio::spawn(async move {
            merge_explicit_scan_impl(&task_pool, account, &keys, &source, &[(1,25)], &snapshots,
                26, tokio::time::Instant::now()+std::time::Duration::from_secs(5),
                Some(ScanTestBarrier { started: started_tx, resume: resume_rx })).await
        });
        started_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        drop(resume_tx);
        assert_eq!(sync_db_snapshot(&pool).await, before);
        pool.close().await;
    }

    #[tokio::test]
    async fn explicit_scan_adds_discovered_key_without_touching_marker() {
        for marker in [false, true] {
            let (pool, account, keys, hash, raw) = explicit_scan_fixture().await;
            let source = load_scan_derivation_source(&pool, account).await.unwrap();
            if marker { sqlx::query("INSERT INTO WalletData(key,value,date_created,date_updated) VALUES (?,?,1,1)").bind(format!("address_discovery_v1_{account}")).bind("done").execute(&pool).await.unwrap(); }
            let mut discovered_tx = bsv::transaction::transaction::Transaction::from_hex(&hex::encode(&raw)).unwrap();
            discovered_tx.outputs[0].satoshis = Some(60);
            discovered_tx.outputs[0].locking_script = bsv::script::locking_script::LockingScript::from_binary(&hex::decode(scan_test_script(1,25)).unwrap());
            let new_hash = crate::core::address::hex_str_to_hash(&discovered_tx.id().unwrap()).unwrap();
            let new_raw = hex::decode(discovered_tx.to_hex().unwrap()).unwrap();
            let mut snapshots = explicit_scan_snapshot(&hash, &raw, Some(50), true);
            snapshots.push(SyncKeySnapshot { key_id: SyncKeyRef::Discovered(0),
                transactions: vec![SyncTransaction { hash: new_hash.clone(), height: Some(11), raw: new_raw.into(), delta: Some(60) }],
                outputs: vec![SyncOutput { hash: new_hash, height: Some(11), index: 0, value: 60, coinbase: true, script_pubkey: scan_test_script(1,25) }],
            });
            merge_explicit_scan_snapshot(&pool, account, &keys, &source, &[(1,25)], &snapshots, 26, tokio::time::Instant::now()+std::time::Duration::from_secs(5)).await.unwrap();
            let actual = get_keyinstances_for_account(&pool, account).await.unwrap();
            assert_eq!(actual.len(), 2);
            let discovered = actual.iter().find(|key| key.keyinstance_id != -1).unwrap();
            let outputs = get_utxos_for_account(&pool, account).await.unwrap();
            assert_eq!(outputs.iter().find(|out| out.value == 60).unwrap().keyinstance_id, discovered.keyinstance_id);
            assert_eq!(get_wallet_data(&pool, &format!("address_discovery_v1_{account}")).await.unwrap().as_deref(), marker.then_some("done"));
            pool.close().await;
        }
    }


    #[tokio::test]
    async fn negative_key_sync_and_discovery_on_synthetic_memory_db() {

        for (name, key_id, discover) in [("minus_one", -1, false), ("collision", -1, true), ("min", i64::MIN, false), ("min_discovery", i64::MIN, true), ("positive", 1, false)] {
            let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
            for migration in [include_str!("../../migrations/0022_create_database.sql"), include_str!("../../migrations/0031_txo_script_pubkey.sql"), include_str!("../../migrations/0032_transaction_delta_known.sql")] {
                sqlx::query(migration).execute(&pool).await.unwrap();
            }
            let master = insert_master_key(&pool, None, derivation_type::BIP32, b"synthetic").await.unwrap();
            let account = insert_account(&pool, Some(master), script_type::P2PKH, "synthetic").await.unwrap();
            sqlx::query("INSERT INTO KeyInstances (keyinstance_id,account_id,masterkey_id,derivation_type,derivation_data,script_type,flags,date_created,date_updated) VALUES (?,?,?,?,?,?,0,1,1)")
                .bind(key_id).bind(account).bind(master).bind(derivation_type::BIP32).bind(br#"{"subpath":[0,0]}"#.as_slice()).bind(script_type::P2PKH).execute(&pool).await.unwrap();
            let hash = vec![1; 32];
            upsert_transaction(&pool, &hash, Some(10), None).await.unwrap();
            upsert_transaction_output(&pool, &hash, 0, 42, key_id, 0, Some("51")).await.unwrap();
            upsert_transaction_delta(&pool, key_id, &hash, 42).await.unwrap();
            let keys = get_keyinstances_for_account(&pool, account).await.unwrap();
            let before = sync_db_snapshot(&pool).await;
            let task_pool = pool.clone();
            let task = tokio::spawn(async move {
                let make_snapshot = |key_id, byte| SyncKeySnapshot {
                    key_id,
                    transactions: vec![SyncTransaction { hash: vec![byte; 32], height: Some(11), raw: vec![byte].into(), delta: Some(i64::from(byte) * 10) }],
                    outputs: vec![SyncOutput { hash: vec![byte; 32], height: Some(11), index: 0, value: i64::from(byte) * 10, coinbase: false, script_pubkey: "51".into() }],
                };
                let mut snapshots = vec![make_snapshot(SyncKeyRef::Existing(key_id), 2)];
                if discover { snapshots.push(make_snapshot(SyncKeyRef::Discovered(0), 3)); }
                let paths = [(1, 3)];
                replace_sync_snapshot(&task_pool, account, &keys, discover.then_some(paths.as_slice()), &snapshots).await
            });
            let result = task.await;
            let after = sync_db_snapshot(&pool).await;
            result.unwrap().unwrap();
            assert_ne!(before, after, "{name}");
            assert_eq!(after[3].len(), if discover { 2 } else { 1 }, "{name}");
            assert_eq!(after[4].len(), if discover { 2 } else { 1 }, "{name}");
            let keys = get_keyinstances_for_account(&pool, account).await.unwrap();
            assert!(keys.iter().any(|key| key.keyinstance_id == key_id));
            assert_eq!(keys.len(), if discover { 2 } else { 1 });
            let outputs = get_utxos_for_account(&pool, account).await.unwrap();
            assert_eq!(outputs.iter().find(|output| output.value == 20).unwrap().keyinstance_id, key_id);
            let deltas: Vec<(i64, i64)> = sqlx::query_as("SELECT keyinstance_id,value_delta FROM TransactionDeltas ORDER BY value_delta").fetch_all(&pool).await.unwrap();
            assert_eq!(deltas[0], (key_id, 20));
            if discover {
                let discovered = keys.iter().find(|key| key.keyinstance_id != key_id).unwrap();
                assert_eq!(outputs.iter().find(|output| output.value == 30).unwrap().keyinstance_id, discovered.keyinstance_id);
                assert_eq!(deltas[1], (discovered.keyinstance_id, 30));
                if key_id == i64::MIN { assert_eq!(discovered.keyinstance_id, i64::MIN + 1); }
            }
            assert_eq!(get_wallet_data(&pool, &format!("address_discovery_v1_{account}")).await.unwrap().as_deref(), discover.then_some("done"));
            pool.close().await;
        }
    }

    fn unique_test_dir(test_name: &str) -> std::path::PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("electrumsv_mc_{}_{}", test_name, id));
        // Clean up any leftover from previous test runs
        if dir.exists() {
            std::fs::remove_dir_all(&dir).ok();
        }
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn setup_test_db(test_name: &str) -> (SqlitePool, std::path::PathBuf) {
        let temp_dir = unique_test_dir(test_name);
        let db_path = temp_dir.join("test_repo.sqlite");
        // Remove any leftover database file
        if db_path.exists() {
            std::fs::remove_file(&db_path).unwrap();
        }
        connection::create_wallet_db(db_path.to_str().unwrap())
            .await
            .unwrap();
        let pool = connection::open_wallet_db(db_path.to_str().unwrap())
            .await
            .unwrap();
        (pool, temp_dir)
    }

    #[tokio::test]
    async fn sync_snapshot_rejects_stale_key_row_before_discovery_writes() {
        let (pool, _dir) = setup_test_db("sync_stale_key_row").await;
        let master = insert_master_key(&pool, None, derivation_type::BIP32, b"synthetic").await.unwrap();
        let account = insert_account(&pool, Some(master), script_type::P2PKH, "synthetic").await.unwrap();
        let key = insert_keyinstance(&pool, account, Some(master), derivation_type::BIP32, br#"{"subpath":[0,0]}"#, script_type::P2PKH, 0, None).await.unwrap();
        let expected = get_keyinstances_for_account(&pool, account).await.unwrap();
        sqlx::query("UPDATE KeyInstances SET flags=1 WHERE keyinstance_id=?").bind(key).execute(&pool).await.unwrap();
        let before = sync_db_snapshot(&pool).await;
        let snapshots = [
            SyncKeySnapshot { key_id: SyncKeyRef::Existing(key), transactions: vec![], outputs: vec![] },
            SyncKeySnapshot { key_id: SyncKeyRef::Discovered(0), transactions: vec![], outputs: vec![] },
        ];
        let error = replace_sync_snapshot(&pool, account, &expected, Some(&[(0, 1)]), &snapshots).await.unwrap_err();
        assert!(error.to_string().contains("account keys changed"));
        assert_eq!(sync_db_snapshot(&pool).await, before);
        pool.close().await;
    }

    #[tokio::test]
    async fn sync_snapshot_rolls_back_and_resyncs_idempotently() {
        let (pool, _dir) = setup_test_db("sync_snapshot_atomic").await;
        let master = insert_master_key(&pool, None, derivation_type::BIP32, b"test").await.unwrap();
        let account = insert_account(&pool, Some(master), script_type::P2PKH, "Test").await.unwrap();
        let first = insert_keyinstance(&pool, account, Some(master), derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#, script_type::P2PKH, 0, None).await.unwrap();
        let second = insert_keyinstance(&pool, account, Some(master), derivation_type::BIP32,
            br#"{"subpath":[0,1]}"#, script_type::P2PKH, 0, None).await.unwrap();
        let old = vec![1; 32];
        upsert_transaction(&pool, &old, Some(10), None).await.unwrap();
        upsert_transaction_output(&pool, &old, 0, 50000, first, 0, None).await.unwrap();
        upsert_transaction_delta(&pool, first, &old, 50000).await.unwrap();
        let expected = get_keyinstances_for_account(&pool, account).await.unwrap();
        let before = sync_db_snapshot(&pool).await;
        let transactions_before: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT tx_hash FROM Transactions ORDER BY tx_hash").fetch_all(&pool).await.unwrap();
        let snapshots = vec![
            SyncKeySnapshot { key_id: SyncKeyRef::Existing(first), transactions: vec![], outputs: vec![] },
            SyncKeySnapshot { key_id: SyncKeyRef::Existing(second), transactions: vec![], outputs: vec![SyncOutput {
                hash: vec![2; 32], height: Some(11), index: 0, value: 12000, coinbase: false, script_pubkey: "76a91400".into(),
            }] },
        ];
        sqlx::query("CREATE TRIGGER fail_sync BEFORE INSERT ON TransactionOutputs BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
            .execute(&pool).await.unwrap();
        let mut snapshots_with_discovery = vec![SyncKeySnapshot { key_id: SyncKeyRef::Discovered(0), transactions: vec![], outputs: vec![] }];
        snapshots_with_discovery.extend(snapshots);
        let error = replace_sync_snapshot(&pool, account, &expected, Some(&[(1, 3)]), &snapshots_with_discovery).await.unwrap_err();
        assert!(format!("{error:#}").contains("injected failure"));
        assert_eq!(sync_db_snapshot(&pool).await, before);
        let transactions_after: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT tx_hash FROM Transactions ORDER BY tx_hash").fetch_all(&pool).await.unwrap();
        assert_eq!(transactions_before, transactions_after);
        assert_eq!(get_keyinstances_for_account(&pool, account).await.unwrap().len(), 2);
        assert!(get_wallet_data(&pool, &format!("address_discovery_v1_{account}")).await.unwrap().is_none());
        assert_eq!(get_balance_for_account(&pool, account).await.unwrap(), (50000, 0, 50000));
        let history = get_tx_history_for_account(&pool, account, 50, 0).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].value_delta, Some(50000));
        sqlx::query("DROP TRIGGER fail_sync").execute(&pool).await.unwrap();
        let snapshots = &snapshots_with_discovery[1..];
        for _ in 0..2 {
            replace_sync_snapshot(&pool, account, &expected, None, snapshots).await.unwrap();
            assert_eq!(get_balance_for_account(&pool, account).await.unwrap(), (12000, 0, 12000));
            assert!(get_tx_history_for_account(&pool, account, 50, 0).await.unwrap().is_empty());
            assert_eq!(get_utxos_for_account(&pool, account).await.unwrap().len(), 1);
        }
        insert_keyinstance(&pool, account, Some(master), derivation_type::BIP32,
            br#"{"subpath":[1,3]}"#, script_type::P2PKH, 0, None).await.unwrap();
        assert!(replace_sync_snapshot(&pool, account, &expected, Some(&[(1, 3)]), &snapshots_with_discovery).await.is_err());
        assert_eq!(get_keyinstances_for_account(&pool, account).await.unwrap().len(), 3);
        assert!(get_wallet_data(&pool, &format!("address_discovery_v1_{account}")).await.unwrap().is_none());
        assert_eq!(get_balance_for_account(&pool, account).await.unwrap(), (12000, 0, 12000));
        pool.close().await;
    }

    #[tokio::test]
    async fn sync_preserves_existing_output_and_transaction_metadata() {
        let (pool, _dir) = setup_test_db("sync_metadata").await;
        let master = insert_master_key(&pool, None, derivation_type::BIP32, b"test").await.unwrap();
        let account = insert_account(&pool, Some(master), script_type::P2PKH, "test").await.unwrap();
        let key = insert_keyinstance(&pool, account, Some(master), derivation_type::BIP32, br#"{"subpath":[0,0]}"#, script_type::P2PKH, 0, None).await.unwrap();
        let keys = get_keyinstances_for_account(&pool,account).await.unwrap();
        let hash = vec![42;32];
        upsert_transaction(&pool,&hash,None,Some(&[1,2,3])).await.unwrap();
        upsert_transaction_output(&pool,&hash,0,50,key,txo_flags::IS_SPENT | txo_flags::IS_COINBASE | 64,Some("51")).await.unwrap();
        sqlx::query("UPDATE Transactions SET flags=?, description='preserved', proof_data=? WHERE tx_hash=?")
            .bind(tx_flags::IS_UNCONFIRMED | tx_flags::IS_COINBASE | 64).bind(vec![9u8]).bind(&hash).execute(&pool).await.unwrap();
        sqlx::query("UPDATE TransactionOutputs SET date_created=12345 WHERE tx_hash=?").bind(&hash).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO SpendPlans(plan_id,account_id,state,plan_json,fee_rate,expires_at,date_updated) VALUES('test',?,'SIGNED','{}',1,0,0)").bind(account).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO SpendReservations(tx_hash,tx_index,plan_id) VALUES(?,0,'test')").bind(&hash).execute(&pool).await.unwrap();
        let snapshot = |height,coinbase| vec![SyncKeySnapshot { key_id:SyncKeyRef::Existing(key),
            transactions:vec![SyncTransaction { hash:hash.clone(), height, raw:vec![1,2,3].into(), delta:Some(50) }],
            outputs:vec![SyncOutput { hash:hash.clone(), height, index:0, value:50, coinbase, script_pubkey:"51".into() }] }];
        replace_sync_snapshot(&pool,account,&keys,None,&snapshot(Some(10),false)).await.unwrap();
        let tx: (i32,Option<String>,Option<Vec<u8>>) = sqlx::query_as("SELECT flags,description,proof_data FROM Transactions WHERE tx_hash=?").bind(&hash).fetch_one(&pool).await.unwrap();
        assert_eq!(tx,(tx_flags::IS_COINBASE | 64,Some("preserved".into()),Some(vec![9])));
        let out: (i32,i64) = sqlx::query_as("SELECT flags,date_created FROM TransactionOutputs WHERE tx_hash=? AND tx_index=0").bind(&hash).fetch_one(&pool).await.unwrap();
        assert_eq!(out,(64,12345));
        let reservation: (String,) = sqlx::query_as("SELECT plan_id FROM SpendReservations WHERE tx_hash=? AND tx_index=0").bind(&hash).fetch_one(&pool).await.unwrap();
        assert_eq!(reservation.0,"test");
        replace_sync_snapshot(&pool,account,&keys,None,&snapshot(None,true)).await.unwrap();
        let tx_flags: (i32,) = sqlx::query_as("SELECT flags FROM Transactions WHERE tx_hash=?").bind(&hash).fetch_one(&pool).await.unwrap();
        let out: (i32,i64) = sqlx::query_as("SELECT flags,date_created FROM TransactionOutputs WHERE tx_hash=? AND tx_index=0").bind(&hash).fetch_one(&pool).await.unwrap();
        assert_eq!(tx_flags.0,tx_flags::IS_COINBASE | tx_flags::IS_UNCONFIRMED | 64);
        assert_eq!(out,(txo_flags::IS_COINBASE | 64,12345));
        pool.close().await;
    }

    #[tokio::test]
    async fn sync_history_known_and_unknown_roundtrip() {
        let (pool, _dir) = setup_test_db("sync_history_values").await;
        let master = insert_master_key(&pool, None, derivation_type::BIP32, b"test").await.unwrap();
        let account = insert_account(&pool, Some(master), script_type::P2PKH, "test").await.unwrap();
        let key = insert_keyinstance(&pool, account, Some(master), derivation_type::BIP32, br#"{"subpath":[0,0]}"#, script_type::P2PKH, 0, None).await.unwrap();
        let keys = get_keyinstances_for_account(&pool, account).await.unwrap();
        let hash: Vec<u8> = (0..32).collect();
        let snapshot = |delta| vec![SyncKeySnapshot { key_id: SyncKeyRef::Existing(key), transactions: vec![SyncTransaction {
            hash: hash.clone(), height: Some(22), raw: vec![1, 2, 3].into(), delta,
        }], outputs: vec![] }];
        replace_sync_snapshot(&pool, account, &keys, None, &snapshot(None)).await.unwrap();
        assert_eq!(get_tx_history_for_account(&pool, account, 50, 0).await.unwrap()[0].value_delta, None);
        replace_sync_snapshot(&pool, account, &keys, None, &snapshot(Some(-500))).await.unwrap();
        let rows = get_tx_history_for_account(&pool, account, 50, 0).await.unwrap();
        assert_eq!(rows[0].value_delta, Some(-500));
        let stored: Option<(Vec<u8>,)> = sqlx::query_as("SELECT tx_data FROM Transactions WHERE tx_hash = ?").bind(&hash).fetch_optional(&pool).await.unwrap();
        assert_eq!(stored.unwrap().0, vec![1, 2, 3]);
        assert_eq!(rows[0].tx_hash_hex, crate::core::address::hash_to_hex_str(&hash));
        pool.close().await;
    }

    #[tokio::test]
    async fn sync_discovery_maps_every_key_and_preserves_scripts() {
        let (pool, _dir) = setup_test_db("sync_discovery_mapping").await;
        let master = insert_master_key(&pool, None, derivation_type::BIP32, b"test").await.unwrap();
        let account = insert_account(&pool, Some(master), script_type::P2PKH, "Test").await.unwrap();
        let expected = get_keyinstances_for_account(&pool, account).await.unwrap();
        let paths = [(0, 7), (1, 9)];
        let snapshots = vec![
            SyncKeySnapshot { key_id: SyncKeyRef::Discovered(1), transactions: vec![], outputs: vec![SyncOutput {
                hash: vec![3; 32], height: Some(8), index: 2, value: 30, coinbase: false, script_pubkey: "bbaa".into(),
            }] },
            SyncKeySnapshot { key_id: SyncKeyRef::Discovered(0), transactions: vec![], outputs: vec![SyncOutput {
                hash: (0..32).collect(), height: Some(9), index: 1, value: 40, coinbase: false, script_pubkey: "aabb".into(),
            }] },
        ];
        replace_sync_snapshot(&pool, account, &expected, Some(&paths), &snapshots).await.unwrap();
        let keys = get_keyinstances_for_account(&pool, account).await.unwrap();
        assert_eq!(keys.len(), 2);
        let outputs = get_utxos_for_account(&pool, account).await.unwrap();
        assert_eq!(outputs.iter().find(|o| o.value == 40).unwrap().keyinstance_id, keys[0].keyinstance_id);
        assert_eq!(outputs.iter().find(|o| o.value == 30).unwrap().keyinstance_id, keys[1].keyinstance_id);
        let txid = crate::core::address::hash_to_hex_str(&(0..32).collect::<Vec<u8>>());
        let details = get_transaction_outputs(&pool, &txid).await.unwrap();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].script_pubkey, "aabb");
        assert_eq!(details[0].value, 40);
        assert_eq!(get_wallet_data(&pool, &format!("address_discovery_v1_{account}")).await.unwrap().as_deref(), Some("done"));
        let incomplete = vec![SyncKeySnapshot { key_id: SyncKeyRef::Existing(keys[0].keyinstance_id), transactions: vec![], outputs: vec![] }];
        assert!(replace_sync_snapshot(&pool, account, &keys, None, &incomplete).await.is_err());
        let duplicate = vec![SyncKeySnapshot { key_id: SyncKeyRef::Existing(keys[0].keyinstance_id), transactions: vec![], outputs: vec![] },
            SyncKeySnapshot { key_id: SyncKeyRef::Existing(keys[0].keyinstance_id), transactions: vec![], outputs: vec![] }];
        assert!(replace_sync_snapshot(&pool, account, &keys, None, &duplicate).await.is_err());
        let invalid = vec![SyncKeySnapshot { key_id: SyncKeyRef::Existing(keys[0].keyinstance_id), transactions: vec![], outputs: vec![] },
            SyncKeySnapshot { key_id: SyncKeyRef::Discovered(usize::MAX), transactions: vec![], outputs: vec![] }];
        assert!(replace_sync_snapshot(&pool, account, &keys, None, &invalid).await.is_err());
        let mut repeated_paths = keys.iter().map(|key| SyncKeySnapshot { key_id: SyncKeyRef::Existing(key.keyinstance_id), transactions: vec![], outputs: vec![] }).collect::<Vec<_>>();
        repeated_paths.push(SyncKeySnapshot { key_id: SyncKeyRef::Discovered(0), transactions: vec![], outputs: vec![] });
        repeated_paths.push(SyncKeySnapshot { key_id: SyncKeyRef::Discovered(1), transactions: vec![], outputs: vec![] });
        assert!(replace_sync_snapshot(&pool, account, &keys, Some(&[(0, 42), (0, 42)]), &repeated_paths).await.unwrap_err().to_string().contains("duplicate discovered"));
        assert_eq!(get_keyinstances_for_account(&pool, account).await.unwrap().len(), 2);
        let new_hash = vec![9; 32];
        let duplicates = keys.iter().map(|key| SyncKeySnapshot { key_id: SyncKeyRef::Existing(key.keyinstance_id), transactions: vec![], outputs: vec![SyncOutput {
            hash: new_hash.clone(), height: Some(10), index: 0, value: 1, coinbase: false, script_pubkey: "51".into(),
        }] }).collect::<Vec<_>>();
        let error = replace_sync_snapshot(&pool, account, &keys, None, &duplicates).await.unwrap_err();
        assert!(error.to_string().contains("duplicate UTXO outpoint"));
        let new_tx: Option<(Vec<u8>,)> = sqlx::query_as("SELECT tx_hash FROM Transactions WHERE tx_hash=?").bind(&new_hash).fetch_optional(&pool).await.unwrap();
        assert!(new_tx.is_none());
        assert_eq!(get_balance_for_account(&pool, account).await.unwrap().2, 70);
        pool.close().await;
    }

    #[tokio::test]
    async fn sync_refuses_another_accounts_output_and_rolls_back() {
        let (pool, _dir) = setup_test_db("sync_output_owner").await;
        let master = insert_master_key(&pool, None, derivation_type::BIP32, b"test").await.unwrap();
        let account = insert_account(&pool, Some(master), script_type::P2PKH, "First").await.unwrap();
        let other = insert_account(&pool, Some(master), script_type::P2PKH, "Second").await.unwrap();
        let key = insert_keyinstance(&pool, account, Some(master), derivation_type::BIP32, br#"{"subpath":[0,0]}"#, script_type::P2PKH, 0, None).await.unwrap();
        let other_key = insert_keyinstance(&pool, other, Some(master), derivation_type::BIP32, br#"{"subpath":[0,1]}"#, script_type::P2PKH, 0, None).await.unwrap();
        let hash = vec![7; 32];
        upsert_transaction(&pool, &hash, Some(10), None).await.unwrap();
        upsert_transaction_output(&pool, &hash, 0, 50000, other_key, 0, Some("abcd")).await.unwrap();
        let keys = get_keyinstances_for_account(&pool, account).await.unwrap();
        let before = sync_db_snapshot(&pool).await;
        let snapshots = vec![SyncKeySnapshot { key_id: SyncKeyRef::Existing(key), transactions: vec![], outputs: vec![SyncOutput {
            hash, height: Some(11), index: 0, value: 50000, coinbase: false, script_pubkey: "abcd".into(),
        }] }];
        assert!(replace_sync_snapshot(&pool, account, &keys, None, &snapshots).await.is_err());
        assert_eq!(sync_db_snapshot(&pool).await, before);
        assert_eq!(get_balance_for_account(&pool, other).await.unwrap().2, 50000);
        assert_eq!(get_utxos_for_account(&pool, other).await.unwrap()[0].keyinstance_id, other_key);
        pool.close().await;
    }

    #[tokio::test]
    async fn test_insert_and_read_master_key() {
        let (pool, _dir) = setup_test_db("mk_rw").await;

        let derivation_data = br#"{"xpub":"test_xpub","xprv":"encrypted_xprv"}"#;
        let id = insert_master_key(&pool, None, derivation_type::BIP32, derivation_data)
            .await
            .unwrap();
        assert_eq!(id, 1);

        let mk = get_first_master_key(&pool).await.unwrap().unwrap();
        assert_eq!(mk.masterkey_id, 1);
        assert_eq!(mk.derivation_type, derivation_type::BIP32);
        assert!(mk.parent_masterkey_id.is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_insert_and_read_account() {
        let (pool, _dir) = setup_test_db("acct_rw").await;

        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Standard account")
            .await
            .unwrap();
        assert_eq!(acct_id, 1);

        let acct = get_first_account(&pool).await.unwrap().unwrap();
        assert_eq!(acct.account_id, 1);
        assert_eq!(acct.account_name, "Standard account");
        assert_eq!(acct.default_script_type, script_type::P2PKH);
        assert_eq!(acct.default_masterkey_id, Some(1));

        pool.close().await;
    }

    #[tokio::test]
    async fn test_wallet_data_get_set() {
        let (pool, _dir) = setup_test_db("wd_gs").await;

        // migration key should already be set by create_wallet_db
        let migration = get_wallet_data(&pool, "migration").await.unwrap();
        assert_eq!(migration, Some(connection::MIGRATION_CURRENT.to_string()));

        // Set a new key
        set_wallet_data(&pool, "password-token", "encrypted_token")
            .await
            .unwrap();
        let val = get_wallet_data(&pool, "password-token").await.unwrap();
        assert_eq!(val, Some("encrypted_token".to_string()));

        // Update existing key
        set_wallet_data(&pool, "password-token", "new_token")
            .await
            .unwrap();
        let val = get_wallet_data(&pool, "password-token").await.unwrap();
        assert_eq!(val, Some("new_token".to_string()));

        pool.close().await;
    }

    #[tokio::test]
    async fn test_get_first_master_key_empty() {
        let (pool, _dir) = setup_test_db("mk_empty").await;
        let mk = get_first_master_key(&pool).await.unwrap();
        assert!(mk.is_none());

        pool.close().await;
    }

    // ========================================================================
    // Milestone 4 Teil 4 — upsert tests
    // ========================================================================

    #[tokio::test]
    async fn test_upsert_transaction_confirmed() {
        let (pool, _dir) = setup_test_db("upsert_tx_conf").await;

        let tx_hash = vec![0xaa; 32];
        upsert_transaction(&pool, &tx_hash, Some(800000), None)
            .await
            .unwrap();

        // Read back
        let row: Option<(Vec<u8>, Option<i64>, i32)> = sqlx::query_as(
            "SELECT tx_hash, block_height, flags FROM Transactions WHERE tx_hash = ?",
        )
        .bind(&tx_hash)
        .fetch_optional(&pool)
        .await
        .unwrap();

        assert!(row.is_some());
        let (hash, height, flags) = row.unwrap();
        assert_eq!(hash, tx_hash);
        assert_eq!(height, Some(800000));
        assert_eq!(flags, 0); // confirmed = no flags

        pool.close().await;
    }

    #[tokio::test]
    async fn test_upsert_transaction_unconfirmed() {
        let (pool, _dir) = setup_test_db("upsert_tx_unconf").await;

        let tx_hash = vec![0xbb; 32];
        upsert_transaction(&pool, &tx_hash, None, None)
            .await
            .unwrap();

        let row: Option<(Option<i64>, i32)> =
            sqlx::query_as("SELECT block_height, flags FROM Transactions WHERE tx_hash = ?")
                .bind(&tx_hash)
                .fetch_optional(&pool)
                .await
                .unwrap();

        let (height, flags) = row.unwrap();
        assert_eq!(height, None);
        assert_eq!(flags, tx_flags::IS_UNCONFIRMED);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_upsert_transaction_updates() {
        let (pool, _dir) = setup_test_db("upsert_tx_update").await;

        let tx_hash = vec![0xcc; 32];
        // Insert as unconfirmed
        upsert_transaction(&pool, &tx_hash, None, None)
            .await
            .unwrap();
        // Update to confirmed
        upsert_transaction(&pool, &tx_hash, Some(800001), None)
            .await
            .unwrap();

        let row: Option<(Option<i64>, i32)> =
            sqlx::query_as("SELECT block_height, flags FROM Transactions WHERE tx_hash = ?")
                .bind(&tx_hash)
                .fetch_optional(&pool)
                .await
                .unwrap();

        let (height, flags) = row.unwrap();
        assert_eq!(height, Some(800001));
        assert_eq!(flags, 0); // confirmed now

        pool.close().await;
    }

    #[tokio::test]
    async fn test_upsert_transaction_output() {
        let (pool, _dir) = setup_test_db("upsert_txo").await;

        // Need a masterkey + account + keyinstance for FK
        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Test")
            .await
            .unwrap();
        let ki_id = insert_keyinstance(
            &pool,
            acct_id,
            Some(mk_id),
            derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        let tx_hash = vec![0xdd; 32];
        upsert_transaction(&pool, &tx_hash, Some(800000), None)
            .await
            .unwrap();
        upsert_transaction_output(&pool, &tx_hash, 0, 50000, ki_id, 0, None)
            .await
            .unwrap();

        // Read back
        let row: Option<(i64, i64, i32)> = sqlx::query_as(
            "SELECT value, keyinstance_id, flags FROM TransactionOutputs WHERE tx_hash = ? AND tx_index = ?",
        )
        .bind(&tx_hash)
        .bind(0i64)
        .fetch_optional(&pool)
        .await
        .unwrap();

        let (value, ki, flags) = row.unwrap();
        assert_eq!(value, 50000);
        assert_eq!(ki, ki_id);
        assert_eq!(flags, 0);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_upsert_transaction_delta() {
        let (pool, _dir) = setup_test_db("upsert_txd").await;

        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Test")
            .await
            .unwrap();
        let ki_id = insert_keyinstance(
            &pool,
            acct_id,
            Some(mk_id),
            derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        let tx_hash = vec![0xee; 32];
        upsert_transaction(&pool, &tx_hash, None, None)
            .await
            .unwrap();
        upsert_transaction_delta(&pool, ki_id, &tx_hash, 25000)
            .await
            .unwrap();

        // Update delta
        upsert_transaction_delta(&pool, ki_id, &tx_hash, 30000)
            .await
            .unwrap();

        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT value_delta FROM TransactionDeltas WHERE keyinstance_id = ? AND tx_hash = ?",
        )
        .bind(ki_id)
        .bind(&tx_hash)
        .fetch_optional(&pool)
        .await
        .unwrap();

        let (delta,) = row.unwrap();
        assert_eq!(delta, 30000); // Updated value

        pool.close().await;
    }

    #[tokio::test]
    async fn test_mark_output_spent() {
        let (pool, _dir) = setup_test_db("mark_spent").await;

        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Test")
            .await
            .unwrap();
        let ki_id = insert_keyinstance(
            &pool,
            acct_id,
            Some(mk_id),
            derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        let tx_hash = vec![0xff; 32];
        upsert_transaction(&pool, &tx_hash, Some(800000), None)
            .await
            .unwrap();
        upsert_transaction_output(&pool, &tx_hash, 0, 50000, ki_id, 0, None)
            .await
            .unwrap();

        // Mark as spent
        mark_output_spent(&pool, &tx_hash, 0).await.unwrap();

        let row: Option<(i32,)> = sqlx::query_as(
            "SELECT flags FROM TransactionOutputs WHERE tx_hash = ? AND tx_index = ?",
        )
        .bind(&tx_hash)
        .bind(0i64)
        .fetch_optional(&pool)
        .await
        .unwrap();

        let (flags,) = row.unwrap();
        assert_eq!(flags, txo_flags::IS_SPENT);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_clear_outputs_and_deltas() {
        let (pool, _dir) = setup_test_db("clear_outputs").await;

        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Test")
            .await
            .unwrap();
        let ki_id = insert_keyinstance(
            &pool,
            acct_id,
            Some(mk_id),
            derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        let tx_hash = vec![0x11; 32];
        upsert_transaction(&pool, &tx_hash, Some(800000), None)
            .await
            .unwrap();
        upsert_transaction_output(&pool, &tx_hash, 0, 50000, ki_id, 0, None)
            .await
            .unwrap();
        upsert_transaction_delta(&pool, ki_id, &tx_hash, 50000)
            .await
            .unwrap();

        // Clear
        clear_outputs_and_deltas_for_keyinstances(&pool, &[ki_id])
            .await
            .unwrap();

        // Verify outputs deleted
        let out_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM TransactionOutputs WHERE keyinstance_id = ?")
                .bind(ki_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(out_count, 0);

        // Verify deltas deleted
        let delta_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM TransactionDeltas WHERE keyinstance_id = ?")
                .bind(ki_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(delta_count, 0);

        // Transaction should still exist (not deleted)
        let tx_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM Transactions WHERE tx_hash = ?")
                .bind(&tx_hash)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(tx_count, 1);

        pool.close().await;
    }

    // ========================================================================
    // Milestone 5 — TOTP Secret queries
    // ========================================================================

    #[tokio::test]
    async fn test_totp_secret_store_and_load() {
        let (pool, _dir) = setup_test_db("totp_secret").await;

        let secret = b"my_totp_secret_20_bytes";
        store_totp_secret(&pool, secret).await.unwrap();

        let loaded = load_totp_secret(&pool).await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap(), secret.to_vec());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_totp_secret_none_when_empty() {
        let (pool, _dir) = setup_test_db("totp_empty").await;

        let loaded = load_totp_secret(&pool).await.unwrap();
        assert!(loaded.is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_totp_secret_delete() {
        let (pool, _dir) = setup_test_db("totp_delete").await;

        store_totp_secret(&pool, b"secret_to_delete").await.unwrap();
        assert!(load_totp_secret(&pool).await.unwrap().is_some());

        delete_totp_secret(&pool).await.unwrap();
        assert!(load_totp_secret(&pool).await.unwrap().is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_hardware_wallet_enabled_default_false() {
        let (pool, _dir) = setup_test_db("hw_default").await;

        let enabled = get_hardware_wallet_enabled(&pool).await.unwrap();
        assert!(!enabled);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_hardware_wallet_enabled_set_true() {
        let (pool, _dir) = setup_test_db("hw_true").await;

        set_hardware_wallet_enabled(&pool, true).await.unwrap();
        let enabled = get_hardware_wallet_enabled(&pool).await.unwrap();
        assert!(enabled);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_hardware_wallet_enabled_toggle() {
        let (pool, _dir) = setup_test_db("hw_toggle").await;

        set_hardware_wallet_enabled(&pool, true).await.unwrap();
        assert!(get_hardware_wallet_enabled(&pool).await.unwrap());

        set_hardware_wallet_enabled(&pool, false).await.unwrap();
        assert!(!get_hardware_wallet_enabled(&pool).await.unwrap());

        pool.close().await;
    }

    // ========================================================================
    // Milestone 6 — Contacts, Labels, Payment Requests, Config tests
    // ========================================================================

    #[tokio::test]
    async fn test_contact_insert_get_update_delete() {
        let (pool, _dir) = setup_test_db("contact_crud").await;

        // Insert
        let id1 = insert_contact(&pool, "Alice").await.unwrap();
        let id2 = insert_contact(&pool, "Bob").await.unwrap();
        assert!(id1 >= 1);
        assert!(id2 > id1);

        // Get all
        let contacts = get_all_contacts(&pool).await.unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].label, "Alice");

        // Get by id
        let alice = get_contact_by_id(&pool, id1).await.unwrap().unwrap();
        assert_eq!(alice.label, "Alice");

        // Update label
        update_contact_label(&pool, id1, "Alice Smith").await.unwrap();
        let alice = get_contact_by_id(&pool, id1).await.unwrap().unwrap();
        assert_eq!(alice.label, "Alice Smith");

        // Delete
        delete_contact(&pool, id2).await.unwrap();
        let contacts = get_all_contacts(&pool).await.unwrap();
        assert_eq!(contacts.len(), 1);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_check_label_in_use() {
        let (pool, _dir) = setup_test_db("contact_label_check").await;

        assert!(!check_label_in_use(&pool, "Charlie").await.unwrap());

        insert_contact(&pool, "Charlie").await.unwrap();
        assert!(check_label_in_use(&pool, "Charlie").await.unwrap());
        assert!(!check_label_in_use(&pool, "Dave").await.unwrap());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_contact_identities() {
        let (pool, _dir) = setup_test_db("contact_identities").await;

        let contact_id = insert_contact(&pool, "Alice").await.unwrap();

        // Insert on-chain identity
        insert_contact_identity(
            &pool,
            contact_id,
            contact_identity_system::ONCHAIN,
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        )
        .await
        .unwrap();

        // Insert paymail identity
        insert_contact_identity(
            &pool,
            contact_id,
            contact_identity_system::PAYMAIL,
            "alice@example.com",
        )
        .await
        .unwrap();

        // Get identities
        let identities = get_contact_identities(&pool, contact_id).await.unwrap();
        assert_eq!(identities.len(), 2);
        assert_eq!(identities[0].system_id, contact_identity_system::ONCHAIN);
        assert_eq!(identities[0].system_data, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(identities[0].identity_id.len(), 16);
        assert!(identities[0].last_verified.is_none());

        assert_eq!(identities[1].system_id, contact_identity_system::PAYMAIL);
        assert_eq!(identities[1].system_data, "alice@example.com");

        // Deleting contact should cascade-delete identities
        delete_contact(&pool, contact_id).await.unwrap();
        let identities = get_contact_identities(&pool, contact_id).await.unwrap();
        assert_eq!(identities.len(), 0);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_keyinstance_label_set_get() {
        let (pool, _dir) = setup_test_db("ki_label").await;

        // Setup: create masterkey, account, keyinstance
        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Test")
            .await
            .unwrap();
        let ki_id = insert_keyinstance(
            &pool,
            acct_id,
            Some(mk_id),
            derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        // Initially no label
        let label = get_keyinstance_label(&pool, ki_id).await.unwrap();
        assert!(label.is_none());

        // Set label
        set_keyinstance_label(&pool, ki_id, Some("My Address")).await.unwrap();
        let label = get_keyinstance_label(&pool, ki_id).await.unwrap();
        assert_eq!(label.as_deref(), Some("My Address"));

        // Clear label
        set_keyinstance_label(&pool, ki_id, None).await.unwrap();
        let label = get_keyinstance_label(&pool, ki_id).await.unwrap();
        assert!(label.is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_transaction_label_set_get() {
        let (pool, _dir) = setup_test_db("tx_label").await;

        let tx_hash = vec![0x42; 32];
        upsert_transaction(&pool, &tx_hash, Some(800000), None)
            .await
            .unwrap();

        // Initially no label
        let label = get_transaction_label(&pool, &tx_hash).await.unwrap();
        assert!(label.is_none());

        // Set label
        set_transaction_label(&pool, &tx_hash, Some("Payment to Alice")).await.unwrap();
        let label = get_transaction_label(&pool, &tx_hash).await.unwrap();
        assert_eq!(label.as_deref(), Some("Payment to Alice"));

        // Clear label
        set_transaction_label(&pool, &tx_hash, None).await.unwrap();
        let label = get_transaction_label(&pool, &tx_hash).await.unwrap();
        assert!(label.is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_payment_request_insert_list() {
        let (pool, _dir) = setup_test_db("payreq").await;

        // Setup: create masterkey, account, keyinstance
        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Test")
            .await
            .unwrap();
        let ki_id = insert_keyinstance(
            &pool,
            acct_id,
            Some(mk_id),
            derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        // Insert payment request with value and description
        let pr_id1 = insert_payment_request(&pool, ki_id, Some(50000), Some("Invoice #1"))
            .await
            .unwrap();
        assert!(pr_id1 >= 1);

        // Insert payment request with no value, no description
        let pr_id2 = insert_payment_request(&pool, ki_id, None, None)
            .await
            .unwrap();
        assert!(pr_id2 > pr_id1);

        // List
        let requests = get_payment_requests(&pool).await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].keyinstance_id, ki_id);
        assert_eq!(requests[0].state, 0);
        assert_eq!(requests[0].value, Some(50000));
        assert_eq!(requests[0].description.as_deref(), Some("Invoice #1"));
        assert!(requests[0].expiration.is_none());

        assert_eq!(requests[1].value, None);
        assert!(requests[1].description.is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_config_set_get_all() {
        let (pool, _dir) = setup_test_db("config").await;

        // Set config values
        set_config_value(&pool, "theme", "dark").await.unwrap();
        set_config_value(&pool, "language", "en").await.unwrap();

        // Get individual
        let theme = get_config_value(&pool, "theme").await.unwrap();
        assert_eq!(theme.as_deref(), Some("dark"));
        let lang = get_config_value(&pool, "language").await.unwrap();
        assert_eq!(lang.as_deref(), Some("en"));
        let missing = get_config_value(&pool, "nonexistent").await.unwrap();
        assert!(missing.is_none());

        // Get all config
        let all = get_all_config(&pool).await.unwrap();
        let obj = all.as_object().unwrap();
        assert!(obj.contains_key("theme"));
        assert_eq!(obj["theme"], "dark");
        assert!(obj.contains_key("language"));
        assert_eq!(obj["language"], "en");
        // migration key should also be present
        assert!(obj.contains_key("migration"));

        // Update existing
        set_config_value(&pool, "theme", "light").await.unwrap();
        let theme = get_config_value(&pool, "theme").await.unwrap();
        assert_eq!(theme.as_deref(), Some("light"));

        pool.close().await;
    }

    #[tokio::test]
    async fn test_get_all_accounts_and_by_id() {
        let (pool, _dir) = setup_test_db("accounts_query").await;

        // No accounts initially
        let accounts = get_all_accounts(&pool).await.unwrap();
        assert!(accounts.is_empty());
        assert!(get_account_by_id(&pool, 1).await.unwrap().is_none());

        // Create accounts
        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct1 = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Account 1")
            .await
            .unwrap();
        let acct2 = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Account 2")
            .await
            .unwrap();

        // Get all
        let accounts = get_all_accounts(&pool).await.unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].account_name, "Account 1");
        assert_eq!(accounts[1].account_name, "Account 2");

        // Get by id
        let acct = get_account_by_id(&pool, acct2).await.unwrap().unwrap();
        assert_eq!(acct.account_name, "Account 2");
        assert_eq!(acct.account_id, acct2);

        // Non-existent id
        assert!(get_account_by_id(&pool, 999).await.unwrap().is_none());

        pool.close().await;
    }
}
