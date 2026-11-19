use crate::commands::transactions::{PrepareTxResult, SignTxResult, TransactionCmdError};
use crate::core::coinchooser::Strategy;
use crate::core::signer::{LocalSigner, Signer};
use crate::core::transaction::{PaymentOutput, SelectedUtxo, TransactionError, TxBuilder, TxPlan};
use crate::db::repositories;
use crate::security::totp::TotpInstance;
use crate::state::{self, AppState};
use bsv::compat::bip32::ExtendedKey;
const TX_PLAN_TTL: i64 = 300;

type InstanceMap = std::collections::HashMap<String, std::sync::Arc<()>>;
fn prepared_instances() -> &'static std::sync::Mutex<InstanceMap> {
    static INSTANCES: std::sync::OnceLock<std::sync::Mutex<InstanceMap>> = std::sync::OnceLock::new();
    INSTANCES.get_or_init(|| std::sync::Mutex::new(InstanceMap::new()))
}

#[cfg(test)]
#[path = "transaction_crash_tests.rs"]
mod transaction_crash_tests;

fn in_flight_broadcasts() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    static FLIGHTS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
    FLIGHTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}
struct BroadcastGuard(String);
impl Drop for BroadcastGuard {
    fn drop(&mut self) { in_flight_broadcasts().lock().unwrap().remove(&self.0); }
}

#[derive(Debug, serde::Serialize)]
pub struct SpendPlanStatus { pub plan_id: String, pub state: String, pub txid: Option<String> }

pub(crate) async fn expire_prepared(pool: &sqlx::SqlitePool, now: i64) -> Result<(), String> {
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let expired: Vec<(String,)> = sqlx::query_as("SELECT plan_id FROM SpendPlans WHERE state='PREPARED' AND expires_at < ?").bind(now).fetch_all(&mut *tx).await.map_err(|e| e.to_string())?;
    sqlx::query("DELETE FROM SpendReservations WHERE plan_id IN (SELECT plan_id FROM SpendPlans WHERE state='PREPARED' AND expires_at < ?)")
        .bind(now).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    sqlx::query("UPDATE SpendPlans SET state='EXPIRED', date_updated=? WHERE state='PREPARED' AND expires_at < ?")
        .bind(now).bind(now).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    let mut instances = prepared_instances().lock().unwrap();
    for (plan_id,) in expired { instances.remove(&plan_id); }
    Ok(())
}

fn get_wallet_data(
    state: &AppState,
) -> Result<(sqlx::SqlitePool, i64, String, Option<String>), TransactionCmdError> {
    let guard = state.active_wallet.lock().unwrap();
    let active = guard.as_ref().ok_or(TransactionCmdError::NoWalletOpen)?;
    Ok((
        active.db_pool.clone(),
        active.account_id,
        active.wallet_path.clone(),
        active.decrypted_xprv.clone(),
    ))
}

async fn ensure_change_key(pool: &sqlx::SqlitePool, account_id: i64) -> Result<(), String> {
    let keys = repositories::get_keyinstances_for_account(pool, account_id).await.map_err(|e| e.to_string())?;
    if keys.iter().any(|key| serde_json::from_slice::<serde_json::Value>(&key.derivation_data).ok().and_then(|v| v.get("subpath").cloned()) == Some(serde_json::json!([1, 0]))) { return Ok(()); }
    let master = repositories::get_first_master_key(pool).await.map_err(|e| e.to_string())?.ok_or("missing master key")?;
    repositories::insert_keyinstance(pool, account_id, Some(master.masterkey_id), repositories::derivation_type::BIP32, br#"{"subpath":[1,0]}"#, repositories::script_type::P2PKH, 0, None).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Derive a change address from the wallet at path 1/0 (change chain, index 0).
fn derive_change_address(xprv: &str) -> Result<String, TransactionCmdError> {
    let account_key = ExtendedKey::from_string(xprv)?;
    let child = account_key.derive("1/0")?;
    let pubkey = child
        .public_key()
        .map_err(|e| TransactionCmdError::BsvSdk(e.to_string()))?;
    Ok(crate::core::address::pubkey_to_p2pkh_address(&pubkey))
}

// ============================================================================
// Commands
// ============================================================================

fn parse_strategy(s: &Option<String>) -> Result<Option<Strategy>, String> {
    let Some(name) = s.as_deref() else { return Ok(None) };
    crate::core::coinchooser::STRATEGY_CATALOG.iter().find(|entry| entry.id == name)
        .map(|entry| entry.strategy)
        .ok_or_else(|| format!("invalid coin_selection_strategy '{}': expected one of {}", name,
            crate::core::coinchooser::STRATEGY_CATALOG.iter().map(|entry| entry.id).collect::<Vec<_>>().join(", ")))
}

/// Prepare an unsigned transaction.
///
/// Selects UTXOs, calculates fees, and creates a TX plan bound to the current wallet.
/// The plan must be signed (sign_tx) and broadcast (broadcast_tx) in subsequent calls.
pub async fn prepare_tx(
    state: &AppState,
    outputs: Vec<PaymentOutput>,
    fee_rate: Option<u64>,
    op_return: Option<String>,
    coin_selection_strategy: Option<String>,
) -> Result<PrepareTxResult, String> {
    log::info!("prepare_tx — {} outputs", outputs.len());

    let fee_rate = match fee_rate {
        Some(r) => r,
        None => crate::features::mapi::fetch_default_fee_rate().await,
    };
    let fee_rate_db = i64::try_from(fee_rate).map_err(|_| "fee rate too large")?;
    let _operation = state.wallet_operation.lock().await;
    let (pool, account_id, wallet_path, xprv_opt) = get_wallet_data(state).map_err(|e| e.to_string())?;
    let instance = state.active_wallet.lock().unwrap().as_ref().ok_or("no wallet is currently open")?.instance_id.clone();
    let xprv = xprv_opt.ok_or(TransactionCmdError::WalletLocked.to_string())?;
    expire_prepared(&pool, chrono::Utc::now().timestamp()).await?;

    let op_return_bytes = op_return.as_deref().map(crate::core::transaction::decode_op_return);

    // Fetch UTXOs from DB
    let mut utxo_infos = repositories::get_utxo_infos_for_account(&pool, account_id)
        .await
        .map_err(|e| e.to_string())?;

    let reserved: Vec<(Vec<u8>, i64)> = sqlx::query_as("SELECT tx_hash, tx_index FROM SpendReservations").fetch_all(&pool).await.map_err(|e| e.to_string())?;
    let reserved: std::collections::HashSet<(String, i64)> = reserved.into_iter()
        .map(|(hash, index)| (crate::core::address::hash_to_hex_str(&hash), index)).collect();
    utxo_infos.retain(|u| !reserved.contains(&(u.tx_hash_hex.clone(), u.tx_index)));
    if utxo_infos.is_empty() {
        return Err(TransactionError::NoUtxos.to_string());
    }

    // Convert UTXOs to SelectedUtxo with subpath info
    let mut selected_utxos = Vec::new();
    for info in &utxo_infos {
        if info.is_coinbase || info.script_pubkey.is_empty() || info.value < 0 { continue; }
        let tx_hash = crate::core::address::hex_str_to_hash(&info.tx_hash_hex).map_err(|e| e.to_string())?;
        let available_raw: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM Transactions WHERE tx_hash=? AND tx_data IS NOT NULL").bind(tx_hash)
            .fetch_one(&pool).await.map_err(|e| e.to_string())?;
        if available_raw.0 == 0 { continue; }
        // Get the KeyInstance to find the subpath
        let ki = repositories::get_keyinstance(&pool, info.keyinstance_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                TransactionError::BsvSdk(format!("KeyInstance {} not found", info.keyinstance_id))
                    .to_string()
            })?;

        if ki.derivation_type != repositories::derivation_type::BIP32 { continue; }
        let derivation_data: serde_json::Value =
            serde_json::from_slice(&ki.derivation_data).map_err(|e| e.to_string())?;

        let subpath = derivation_data
            .get("subpath")
            .and_then(|s| s.as_array())
            .ok_or_else(|| {
                TransactionError::BsvSdk("missing subpath in derivation_data".to_string())
                    .to_string()
            })?;

        let type_idx = subpath.get(0)
            .and_then(|v| v.as_u64()).and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| TransactionError::BsvSdk("invalid subpath type index".to_string()).to_string())?;
        let addr_idx = subpath.get(1)
            .and_then(|v| v.as_u64()).and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| TransactionError::BsvSdk("invalid subpath address index".to_string()).to_string())?;

        selected_utxos.push(SelectedUtxo::from_utxo_info(info, [type_idx, addr_idx]));
    }

    // Register the change address so later syncs discover its outputs.
    ensure_change_key(&pool, account_id).await?;
    let change_address = derive_change_address(&xprv).map_err(|e| e.to_string())?;

    // Parse coin selection strategy (None -> largest-first default)
    let strategy = parse_strategy(&coin_selection_strategy)?;

    // Build unsigned transaction
    let op_return_ref = op_return_bytes.as_deref();
    let (tx, selection) =
        TxBuilder::build_unsigned(&selected_utxos, &outputs, Some(&change_address), fee_rate, op_return_ref, strategy)
            .map_err(|e| e.to_string())?;

    // Create TX plan
    let plan = TxBuilder::create_plan(
        tx,
        outputs,
        selection,
        Some(change_address),
        wallet_path,
        account_id,
        TX_PLAN_TTL,
        op_return_bytes,
    )
    .map_err(|e| e.to_string())?;

    log::info!(
        "TX plan created: {} inputs, {} sat fee, {} sat change, expires in {}s",
        plan.inputs.len(),
        plan.fee,
        plan.change,
        TX_PLAN_TTL
    );

    // AUD-008: Store the plan server-side and return only a plan_id handle.
    // The renderer never sees the unsigned_tx_hex or inputs — it cannot
    // tamper with the plan that actually gets signed.
    let plan_id = state::generate_plan_id();
    let now = chrono::Utc::now().timestamp();
    let num_inputs = plan.inputs.len();
    let num_outputs = plan.outputs.len()
        + if plan.change > 0 { 1 } else { 0 }
        + if plan.op_return.is_some() { 1 } else { 0 };
    let fee = plan.fee;
    let total_input = plan.total_input;
    let total_output = plan.total_output;
    let change = plan.change;

    let mut dbtx = pool.begin().await.map_err(|e| e.to_string())?;
    sqlx::query("INSERT INTO SpendPlans (plan_id, account_id, state, plan_json, fee_rate, expires_at, date_updated) VALUES (?, ?, 'PREPARED', ?, ?, ?, ?)")
        .bind(&plan_id).bind(account_id).bind(serde_json::to_string(&plan).map_err(|e| e.to_string())?)
        .bind(fee_rate_db).bind(plan.expires_at).bind(now).execute(&mut *dbtx).await.map_err(|e| e.to_string())?;
    for input in &plan.inputs {
        let hash = crate::core::address::hex_str_to_hash(&input.tx_hash_hex).map_err(|e| e.to_string())?;
        let exists: Option<(i64,)> = sqlx::query_as("SELECT o.value FROM TransactionOutputs o JOIN KeyInstances k ON k.keyinstance_id=o.keyinstance_id WHERE o.tx_hash=? AND o.tx_index=? AND o.keyinstance_id=? AND k.account_id=? AND (o.flags & ?) = 0")
            .bind(&hash).bind(input.tx_index as i64).bind(input.keyinstance_id).bind(account_id).bind(repositories::txo_flags::IS_SPENT)
            .fetch_optional(&mut *dbtx).await.map_err(|e| e.to_string())?;
        if exists.map(|v| v.0) != Some(i64::try_from(input.satoshis).map_err(|_| "input amount overflow")?) { return Err("UTXO changed during preparation".into()); }
        sqlx::query("INSERT INTO SpendReservations (tx_hash, tx_index, plan_id) VALUES (?, ?, ?)")
            .bind(hash).bind(input.tx_index as i64).bind(&plan_id).execute(&mut *dbtx).await.map_err(|e| format!("UTXO reservation failed: {e}"))?;
    }
    dbtx.commit().await.map_err(|e| e.to_string())?;
    prepared_instances().lock().unwrap().insert(plan_id.clone(), instance);
    log::info!("TX plan stored server-side — plan_id: {}", plan_id);

    Ok(PrepareTxResult {
        plan_id,
        fee,
        total_input,
        total_output,
        change,
        num_inputs,
        num_outputs,
    })
}

/// Sign a transaction plan.
///
/// AUD-007: Requires TOTP verification before signing.
/// The plan must belong to the current wallet (wallet_path binding).
/// AUD-008: The plan is fetched server-side by `plan_id` from the plan store
/// instead of being accepted as a parameter from the renderer. This prevents
/// a compromised renderer from tampering with inputs/outputs/fee.
pub async fn sign_tx(state: &AppState, plan_id: String, totp_code: String) -> Result<SignTxResult, String> {
    let _operation = state.wallet_operation.lock().await;
    let (pool, account_id, wallet_path, xprv) = get_wallet_data(state).map_err(|e| e.to_string())?;
    let xprv = xprv.ok_or(TransactionCmdError::WalletLocked.to_string())?;
    let instance = state.active_wallet.lock().unwrap().as_ref().ok_or("no wallet is currently open")?.instance_id.clone();
    let same = prepared_instances().lock().unwrap().get(&plan_id).is_some_and(|old| std::sync::Arc::ptr_eq(old, &instance));
    if !same { return Err("plan belongs to a previous wallet session or does not exist".into()); }
    let row: Option<(i64, String, String, i64, i64)> = sqlx::query_as("SELECT account_id, state, plan_json, fee_rate, expires_at FROM SpendPlans WHERE plan_id=?")
        .bind(&plan_id).fetch_optional(&pool).await.map_err(|e| e.to_string())?;
    let (plan_account, status, plan_json, fee_rate, expires_at) = row.ok_or("spend plan not found")?;
    if plan_account != account_id { return Err("plan account mismatch".into()); }
    if status != "PREPARED" { return Err(format!("plan is {status}")); }
    if chrono::Utc::now().timestamp() > expires_at { expire_prepared(&pool, chrono::Utc::now().timestamp()).await?; return Err("plan expired".into()); }
    let plan: TxPlan = serde_json::from_str(&plan_json).map_err(|e| e.to_string())?;
    if plan.wallet_path != wallet_path || plan.account_id != account_id { return Err("plan wallet mismatch".into()); }
    if crate::services::wallet_security::verify_sign_totp_locked(state, &_operation, &totp_code)?.is_none() {
        let secret = repositories::load_totp_secret(&pool).await.map_err(|e| e.to_string())?.ok_or("TOTP is not enabled")?;
        let totp = TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").map_err(|e| e.to_string())?;
        if !totp.verify_current(&totp_code).map_err(|e| e.to_string())? { return Err("TOTP verification failed".into()); }
    }
    let mut raw_prevouts = Vec::with_capacity(plan.inputs.len());
    for input in &plan.inputs {
        let hash = crate::core::address::hex_str_to_hash(&input.tx_hash_hex).map_err(|e| e.to_string())?;
        let row: Option<(i64, Option<String>, Option<Vec<u8>>, Vec<u8>, i32)> = sqlx::query_as(
            "SELECT o.value,o.script_pubkey,t.tx_data,k.derivation_data,k.derivation_type FROM TransactionOutputs o JOIN KeyInstances k ON k.keyinstance_id=o.keyinstance_id JOIN Transactions t ON t.tx_hash=o.tx_hash JOIN SpendReservations r ON r.tx_hash=o.tx_hash AND r.tx_index=o.tx_index WHERE o.tx_hash=? AND o.tx_index=? AND o.keyinstance_id=? AND k.account_id=? AND (o.flags & ?)=0 AND r.plan_id=?")
            .bind(hash).bind(input.tx_index as i64).bind(input.keyinstance_id).bind(account_id).bind(repositories::txo_flags::IS_SPENT).bind(&plan_id)
            .fetch_optional(&pool).await.map_err(|e| e.to_string())?;
        let (value, script, raw, derivation, typ) = row.ok_or("reserved UTXO unavailable")?;
        if value < 0 || value as u64 != input.satoshis || typ != repositories::derivation_type::BIP32 { return Err("reserved UTXO metadata changed".into()); }
        let derivation: serde_json::Value = serde_json::from_slice(&derivation).map_err(|e| e.to_string())?;
        if derivation.get("subpath") != Some(&serde_json::json!(input.subpath)) { return Err("reserved key path changed".into()); }
        let raw = raw.ok_or("previous transaction missing")?;
        crate::commands::network::validate_transaction_wire(&raw)?;
        let prev = bsv::transaction::transaction::Transaction::from_hex(&hex::encode(&raw)).map_err(|e| e.to_string())?;
        let output = prev.outputs.get(input.tx_index as usize).ok_or("previous output missing")?;
        if script.as_deref() != Some(hex::encode(output.locking_script.to_binary()).as_str()) { return Err("reserved UTXO script mismatch".into()); }
        raw_prevouts.push(raw);
    }
    crate::core::transaction::validate_plan_consistency(&plan).map_err(|e| e.to_string())?;
    let signer = LocalSigner::new(&xprv);
    signer.validate_prevouts(&plan.inputs, &raw_prevouts).map_err(|e| e.to_string())?;
    let mut tx = bsv::transaction::transaction::Transaction::from_hex(&plan.unsigned_tx_hex).map_err(|e| e.to_string())?;
    signer.sign_tx(&mut tx, &plan.inputs).map_err(|e| e.to_string())?;
    crate::core::signer::validate_signed_fee(&tx, &plan.inputs, u64::try_from(fee_rate).map_err(|_| "invalid fee rate")?).map_err(|e| e.to_string())?;
    let txid = tx.id().map_err(|e| e.to_string())?;
    let signed_tx_hex = tx.to_hex().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp();
    let done = sqlx::query("UPDATE SpendPlans SET state='SIGNED', signed_raw=?, txid=?, date_updated=? WHERE plan_id=? AND state='PREPARED' AND expires_at>=?")
        .bind(&signed_tx_hex).bind(&txid).bind(now).bind(&plan_id).bind(now).execute(&pool).await.map_err(|e| e.to_string())?;
    if done.rows_affected() != 1 { return Err("plan state changed during signing".into()); }
    prepared_instances().lock().unwrap().remove(&plan_id);
    Ok(SignTxResult { txid, signed_tx_hex })
}

pub async fn get_spend_plan_status(state: &AppState, plan_id: &str) -> Result<SpendPlanStatus, String> {
    let _operation = state.wallet_operation.lock().await;
    let (pool, account_id, _, _) = get_wallet_data(state).map_err(|e| e.to_string())?;
    expire_prepared(&pool, chrono::Utc::now().timestamp()).await?;
    let row: Option<(String, String, Option<String>)> = sqlx::query_as("SELECT plan_id, state, txid FROM SpendPlans WHERE plan_id=? AND account_id=?")
        .bind(plan_id).bind(account_id).fetch_optional(&pool).await.map_err(|e| e.to_string())?;
    let (plan_id, state, txid) = row.ok_or("spend plan not found")?;
    Ok(SpendPlanStatus { plan_id, state, txid })
}

pub async fn list_spend_plans(state: &AppState) -> Result<Vec<SpendPlanStatus>, String> {
    let _operation = state.wallet_operation.lock().await;
    let (pool, account_id, _, _) = get_wallet_data(state).map_err(|e| e.to_string())?;
    expire_prepared(&pool, chrono::Utc::now().timestamp()).await?;
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as("SELECT plan_id, state, txid FROM SpendPlans WHERE account_id=? AND state IN ('PREPARED','SIGNED','BROADCAST_UNKNOWN','BROADCASTED') ORDER BY date_updated DESC, plan_id")
        .bind(account_id).fetch_all(&pool).await.map_err(|e| e.to_string())?;
    Ok(rows.into_iter().map(|(plan_id, state, txid)| SpendPlanStatus { plan_id, state, txid }).collect())
}

pub async fn cancel_spend_plan(state: &AppState, plan_id: &str) -> Result<(), String> {
    let _operation = state.wallet_operation.lock().await;
    let (pool, account_id, _, _) = get_wallet_data(state).map_err(|e| e.to_string())?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let changed = sqlx::query("UPDATE SpendPlans SET state='CANCELLED', date_updated=? WHERE plan_id=? AND account_id=? AND state='PREPARED'")
        .bind(chrono::Utc::now().timestamp()).bind(plan_id).bind(account_id).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    if changed.rows_affected() != 1 { return Err("only a prepared plan can be cancelled".into()); }
    sqlx::query("DELETE FROM SpendReservations WHERE plan_id=?").bind(plan_id).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    prepared_instances().lock().unwrap().remove(plan_id);
    Ok(())
}

async fn broadcast_plan_with<F, Fut>(state: &AppState, plan_id: &str, expected_txid: &str, retry_unknown: bool, send: F) -> Result<String, String>
where F: FnOnce(Vec<u8>) -> Fut, Fut: std::future::Future<Output = Result<String, String>> {
    let operation = state.wallet_operation.lock().await;
    let (pool, account_id, _, _) = get_wallet_data(state).map_err(|e| e.to_string())?;
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as("SELECT state, signed_raw, txid FROM SpendPlans WHERE plan_id=? AND account_id=?")
        .bind(plan_id).bind(account_id).fetch_optional(&pool).await.map_err(|e| e.to_string())?;
    let (status, raw, id) = row.ok_or("spend plan not found")?;
    let id = id.ok_or("plan is not signed")?;
    let raw = raw.ok_or("signed transaction missing")?;
    if id != expected_txid { return Err("transaction id does not match plan".into()); }
    if status == "BROADCASTED" { return Ok(id); }
    if status != "SIGNED" && !(status == "BROADCAST_UNKNOWN" && retry_unknown) { return Err(format!("plan is {status}; explicit retry required for unknown outcome")); }
    let bytes = hex::decode(&raw).map_err(|e| e.to_string())?;
    crate::commands::network::validate_transaction_wire(&bytes)?;
    let parsed = bsv::transaction::transaction::Transaction::from_hex(&raw).map_err(|e| e.to_string())?;
    if parsed.id().map_err(|e| e.to_string())? != id || parsed.to_hex().map_err(|e| e.to_string())? != raw { return Err("stored signed transaction mismatch".into()); }
    if !in_flight_broadcasts().lock().unwrap().insert(plan_id.to_owned()) { return Err("broadcast already in progress".into()); }
    let _flight = BroadcastGuard(plan_id.to_owned());
    let updated = sqlx::query("UPDATE SpendPlans SET state='BROADCAST_UNKNOWN', date_updated=? WHERE plan_id=? AND account_id=? AND state=?")
        .bind(chrono::Utc::now().timestamp()).bind(plan_id).bind(account_id).bind(&status).execute(&pool).await.map_err(|e| e.to_string())?;
    if updated.rows_affected() != 1 { return Err("plan state changed before broadcast".into()); }
    drop(operation);
    let server_id = send(bytes).await?;
    if server_id != id { return Err("server returned different transaction id; broadcast outcome unknown".into()); }
    let updated = sqlx::query("UPDATE SpendPlans SET state='BROADCASTED', date_updated=? WHERE plan_id=? AND account_id=? AND state='BROADCAST_UNKNOWN'")
        .bind(chrono::Utc::now().timestamp()).bind(plan_id).bind(account_id).execute(&pool).await.map_err(|e| e.to_string())?;
    if updated.rows_affected() != 1 { return Err("broadcast accepted but plan state could not be recorded".into()); }
    Ok(id)
}

pub async fn broadcast_plan(state: &AppState, plan_id: &str, expected_txid: &str, retry_unknown: bool) -> Result<String, String> {
    broadcast_plan_with_status(state, plan_id, expected_txid, retry_unknown, get_spend_plan_status(state, plan_id)).await
}

async fn broadcast_plan_with_status<F>(state: &AppState, plan_id: &str, expected_txid: &str, retry_unknown: bool, status: F) -> Result<String, String>
where F: std::future::Future<Output = Result<SpendPlanStatus, String>> {
    let backend = state.network.lock().unwrap().selected_backend_snapshot();
    let status = status.await?;
    if status.state == "BROADCASTED" && status.txid.as_deref() == Some(expected_txid) { return Ok(expected_txid.to_string()); }
    let backend = backend.connected_backend().ok_or("not connected to a network backend")?;
    broadcast_plan_with(state, plan_id, expected_txid, retry_unknown, move |bytes| async move {
        backend.broadcast(&bytes).await.map_err(|e| e.to_string())
    }).await
}

pub async fn broadcast_tx(state: &AppState, signed_tx_hex: String, expected_txid: String) -> Result<String, String> {
    let (pool, account_id, _, _) = get_wallet_data(state).map_err(|e| e.to_string())?;
    let plan: Option<(String,)> = sqlx::query_as("SELECT plan_id FROM SpendPlans WHERE account_id=? AND signed_raw=? AND txid=?")
        .bind(account_id).bind(signed_tx_hex).bind(&expected_txid).fetch_optional(&pool).await.map_err(|e| e.to_string())?;
    let (plan_id,) = plan.ok_or("no matching signed plan")?;
    broadcast_plan(state, &plan_id, &expected_txid, false).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{account_service, wallet_service};
    use bsv::script::{spend::{Spend, SpendParams}, templates::{p2pkh::P2PKH, ScriptTemplateLock}};
    use bsv::transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn catalog_strategy_parser_preserves_names_default_and_errors() {
        use crate::core::coinchooser::STRATEGY_CATALOG;
        let expected = [
            ("largest_first", None),
            ("branch_and_bound", Some(Strategy::BranchAndBound)),
            ("random_subset", Some(Strategy::RandomSubset)),
            ("privacy", Some(Strategy::Privacy)),
        ];
        assert_eq!(parse_strategy(&None).unwrap(), None);
        assert_eq!(STRATEGY_CATALOG.len(), expected.len());
        let mut ids = std::collections::HashSet::new();
        for (entry, (id, strategy)) in STRATEGY_CATALOG.iter().zip(expected) {
            assert!(ids.insert(entry.id));
            assert_eq!((entry.id, entry.strategy), (id, strategy));
            assert_eq!(parse_strategy(&Some(entry.id.to_owned())).unwrap(), strategy);
        }
        for invalid in ["", " ", "privacy ", " privacy", "Privacy", "bogus"] {
            assert_eq!(parse_strategy(&Some(invalid.to_owned())).unwrap_err(), format!(
                "invalid coin_selection_strategy '{}': expected one of largest_first, branch_and_bound, random_subset, privacy", invalid));
        }
    }

    #[tokio::test]
    async fn ledger_prepare_sign_and_mock_broadcast_survives_reopen() {
        let mut state = AppState::new();
        let dir = std::env::temp_dir().join(format!("electrumsv-spend-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        state.data_dir = dir.to_str().unwrap().into();
        wallet_service::create_legacy_fixture(&state, "synthetic", "pw", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None).await.unwrap();
        let (pool, account, _, xprv) = get_wallet_data(&state).unwrap();
        let account_key = ExtendedKey::from_string(&xprv.unwrap()).unwrap();
        let child = account_key.derive("0/0").unwrap();
        let address = crate::core::address::pubkey_to_p2pkh_address(&child.public_key().unwrap());
        let script = P2PKH::from_address(&address).unwrap().lock().unwrap();
        let master = repositories::get_first_master_key(&pool).await.unwrap().unwrap();
        let key = repositories::insert_keyinstance(&pool, account, Some(master.masterkey_id), repositories::derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#, repositories::script_type::P2PKH, 0, None).await.unwrap();
        let mut funding = Transaction::new();
        funding.inputs.push(TransactionInput { source_txid: Some(hex::encode((0u8..32).collect::<Vec<_>>())), source_output_index: 1, ..Default::default() });
        funding.outputs.push(TransactionOutput { satoshis: Some(100_000), locking_script: script.clone(), change: false });
        let id = funding.id().unwrap();
        let hash = crate::core::address::hex_str_to_hash(&id).unwrap();
        let raw = hex::decode(funding.to_hex().unwrap()).unwrap();
        repositories::upsert_transaction(&pool, &hash, Some(10), Some(&raw)).await.unwrap();
        repositories::upsert_transaction_output(&pool, &hash, 0, 100_000, key, 0, Some(&hex::encode(script.to_binary()))).await.unwrap();
        let totp = TotpInstance::new("ElectrumSV-Mc", "wallet").unwrap();
        repositories::store_totp_secret(&pool, totp.secret_bytes()).await.unwrap();
        drop(pool);
        let dest = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();
        let payment = vec![PaymentOutput { address: dest, satoshis: 10_000 }];
        for invalid in ["", "Privacy", " privacy", "bogus"] {
            let error = prepare_tx(&state, payment.clone(), Some(1), None, Some(invalid.into())).await.unwrap_err();
            assert_eq!(error, format!("invalid coin_selection_strategy '{}': expected one of largest_first, branch_and_bound, random_subset, privacy", invalid));
        }
        let (pool, _, _, _) = get_wallet_data(&state).unwrap();
        let plans: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM SpendPlans").fetch_one(&pool).await.unwrap();
        let reservations: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM SpendReservations").fetch_one(&pool).await.unwrap();
        assert_eq!((plans.0, reservations.0), (0, 0));
        drop(pool);
        let (first, second) = tokio::join!(
            prepare_tx(&state, payment.clone(), Some(1), Some("hello".into()), None),
            prepare_tx(&state, payment.clone(), Some(1), Some("hello".into()), None));
        assert_ne!(first.is_ok(), second.is_ok());
        let prep = first.or(second).unwrap();
        let balance = account_service::get_balance(&state, None).await.unwrap();
        assert_eq!((balance.total, balance.reserved, balance.available), (100_000, 100_000, 0));
        assert!(prepare_tx(&state, payment, Some(1), None, None).await.is_err());
        assert!(sign_tx(&state, prep.plan_id.clone(), "invalid".into()).await.is_err());
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "PREPARED");
        let multisig = crate::commands::transactions::sign_multisig_tx(prep.plan_id.clone(), totp.generate_current().unwrap(), 0).await.unwrap_err();
        assert!(multisig.contains("not supported"));
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "PREPARED");
        let (pool, _, _, _) = get_wallet_data(&state).unwrap();
        let original: (String,) = sqlx::query_as("SELECT plan_json FROM SpendPlans WHERE plan_id=?").bind(&prep.plan_id).fetch_one(&pool).await.unwrap();
        let mut tampered: TxPlan = serde_json::from_str(&original.0).unwrap();
        tampered.outputs[0].satoshis += 1;
        sqlx::query("UPDATE SpendPlans SET plan_json=? WHERE plan_id=?").bind(serde_json::to_string(&tampered).unwrap()).bind(&prep.plan_id).execute(&pool).await.unwrap();
        drop(pool);
        assert!(sign_tx(&state, prep.plan_id.clone(), totp.generate_current().unwrap()).await.is_err());
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "PREPARED");
        let (pool, _, _, _) = get_wallet_data(&state).unwrap();
        sqlx::query("UPDATE SpendPlans SET plan_json=? WHERE plan_id=?").bind(original.0).bind(&prep.plan_id).execute(&pool).await.unwrap();
        drop(pool);
        let signed = sign_tx(&state, prep.plan_id.clone(), totp.generate_current().unwrap()).await.unwrap();
        assert!(sign_tx(&state, prep.plan_id.clone(), totp.generate_current().unwrap()).await.is_err());
        assert!(cancel_spend_plan(&state, &prep.plan_id).await.is_err());
        let tx = Transaction::from_hex(&signed.signed_tx_hex).unwrap();
        assert_eq!(tx.inputs[0].source_txid.as_deref(), Some(id.as_str()));
        let mut spend = Spend::new(SpendParams { locking_script: script, unlocking_script: tx.inputs[0].unlocking_script.clone().unwrap(),
            source_txid: id, source_output_index: 0, source_satoshis: 100_000, transaction_version: tx.version,
            transaction_lock_time: tx.lock_time, transaction_sequence: tx.inputs[0].sequence, other_inputs: vec![], other_outputs: tx.outputs.clone(), input_index: 0 });
        assert!(spend.validate().unwrap());
        let sent = tx.outputs.iter().map(|o| o.satoshis.unwrap()).sum::<u64>();
        assert!(100_000 - sent >= (signed.signed_tx_hex.len() / 2) as u64);
        {
            let mut net = state.network.lock().unwrap();
            net.connected = true;
            net.active_backend = None;
        }
        assert!(broadcast_plan(&state, &prep.plan_id, &signed.txid, false).await.is_err());
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "SIGNED");
        {
            let mut net = state.network.lock().unwrap();
            net.active_backend = Some(crate::network::backend::BackendType::ElectrumX);
            net.client = Some(crate::network::electrumx::ElectrumXClient::new(
                crate::network::server_list::ServerEntry::new("synthetic.invalid", 50002)));
        }
        assert!(broadcast_plan(&state, &prep.plan_id, &signed.txid, false).await.is_err());
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "SIGNED");
        let electrum = state.network.lock().unwrap().client.clone().unwrap();
        electrum.mark_test_connected();
        let (entered, wait) = tokio::sync::oneshot::channel();
        let (resume, resumed) = tokio::sync::oneshot::channel();
        let status = async {
            entered.send(()).unwrap(); resumed.await.unwrap();
            get_spend_plan_status(&state, &prep.plan_id).await
        };
        let (result, ()) = tokio::join!(
            broadcast_plan_with_status(&state, &prep.plan_id, &signed.txid, false, status),
            async { wait.await.unwrap(); electrum.disconnect().await.unwrap(); resume.send(()).unwrap(); }
        );
        assert_eq!(result.unwrap_err(), "not connected to a network backend");
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "SIGNED");
        state.network.lock().unwrap().connected = false;
        let (entered, wait) = tokio::sync::oneshot::channel();
        let (resume, resumed) = tokio::sync::oneshot::channel();
        let status = async {
            entered.send(()).unwrap(); resumed.await.unwrap();
            get_spend_plan_status(&state, &prep.plan_id).await
        };
        let (result, ()) = tokio::join!(
            broadcast_plan_with_status(&state, &prep.plan_id, &signed.txid, false, status),
            async { wait.await.unwrap(); electrum.mark_test_connected(); state.network.lock().unwrap().connected = true; resume.send(()).unwrap(); }
        );
        assert_eq!(result.unwrap_err(), "not connected to a network backend");
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "SIGNED");
        assert!(electrum.is_connected());
        electrum.disconnect().await.unwrap();
        state.network.lock().unwrap().woc_client = Some(crate::network::WhatsOnChainClient::with_base_url("http://[invalid"));
        let (entered, wait) = tokio::sync::oneshot::channel();
        let (resume, resumed) = tokio::sync::oneshot::channel();
        let status = async {
            entered.send(()).unwrap(); resumed.await.unwrap();
            get_spend_plan_status(&state, &prep.plan_id).await
        };
        let (result, ()) = tokio::join!(
            broadcast_plan_with_status(&state, &prep.plan_id, &signed.txid, false, status),
            async {
                wait.await.unwrap(); electrum.mark_test_connected();
                state.network.lock().unwrap().active_backend = Some(crate::network::BackendType::WhatsOnChain);
                resume.send(()).unwrap();
            }
        );
        assert_eq!(result.unwrap_err(), "no backend connected");
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "BROADCAST_UNKNOWN");
        state.network.lock().unwrap().active_backend = Some(crate::network::BackendType::ElectrumX);
        let balance = account_service::get_balance(&state, None).await.unwrap();
        assert_eq!((balance.reserved, balance.available), (100_000, 0));
        electrum.mark_test_connected();
        let retry_error = broadcast_plan(&state, &prep.plan_id, &signed.txid, false).await.unwrap_err();
        assert_eq!(retry_error, "plan is BROADCAST_UNKNOWN; explicit retry required for unknown outcome");
        assert!(electrum.is_connected(), "implicit retry must not enter transport");
        state.network.lock().unwrap().connected = false;
        assert!(broadcast_plan_with(&state, &prep.plan_id, &"ff".repeat(32), false, |_| async { panic!("bad txid broadcast") }).await.is_err());
        let calls = AtomicUsize::new(0);
        let attempt = broadcast_plan_with(&state, &prep.plan_id, &signed.txid, true, |_| async { calls.fetch_add(1, Ordering::SeqCst); Err("timeout".to_string()) }).await;
        assert!(attempt.is_err());
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "BROADCAST_UNKNOWN");
        assert!(broadcast_plan_with(&state, &prep.plan_id, &signed.txid, false, |_| async { panic!("implicit retry") }).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        wallet_service::close_wallet(&state).await.unwrap();
        wallet_service::open_wallet(&state, "synthetic").await.unwrap();
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "BROADCAST_UNKNOWN");
        let balance = account_service::get_balance(&state, None).await.unwrap();
        assert_eq!((balance.reserved, balance.available), (100_000, 0));
        let expected_bytes = hex::decode(&signed.signed_tx_hex).unwrap();
        let expected_copy = expected_bytes.clone();
        let wrong = broadcast_plan_with(&state, &prep.plan_id, &signed.txid, true, move |bytes| async move {
            assert_eq!(bytes, expected_copy);
            Ok("ff".repeat(32))
        }).await.unwrap_err();
        assert_eq!(wrong, "server returned different transaction id; broadcast outcome unknown");
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "BROADCAST_UNKNOWN");
        let balance = account_service::get_balance(&state, None).await.unwrap();
        assert_eq!((balance.reserved, balance.available), (100_000, 0));
        let server_id = signed.txid.clone();
        let result = broadcast_plan_with(&state, &prep.plan_id, &signed.txid, true, move |bytes| async move {
            assert_eq!(bytes, expected_bytes);
            Ok(server_id)
        }).await.unwrap();
        assert_eq!(result, signed.txid);
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "BROADCASTED");
        assert_eq!(broadcast_plan(&state, &prep.plan_id, &signed.txid, false).await.unwrap(), signed.txid);
        broadcast_plan_with(&state, &prep.plan_id, &signed.txid, false, |_| async { panic!("duplicate broadcast") }).await.unwrap();
        // Apply a synthetic server snapshot after acceptance, without any network access.
        let (pool, account, _, _) = get_wallet_data(&state).unwrap();
        let keys = repositories::get_keyinstances_for_account(&pool, account).await.unwrap();
        let change_key = keys.iter().find(|k| serde_json::from_slice::<serde_json::Value>(&k.derivation_data).unwrap()["subpath"] == serde_json::json!([1, 0])).unwrap();
        let change_address = crate::core::address::pubkey_to_p2pkh_address(&account_key.derive("1/0").unwrap().public_key().unwrap());
        let change_script = P2PKH::from_address(&change_address).unwrap().lock().unwrap();
        let (change_index, change_output) = tx.outputs.iter().enumerate().find(|(_, o)| o.locking_script.to_binary() == change_script.to_binary()).unwrap();
        let tx_hash = crate::core::address::hex_str_to_hash(&signed.txid).unwrap();
        let snapshots = keys.iter().map(|key_row| {
            let outputs = if key_row.keyinstance_id == change_key.keyinstance_id {
                vec![repositories::SyncOutput { hash: tx_hash.clone(), height: None, index: change_index as i64,
                    value: change_output.satoshis.unwrap() as i64, coinbase: false, script_pubkey: hex::encode(change_script.to_binary()) }]
            } else { vec![] };
            let delta = if key_row.keyinstance_id == change_key.keyinstance_id { change_output.satoshis.unwrap() as i64 } else { -100_000 };
            let transaction = repositories::SyncTransaction { hash: tx_hash.clone(), height: None,
                raw: hex::decode(&signed.signed_tx_hex).unwrap().into(), delta: Some(delta) };
            repositories::SyncKeySnapshot { key_id: key_row.keyinstance_id, transactions: vec![transaction], outputs }
        }).collect::<Vec<_>>();
        repositories::replace_sync_snapshot(&pool, account, &keys, None, &snapshots).await.unwrap();
        let refreshed = account_service::get_balance(&state, None).await.unwrap();
        assert_eq!(refreshed.total, change_output.satoshis.unwrap() as i64);
        assert_eq!(refreshed.available, refreshed.total);
        assert_eq!(refreshed.reserved, 0);
        let reservations: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM SpendReservations WHERE plan_id=?").bind(&prep.plan_id).fetch_one(&pool).await.unwrap();
        assert_eq!(reservations.0, 1);
        assert_eq!(repositories::get_utxos_for_account(&pool, account).await.unwrap().len(), 1);
        let mut confirmed_snapshots = snapshots;
        for item in &mut confirmed_snapshots {
            for tx in &mut item.transactions { tx.height = Some(20); }
            for output in &mut item.outputs { output.height = Some(20); }
        }
        repositories::replace_sync_snapshot(&pool, account, &keys, None, &confirmed_snapshots).await.unwrap();
        let confirmed = account_service::get_balance(&state, None).await.unwrap();
        assert_eq!((confirmed.confirmed, confirmed.unconfirmed, confirmed.available), (refreshed.total, 0, refreshed.total));
        let original_hash = crate::core::address::hex_str_to_hash(&funding.id().unwrap()).unwrap();
        let reorg = keys.iter().map(|k| repositories::SyncKeySnapshot {
            key_id: k.keyinstance_id,
            transactions: if k.keyinstance_id == key { vec![repositories::SyncTransaction { hash: original_hash.clone(), height: Some(10), raw: raw.clone().into(), delta: Some(100_000) }] } else { vec![] },
            outputs: if k.keyinstance_id == key { vec![repositories::SyncOutput { hash: original_hash.clone(), height: Some(10), index: 0, value: 100_000, coinbase: false, script_pubkey: hex::encode(funding.outputs[0].locking_script.to_binary()) }] } else { vec![] },
        }).collect::<Vec<_>>();
        repositories::replace_sync_snapshot(&pool, account, &keys, None, &reorg).await.unwrap();
        let reverted = account_service::get_balance(&state, None).await.unwrap();
        assert_eq!((reverted.total, reverted.reserved, reverted.available), (100_000, 100_000, 0));
        assert_eq!(get_spend_plan_status(&state, &prep.plan_id).await.unwrap().state, "BROADCASTED");
        repositories::replace_sync_snapshot(&pool, account, &keys, None, &confirmed_snapshots).await.unwrap();
        sqlx::query("UPDATE TransactionOutputs SET script_pubkey='' WHERE tx_hash=?").bind(&tx_hash).execute(&pool).await.unwrap();
        assert_eq!(account_service::get_balance(&state, None).await.unwrap().available, 0);
        sqlx::query("UPDATE TransactionOutputs SET script_pubkey=? WHERE tx_hash=?").bind(hex::encode(change_script.to_binary())).bind(&tx_hash).execute(&pool).await.unwrap();
        drop(pool);
        wallet_service::unlock_wallet_authorized(&state, "pw", Some(&totp.generate_current().unwrap())).await.unwrap();
        let p2 = prepare_tx(&state, vec![PaymentOutput { address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into(), satoshis: 1000 }], Some(1), None, None).await.unwrap();
        let (pool, _, _, _) = get_wallet_data(&state).unwrap();
        sqlx::query("UPDATE SpendPlans SET expires_at=0 WHERE plan_id=?").bind(&p2.plan_id).execute(&pool).await.unwrap();
        drop(pool);
        let after_expiry = account_service::get_balance(&state, None).await.unwrap();
        assert_eq!(after_expiry.reserved, 0);
        assert_eq!(after_expiry.available, refreshed.available);
        assert_eq!(get_spend_plan_status(&state, &p2.plan_id).await.unwrap().state, "EXPIRED");
        assert!(sign_tx(&state, p2.plan_id, totp.generate_current().unwrap()).await.is_err());
        let p3 = prepare_tx(&state, vec![PaymentOutput { address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into(), satoshis: 1000 }], Some(1), None, None).await.unwrap();
        wallet_service::close_wallet(&state).await.unwrap();
        wallet_service::open_wallet(&state, "synthetic").await.unwrap();
        wallet_service::unlock_wallet_authorized(&state, "pw", Some(&totp.generate_current().unwrap())).await.unwrap();
        assert!(sign_tx(&state, p3.plan_id.clone(), totp.generate_current().unwrap()).await.is_err());
        cancel_spend_plan(&state, &p3.plan_id).await.unwrap();
        wallet_service::close_wallet(&state).await.unwrap();
    }
}
