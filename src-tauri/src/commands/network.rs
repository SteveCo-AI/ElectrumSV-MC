// commands/network.rs — Network Tauri commands (Milestone 4)
//
// Provides: get_network_info, get_servers, connect_server, disconnect_server,
//           set_network_backend, sync_wallet
//
// These commands expose the network layer to the frontend. They interact with
// the NetworkState in AppState to manage server connections and retrieve
// blockchain data via the ElectrumX client.
//
// AUDIT:
// - AUD-006: broadcast_tx validation is enforced in the backend, not here.
// - AUD-Fund #6: TLS validation is enforced in the ElectrumXClient.
// - MutexGuard not Send: We extract data from locks before awaiting (same
//   pattern as commands/account.rs).

use crate::core::address;
use crate::db::repositories;
use crate::network::backend::{BackendType, NetworkBackend, NetworkError, ScriptHash};
use crate::network::electrumx::{ElectrumXClient, ScanResponseBudget};
use crate::network::header_store::{HeaderStore, ParsedHeader};
use crate::network::server_list::{ServerStatus, ServerStatusInfo};
use crate::state::AppState;
use crate::db::repositories::SyncKeyRef;
use bsv::compat::bip32::ExtendedKey;
use tauri::State;

// ============================================================================
// Response types
// ============================================================================

/// Network info returned by get_network_info.
#[derive(Debug, serde::Serialize)]
pub struct NetworkInfo {
    /// Whether any backend is currently connected.
    pub connected: bool,
    /// Active backend type ("electrumx" or "whatsonchain").
    pub backend_type: Option<String>,
    /// Active server host, if connected.
    pub active_server: Option<String>,
    /// Current chain tip height, if known.
    pub tip_height: Option<u64>,
    /// Total number of known servers.
    pub server_count: usize,
    /// Number of connected servers.
    pub connected_count: usize,
    /// Number of banned servers.
    pub banned_count: usize,
}

/// Server list entry returned by get_servers.
#[derive(Debug, serde::Serialize)]
pub struct ServerInfo {
    pub host: String,
    pub ssl_port: u16,
    pub tcp_port: Option<u16>,
    pub version: String,
    pub status: String,
    pub avg_latency_ms: Option<u64>,
    pub consecutive_failures: u32,
}

// ============================================================================
// Error type
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum NetworkCommandError {
    #[error("network error: {0}")]
    Network(#[from] NetworkError),
    #[error("no wallet is currently open")]
    NoWalletOpen,
    #[error("not connected to any server")]
    NotConnected,
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl serde::Serialize for NetworkCommandError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// ============================================================================
// Helper: extract network data without holding lock across awaits
// ============================================================================

/// Get server list snapshot and counts without holding the lock.
fn get_network_snapshot(state: &AppState) -> (Vec<ServerStatusInfo>, bool, usize, usize, usize) {
    let net = state.network.lock().unwrap();
    let info = net.server_list.list_with_status();
    let counts = net.server_list.count_by_status();
    (
        info,
        net.connected,
        counts.connected,
        counts.banned,
        net.server_list.len(),
    )
}

// ============================================================================
// Commands
// ============================================================================

/// Get current network status — server info, connection state, tip height.
///
/// Does not require an open wallet. Returns metadata about the network layer.
#[tauri::command]
pub async fn get_network_info(state: State<'_, AppState>) -> Result<NetworkInfo, String> {
    let (connected, connected_count, banned_count, total, active_server, backend_type) = {
        let net = state.network.lock().unwrap();
        let counts = net.server_list.count_by_status();
        let host = net.server_list.active().map(|s| s.host.clone());
        let bt = net.active_backend.map(|b| b.to_string());
        (net.connected && net.active_backend_snapshot().is_some(), counts.connected, counts.banned, net.server_list.len(), host, bt)
    };

    Ok(NetworkInfo {
        connected,
        backend_type,
        active_server,
        tip_height: None, // Updated when sync is implemented
        server_count: total,
        connected_count,
        banned_count,
    })
}

/// Get the list of known servers with their health status.
///
/// Does not require an open wallet or a connection.
#[tauri::command]
pub async fn get_servers(state: State<'_, AppState>) -> Result<Vec<ServerInfo>, String> {
    let (server_infos, _, _, _, _) = get_network_snapshot(&state);

    Ok(server_infos
        .into_iter()
        .map(|s| ServerInfo {
            host: s.host,
            ssl_port: s.ssl_port,
            tcp_port: s.tcp_port,
            version: s.version,
            status: format!("{:?}", s.status).to_lowercase(),
            avg_latency_ms: s.avg_latency_ms,
            consecutive_failures: s.consecutive_failures,
        })
        .collect())
}

/// Connect to a specific ElectrumX server by host name.
///
/// If no host is provided, selects the best available server.
/// Performs TLS handshake and server.version negotiation.
/// Also starts a background task to forward ElectrumX push notifications
/// to Tauri frontend events ("new_block", "balance_changed").
///
/// AUD-Fund #6: TLS certificate + hostname verification is enforced
/// in the ElectrumXClient. No permissive verifier is used.
#[tauri::command]
pub async fn connect_server(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    host: Option<String>,
) -> Result<String, String> {
    // Select server
    let server = {
        let net = state.network.lock().unwrap();
        match host {
            Some(h) => net
                .server_list
                .all()
                .iter()
                .find(|s| s.host == h)
                .cloned()
                .ok_or_else(|| format!("server not found: {h}"))?,
            None => net
                .server_list
                .select_best()
                .cloned()
                .ok_or_else(|| "no eligible servers available".to_string())?,
        }
    };

    let client = connect_explicit_server(&state, server).await?;
    let host = client.server_host();
    crate::commands::events::start_notification_forwarder(app, client);
    Ok(host)
}

pub async fn connect_explicit_server(
    state: &AppState,
    server: crate::network::server_list::ServerEntry,
) -> Result<ElectrumXClient, String> {
    log::info!("Connecting to ElectrumX server: {}", server.host);

    // Create client and connect
    let generation = state.network.lock().unwrap().begin_network_operation();
    let client = ElectrumXClient::new(server.clone());
    client
        .connect()
        .await
        .map_err(|e| format!("connection failed: {e}"))?;

    register_connected_server(state, &server, &client, generation)?;
    Ok(client)
}

#[cfg(test)]
pub(crate) async fn connect_explicit_server_with_test_roots(
    state: &AppState, server: crate::network::server_list::ServerEntry, roots: rustls::RootCertStore,
) -> Result<ElectrumXClient, String> {
    let generation = state.network.lock().unwrap().begin_network_operation();
    let client = ElectrumXClient::new(server.clone());
    client.connect_with_test_roots(roots).await.map_err(|e| format!("connection failed: {e}"))?;
    register_connected_server(state, &server, &client, generation)?;
    Ok(client)
}

fn register_connected_server(state: &AppState, server: &crate::network::server_list::ServerEntry, client: &ElectrumXClient, generation: u64) -> Result<(), String> {
    let old = {
        let mut net = state.network.lock().unwrap();
        if !net.is_current_network_operation(generation) || net.server_list.status(&server.host) == ServerStatus::Banned || !client.is_connected() {
            crate::network::service::cleanup((Some(client.clone()), None));
            return Err("connection superseded, banned or closed".into());
        }
        let old = net.take_active_network();
        net.server_list.record_success(&server.host, 0);
        net.connected = true;
        net.client = Some(client.clone());
        net.active_backend = Some(BackendType::ElectrumX);
        old
    };
    crate::network::service::cleanup(old);

    log::info!("Connected to {}", server.host);
    Ok(())
}

/// Disconnect from the current server.
#[tauri::command]
pub async fn disconnect_server(state: State<'_, AppState>) -> Result<(), String> {
    disconnect_server_inner(&state).await
}

pub async fn disconnect_server_inner(state: &AppState) -> Result<(), String> {
    let old = {
        let mut net = state.network.lock().unwrap();
        net.clear_active_network()
    };
    crate::network::service::cleanup(old);
    Ok(())
}

/// Set the network backend type (ElectrumX or WhatsOnChain).
///
/// Switches between the ElectrumX TCP+TLS protocol and the WhatsOnChain
/// REST API. When switching to WhatsOnChain, creates a new WoC client and
/// pings it to verify connectivity. When switching to ElectrumX, clears
/// the WoC client — the user must call connect_server to establish a new
/// ElectrumX connection.
#[tauri::command]
pub async fn set_network_backend(
    state: State<'_, AppState>,
    backend_type: String,
) -> Result<(), String> {
    match backend_type.as_str() {
        "electrumx" => {
            let mut net = state.network.lock().unwrap();
            net.begin_network_operation();
            if net.active_backend == Some(BackendType::ElectrumX) && net.client.is_some() {
                return Ok(());
            }
            let old = net.take_active_network();
            net.active_backend = Some(BackendType::ElectrumX);
            drop(net);
            crate::network::service::cleanup(old);
            log::info!("Network backend set to ElectrumX");
            Ok(())
        }
        "whatsonchain" => {
            let generation = state.network.lock().unwrap().begin_network_operation();
            let woc = crate::network::whatsonchain::WhatsOnChainClient::new();
            // Ping to verify connectivity
            woc.ping()
                .await
                .map_err(|e| format!("WhatsOnChain backend connection failed: {e}"))?;

            let mut net = state.network.lock().unwrap();
            if !net.is_current_network_operation(generation) {
                return Err("backend selection superseded".into());
            }
            let old = net.take_active_network();
            net.woc_client = Some(woc);
            net.active_backend = Some(BackendType::WhatsOnChain);
            // If an ElectrumX client is active, disconnect it
            net.connected = true;
            drop(net);
            crate::network::service::cleanup(old);
            log::info!("Network backend set to WhatsOnChain");
            Ok(())
        }
        other => Err(format!("unknown backend type: {other}")),
    }
}

/// Trigger a wallet sync — fetch balance, history, and UTXOs from the server.
///
/// Requires an open wallet with KeyInstances and a connected ElectrumX server.
///
/// Sync flow:
/// 1. Load all KeyInstances for the active account from DB
/// 2. For each KeyInstance, derive the public key from the xprv and compute
///    the ElectrumX scripthash
/// 3. For each scripthash, fetch get_balance, get_history, get_utxos from server
/// 4. Store results in DB (Transactions, TransactionOutputs, TransactionDeltas)
/// 5. Subscribe to scripthash updates for push notifications
///
/// Returns a SyncResult with counts of synced keys and transactions.
type RawTransactionCache = std::collections::HashMap<String, Option<(Vec<u8>, bsv::transaction::transaction::Transaction)>>;
const MAX_SYNC_TX_REQUESTS: usize = 4096;
const MAX_SYNC_HISTORY_ENTRIES: usize = 100_000;
const MAX_SYNC_RAW_BYTES: usize = 64 * 1024 * 1024;
const MAX_SYNC_TX_BYTES: usize = 4 * 1024 * 1024;
const MAX_SCAN_OUTPUTS: usize = 100_000;
const SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
static SYNC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn bounded<F, T>(deadline: Option<tokio::time::Instant>, future: F) -> Result<T, String>
where F: std::future::Future<Output = Result<T, String>> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, future).await.map_err(|_| "scan deadline exceeded".to_string())?,
        None => future.await,
    }
}

// Check wire lengths before the SDK allocates vectors from untrusted varints.
pub(crate) use crate::core::transaction::validate_transaction_wire;

async fn fetch_sync_transaction(client: &ElectrumXClient, txid: &str, cache: &mut RawTransactionCache, total_bytes: &mut usize, optional: bool, budget: Option<&std::sync::Arc<ScanResponseBudget>>)
    -> Result<Option<(Vec<u8>, bsv::transaction::transaction::Transaction)>, String> {
    fetch_sync_transaction_with(txid, cache, total_bytes, optional, |key| async move {
        client.call_with_budget("blockchain.transaction.get", serde_json::json!([key, false]), budget.cloned()).await
    }).await
}

async fn fetch_sync_transaction_with<F, Fut>(txid: &str, cache: &mut RawTransactionCache, total_bytes: &mut usize, optional: bool, fetch: F)
    -> Result<Option<(Vec<u8>, bsv::transaction::transaction::Transaction)>, String>
where F: FnOnce(String) -> Fut, Fut: std::future::Future<Output = Result<serde_json::Value, NetworkError>> {
    let key = txid.to_ascii_lowercase();
    if let Some(value) = cache.get(&key) { return Ok(value.clone()); }
    if cache.len() >= MAX_SYNC_TX_REQUESTS { return Err("sync transaction request limit exceeded".into()); }
    let value = match fetch(key.clone()).await {
        Ok(value) => value,
        Err(NetworkError::NotFound(_)) if optional => { cache.insert(key, None); return Ok(None); }
        Err(error) => return Err(format!("transaction fetch failed: {error}")),
    };
    if value.is_null() && optional { cache.insert(key, None); return Ok(None); }
    let raw = value.as_str().ok_or("server returned invalid transaction data")?;
    if raw.len() > MAX_SYNC_TX_BYTES * 2 || raw.len() % 2 != 0 { return Err("transaction size limit exceeded or invalid hex".into()); }
    let bytes = hex::decode(raw).map_err(|e| format!("invalid transaction hex: {e}"))?;
    *total_bytes = total_bytes.checked_add(bytes.len()).ok_or("sync transaction size overflow")?;
    if *total_bytes > MAX_SYNC_RAW_BYTES { return Err("sync transaction byte limit exceeded".into()); }
    validate_transaction_wire(&bytes)?;
    let parsed = bsv::transaction::transaction::Transaction::from_hex(raw).map_err(|e| format!("invalid transaction: {e}"))?;
    if !parsed.id().map_err(|e| e.to_string())?.eq_ignore_ascii_case(&key) ||
        parsed.to_hex().map_err(|e| e.to_string())? != hex::encode(&bytes) { return Err("transaction hash or encoding mismatch".into()); }
    let result = Some((bytes, parsed));
    cache.insert(key, result.clone());
    Ok(result)
}

fn calculate_history_values(
    tx: &bsv::transaction::transaction::Transaction,
    wallet_scripts: &std::collections::HashMap<String, SyncKeyRef>,
    parents: &RawTransactionCache,
) -> Result<(std::collections::HashMap<SyncKeyRef, i64>, bool), String> {
    let mut amounts: std::collections::HashMap<SyncKeyRef, i64> = std::collections::HashMap::new();
    for output in &tx.outputs {
        let hash = crate::network::backend::scripthash_from_script(&hex::encode(output.locking_script.to_binary())).map_err(|e| e.to_string())?;
        if let Some(key) = wallet_scripts.get(&hash) {
            let value = i64::try_from(output.satoshis.ok_or("missing output amount")?).map_err(|_| "output amount overflow")?;
            let amount = amounts.entry(*key).or_default();
            *amount = amount.checked_add(value).ok_or("history delta overflow")?;
        }
    }
    let mut complete = true;
    for input in &tx.inputs {
        let previous = input.source_txid.as_deref().ok_or("missing previous txid")?;
        if input.source_output_index == u32::MAX && previous.bytes().all(|b| b == b'0') { continue; }
        let Some(Some((_, prev_tx))) = parents.get(&previous.to_ascii_lowercase()) else { complete = false; continue; };
        let output = prev_tx.outputs.get(input.source_output_index as usize).ok_or("previous output index out of range")?;
        let hash = crate::network::backend::scripthash_from_script(&hex::encode(output.locking_script.to_binary())).map_err(|e| e.to_string())?;
        if let Some(key) = wallet_scripts.get(&hash) {
            let value = i64::try_from(output.satoshis.ok_or("missing previous output amount")?).map_err(|_| "previous output amount overflow")?;
            let amount = amounts.entry(*key).or_default();
            *amount = amount.checked_sub(value).ok_or("history delta overflow")?;
        }
    }
    Ok((amounts, complete))
}

fn validate_utxo_history(transactions: &[repositories::SyncTransaction], outputs: &[repositories::SyncOutput]) -> Result<(), String> {
    let hashes: std::collections::HashSet<&[u8]> = transactions.iter().map(|item| item.hash.as_slice()).collect();
    if outputs.iter().any(|output| !hashes.contains(output.hash.as_slice())) {
        return Err("server UTXO missing from address history".into());
    }
    Ok(())
}

fn validate_history_membership(amounts: &std::collections::HashMap<SyncKeyRef, i64>, owners: &std::collections::HashSet<SyncKeyRef>, complete: bool) -> Result<(), String> {
    if amounts.keys().any(|key| !owners.contains(key)) {
        return Err("server history omitted a wallet key involved in a transaction".into());
    }
    if complete && owners.iter().any(|key| !amounts.contains_key(key)) {
        return Err("server history contains an unrelated transaction".into());
    }
    Ok(())
}

async fn resolve_sync_history<F, Fut>(
    snapshots: &mut [repositories::SyncKeySnapshot], wallet_scripts: &std::collections::HashMap<String, SyncKeyRef>,
    tx_cache: &mut RawTransactionCache, raw_bytes: &mut usize, mut fetch: F,
) -> Result<(), String>
where F: FnMut(String) -> Fut, Fut: std::future::Future<Output = Result<serde_json::Value, NetworkError>> {
    let mut resolved = std::collections::HashMap::new();
    for snapshot in snapshots.iter() {
        for item in &snapshot.transactions {
            let id = crate::core::address::hash_to_hex_str(&item.hash);
            if resolved.contains_key(&id) { continue; }
            let (raw, tx) = fetch_sync_transaction_with(&id, tx_cache, raw_bytes, false, |key| fetch(key))
                .await?.ok_or("history transaction unavailable")?;
            for input in &tx.inputs {
                let previous = input.source_txid.as_deref().ok_or("missing previous txid")?;
                if input.source_output_index == u32::MAX && previous.bytes().all(|b| b == b'0') { continue; }
                fetch_sync_transaction_with(previous, tx_cache, raw_bytes, true, |key| fetch(key)).await?;
            }
            let (amounts, complete) = calculate_history_values(&tx, wallet_scripts, tx_cache)?;
            resolved.insert(id, (std::sync::Arc::<[u8]>::from(raw), amounts, complete));
        }
    }
    let mut listed: std::collections::HashMap<String, std::collections::HashSet<SyncKeyRef>> = std::collections::HashMap::new();
    for snapshot in snapshots.iter() {
        for item in &snapshot.transactions {
            listed.entry(crate::core::address::hash_to_hex_str(&item.hash)).or_default().insert(snapshot.key_id);
        }
    }
    for (id, (_, amounts, complete)) in &resolved {
        let owners = listed.get(id).ok_or("missing history membership")?;
        validate_history_membership(amounts, owners, *complete)?;
    }
    for snapshot in snapshots.iter_mut() {
        for item in &mut snapshot.transactions {
            let id = crate::core::address::hash_to_hex_str(&item.hash);
            let (raw, amounts, complete) = resolved.get(&id).ok_or("missing resolved transaction")?;
            item.raw = std::sync::Arc::clone(raw);
            item.delta = complete.then(|| *amounts.get(&snapshot.key_id).unwrap_or(&0));
        }
    }

    Ok(())
}

async fn discover_used_keys(client: &ElectrumXClient, pool: &sqlx::SqlitePool, account_id: i64, account_key: &ExtendedKey, keys: &[repositories::KeyInstanceRow]) -> Result<Option<Vec<(u64, u64)>>, String> {
    if keys.iter().any(|key| key.derivation_type != repositories::derivation_type::BIP32) {
        return Err("imported keys are not supported in synchronization".into());
    }
    let marker = format!("address_discovery_v1_{account_id}");
    if repositories::get_wallet_data(pool, &marker).await.map_err(|e| e.to_string())?.is_some() { return Ok(None); }
    let mut known = std::collections::HashSet::new();
    for key in keys {
        if key.derivation_type != repositories::derivation_type::BIP32 { return Err("imported keys are not supported in synchronization".into()); }
        let v: serde_json::Value = serde_json::from_slice(&key.derivation_data).map_err(|e| e.to_string())?;
        let path = v.get("subpath").and_then(|v| v.as_array()).ok_or("invalid key path")?;
        let chain = path.first().and_then(|v| v.as_u64()).ok_or("invalid chain")?;
        let index = path.get(1).and_then(|v| v.as_u64()).ok_or("invalid index")?;
        known.insert((chain, index));
    }
    let mut found = Vec::new();
    for chain in 0u64..=1 {
        let known_max = known.iter().filter(|(c, _)| *c == chain).map(|(_, i)| *i).max();
        let mut gap = 0;
        let mut completed = false;
        for index in 0u64..10_000 {
            let child = account_key.derive(&format!("{chain}/{index}")).map_err(|e| e.to_string())?;
            let public = child.public_key().map_err(|e| e.to_string())?;
            let addr = address::pubkey_to_p2pkh_address(&public);
            let hash = crate::network::backend::scripthash_from_address(&addr).map_err(|e| e.to_string())?;
            let target = ScriptHash::try_from(hash.as_str()).map_err(|e| e.to_string())?;
            let used = !client.get_history(&target).await.map_err(|e| format!("address discovery failed: {e}"))?.is_empty();
            if used && !known.contains(&(chain, index)) { found.push((chain, index)); }
            if used || known.contains(&(chain, index)) { gap = 0; } else { gap += 1; }
            if gap >= 20 && known_max.is_none_or(|max| index > max) { completed = true; break; }
        }
        if !completed { return Err("address discovery reached its safety limit".into()); }
    }
    Ok(Some(found))
}

async fn discover_explicit_range(client: &ElectrumXClient, account_key: &ExtendedKey, keys: &[repositories::KeyInstanceRow], end: u32, deadline: tokio::time::Instant, budget: &std::sync::Arc<ScanResponseBudget>) -> Result<(Vec<(u64,u64)>, usize), String> {
    discover_explicit_range_with(account_key, keys, end, Some(deadline), |target| async move {
        client.get_history_with_budget(&target, Some(budget)).await.map_err(|e| format!("address discovery failed: {e}"))
    }).await
}

async fn discover_explicit_range_with<F, Fut>(account_key: &ExtendedKey, keys: &[repositories::KeyInstanceRow], end: u32, deadline: Option<tokio::time::Instant>, mut fetch: F) -> Result<(Vec<(u64,u64)>, usize), String>
where F: FnMut(ScriptHash) -> Fut, Fut: std::future::Future<Output = Result<Vec<crate::network::backend::TxHistoryEntry>, String>> {
    if !(1..=1000).contains(&end) { return Err("end_index_exclusive must be between 1 and 1000".into()); }
    let mut known = std::collections::HashSet::new();
    for key in keys {
        if key.derivation_type != repositories::derivation_type::BIP32 { return Err("imported keys are not supported in synchronization".into()); }
        let value: serde_json::Value = serde_json::from_slice(&key.derivation_data).map_err(|e| e.to_string())?;
        let path = value.get("subpath").and_then(|v| v.as_array()).ok_or("invalid key path")?;
        let chain = path.first().and_then(|v| v.as_u64()).ok_or("invalid chain")?;
        let index = path.get(1).and_then(|v| v.as_u64()).ok_or("invalid index")?;
        if !known.insert((chain,index)) { return Err("duplicate existing derivation path".into()); }
    }
    let mut found = Vec::new();
    let mut history_count = 0usize;
    for chain in 0..=1u64 {
        for index in 0..u64::from(end) {
            if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) { return Err("scan deadline exceeded".into()); }
            let child = account_key.derive(&format!("{chain}/{index}")).map_err(|e| e.to_string())?;
            let public = child.public_key().map_err(|e| e.to_string())?;
            let address = address::pubkey_to_p2pkh_address(&public);
            let hash = crate::network::backend::scripthash_from_address(&address).map_err(|e| e.to_string())?;
            let target = ScriptHash::try_from(hash.as_str()).map_err(|e| e.to_string())?;
            let history = fetch(target).await?;
            history_count = history_count.checked_add(history.len()).ok_or("scan history count overflow")?;
            if history_count > MAX_SYNC_HISTORY_ENTRIES { return Err("scan history entry limit exceeded".into()); }
            if !history.is_empty() && !known.contains(&(chain,index)) { found.push((chain,index)); }
        }
    }
    Ok((found,history_count))
}

#[derive(Debug, serde::Serialize)]
pub struct ExplicitScanResult {
    pub start_index: u32,
    pub end_index_exclusive: u32,
    pub new_keys: usize,
    pub server_host: String,
}

fn require_scan_wallet_session(state: &AppState, instance: &std::sync::Arc<()>, account_id: i64, token: Option<&str>) -> Result<(), String> {
    let active = state.active_wallet.lock().unwrap();
    if !active.as_ref().is_some_and(|wallet| std::sync::Arc::ptr_eq(&wallet.instance_id, instance)
        && wallet.account_id == account_id && token.is_none_or(|token| token == wallet.instance_token)) {
        return Err("active wallet changed during synchronization".into());
    }
    Ok(())
}

fn require_matching_scan_source(account_key: &ExtendedKey, source: &repositories::ScanDerivationSource) -> Result<(), String> {
    let record: serde_json::Value = serde_json::from_slice(&source.master.derivation_data).map_err(|_| "invalid scan derivation source")?;
    let xpub = account_key.to_public().map_err(|_| "invalid scan derivation source")?.to_base58();
    if source.master.derivation_type != repositories::derivation_type::BIP32 || record.get("xpub").and_then(|v| v.as_str()) != Some(xpub.as_str()) {
        return Err("scan derivation source does not match active wallet".into());
    }
    Ok(())
}

pub async fn scan_address_range_inner(state: &AppState, account_id: i64, wallet_instance_token: &str, end_index_exclusive: u32) -> Result<ExplicitScanResult, String> {
    if !(1..=1000).contains(&end_index_exclusive) { return Err("end_index_exclusive must be between 1 and 1000".into()); }
    let deadline = tokio::time::Instant::now() + SCAN_TIMEOUT;
    let (result, new_keys) = sync_wallet_impl(state, Some(account_id), Some(wallet_instance_token), Some((end_index_exclusive, deadline))).await?;
    Ok(ExplicitScanResult { start_index: 0, end_index_exclusive, new_keys, server_host: result.server_host })
}

#[tauri::command]
pub async fn scan_address_range(
    state: State<'_, AppState>,
    account_id: i64,
    wallet_instance_token: String,
    end_index_exclusive: u32,
) -> Result<ExplicitScanResult, String> {
    scan_address_range_inner(&state, account_id, &wallet_instance_token, end_index_exclusive).await
}

#[tauri::command]
pub async fn sync_wallet(
    state: State<'_, AppState>,
    account_id: Option<i64>,
    wallet_instance_token: Option<String>,
) -> Result<SyncResult, String> {
    sync_wallet_with_token_inner(&state, account_id, wallet_instance_token.as_deref()).await
}

pub async fn sync_wallet_inner(state: &AppState, account_id: Option<i64>) -> Result<SyncResult, String> {
    sync_wallet_with_token_inner(state, account_id, None).await
}

pub async fn sync_wallet_with_token_inner(state: &AppState, account_id: Option<i64>, wallet_instance_token: Option<&str>) -> Result<SyncResult, String> {
    if wallet_instance_token.is_some_and(str::is_empty) { return Err("wallet instance token is empty".into()); }
    Ok(sync_wallet_impl(state, account_id, wallet_instance_token, None).await?.0)
}

async fn sync_wallet_impl(state: &AppState, account_id: Option<i64>, wallet_instance_token: Option<&str>, scan: Option<(u32,tokio::time::Instant)>) -> Result<(SyncResult,usize), String> {
    // Serialize synchronization across wallets; no state mutex is held over network I/O.
    let deadline = scan.map(|(_,deadline)| deadline);
    let response_budget = scan.map(|_| std::sync::Arc::new(ScanResponseBudget::new(64 * 1024 * 1024)));
    let _sync_guard = bounded(deadline, async { Ok(SYNC_LOCK.lock().await) }).await?;
    let context_guard = if wallet_instance_token.is_some() { Some(bounded(deadline, async { Ok(state.wallet_operation.lock().await) }).await?) } else { None };
    // 1. Extract client from network state (without holding lock across awaits)
    let client = {
        let net = state.network.lock().unwrap();
        if !net.connected {
            return Err("not connected to any server — call connect_server first".to_string());
        }
        net.client
            .clone()
            .ok_or_else(|| "no active client — call connect_server first".to_string())?
    };

    // 2. Extract wallet data (pool, account_id, xprv)
    let (pool, default_acct_id, xprv_opt, wallet_path, wallet_instance) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        if wallet_instance_token.is_some_and(|token| token != active.instance_token) { return Err("active wallet token changed".into()); }
        (
            active.db_pool.clone(),
            active.account_id,
            active.decrypted_xprv.clone(),
            active.wallet_path.clone(),
            active.instance_id.clone(),
        )
    };
    let acct_id = account_id.unwrap_or(default_acct_id);

    // Wallet must be unlocked for key derivation
    let xprv_str =
        xprv_opt.ok_or("wallet is locked — unlock first to derive public keys for sync")?;

    if scan.is_none() { log::info!("sync_wallet: account {} — starting full sync", acct_id); }
    else { log::info!("explicit address scan: account {acct_id}"); }

    if acct_id != default_acct_id { return Err("only the active account can be synchronized".into()); }
    let account_key = ExtendedKey::from_string(&xprv_str).map_err(|e| format!("invalid xprv: {e}"))?;
    let source = if scan.is_some() {
        let source = bounded(deadline, async { repositories::load_scan_derivation_source(&pool, acct_id).await.map_err(|_| "scan derivation source unavailable".to_string()) }).await?;
        require_matching_scan_source(&account_key, &source)?;
        Some(source)
    } else { None };
    drop(context_guard);
    let expected_keys = bounded(deadline, async {
        let result = if scan.is_some() { repositories::get_keyinstances_for_account_bounded(&pool, acct_id, 100_000).await }
            else { repositories::get_keyinstances_for_account(&pool, acct_id).await };
        result.map_err(|e| format!("failed to load keyinstances: {e}"))
    }).await?;
    if let Some((end,scan_deadline)) = scan {
        repositories::validate_scan_inventory(source.as_ref().ok_or("missing scan derivation source")?, &expected_keys, &[], end, scan_deadline)
            .map_err(|e| format!("unsupported scan inventory: {e}"))?;
    }
    let (discovered, discovery_history_count) = if let Some((end, scan_deadline)) = scan {
        let budget = response_budget.as_ref().ok_or("missing scan response budget")?;
        let (found,count) = bounded(deadline, discover_explicit_range(&client, &account_key, &expected_keys, end, scan_deadline, budget)).await?;
        (Some(found),count)
    } else {
        (discover_used_keys(&client, &pool, acct_id, &account_key, &expected_keys).await?,0)
    };
    let new_keys = discovered.as_ref().map_or(0, Vec::len);
    let mut key_instances: Vec<(SyncKeyRef, Vec<u8>)> = expected_keys.iter()
        .map(|key| (SyncKeyRef::Existing(key.keyinstance_id), key.derivation_data.clone())).collect();
    if let Some(paths) = &discovered {
        for (index, (chain, child)) in paths.iter().enumerate() {
            key_instances.push((SyncKeyRef::Discovered(index),
                serde_json::json!({"subpath": [chain, child]}).to_string().into_bytes()));
        }
    }

    if key_instances.is_empty() && scan.is_none() {
        log::warn!("sync_wallet: no keyinstances found for account {} — generating initial receiving addresses", acct_id);
        return Ok((SyncResult {
            server_host: client.server_host(),
            account_id: acct_id,
            synced: false,
            message: "no keyinstances found — generate receive addresses first".to_string(),
        },new_keys));
    }

    // 4. For each KeyInstance: derive pubkey → compute scripthash → fetch from server
    let mut total_balance_confirmed: u64 = 0;
    let mut total_balance_unconfirmed: i64 = 0;
    let mut total_tx_count: usize = discovery_history_count;
    let mut total_utxo_count: usize = 0;
    let mut synced_keys: usize = 0;
    let mut snapshots = Vec::new();
    let mut heights = std::collections::HashMap::new();
    let mut outpoints = std::collections::HashSet::new();
    let mut wallet_scripts = std::collections::HashMap::new();
    let mut tx_cache = RawTransactionCache::new();
    let mut raw_bytes = 0usize;

    for (key_ref, derivation_bytes) in &key_instances {
        // Parse derivation_data to get subpath
        let derivation_data: serde_json::Value = serde_json::from_slice(derivation_bytes)
            .map_err(|e| {
                format!(
                    "invalid derivation_data for keyinstance {:?}: {e}",
                    key_ref
                )
            })?;

        let subpath = derivation_data
            .get("subpath")
            .and_then(|s| s.as_array())
            .ok_or_else(|| {
                format!(
                    "missing subpath in derivation_data for keyinstance {:?}",
                    key_ref
                )
            })?;

        let type_idx = subpath
            .first()
            .and_then(|t| t.as_i64())
            .ok_or("invalid subpath type index")?;
        let addr_idx = subpath
            .get(1)
            .and_then(|t| t.as_i64())
            .ok_or("invalid subpath address index")?;

        // Derive the child key at {type_idx}/{addr_idx}
        let derivation_path = format!("{}/{}", type_idx, addr_idx);
        let child_key = account_key.derive(&derivation_path).map_err(|e| {
            format!(
                "derivation failed for keyinstance {:?}: {e}",
                key_ref
            )
        })?;

        let pubkey = child_key.public_key().map_err(|e| {
            format!(
                "public key derivation failed for keyinstance {:?}: {e}",
                key_ref
            )
        })?;

        // Compute the P2PKH address
        let addr_str = address::pubkey_to_p2pkh_address(&pubkey);

        // Compute the ElectrumX scripthash
        let scripthash =
            crate::network::backend::scripthash_from_address(&addr_str).map_err(|e| {
                format!(
                    "scripthash computation failed for keyinstance {:?}: {e}",
                    key_ref
                )
            })?;

        let target = ScriptHash::try_from(scripthash.as_str()).map_err(|e| e.to_string())?;
        if wallet_scripts.insert(scripthash.clone(), *key_ref).is_some() {
            return Err("duplicate wallet script".into());
        }

        log::debug!(
            "sync_wallet: keyinstance {:?} — address {} — scripthash {}",
            key_ref,
            addr_str,
            scripthash
        );

        // Fetch balance from server
        let balance = match bounded(deadline, async { client.get_balance_with_budget(&target, response_budget.as_ref()).await.map_err(|e| e.to_string()) }).await {
            Ok(b) => b,
            Err(e) => return Err(format!("keyinstance {:?}: balance error: {e}", key_ref)),
        };

        total_balance_confirmed = total_balance_confirmed.checked_add(balance.confirmed).ok_or("confirmed balance overflow")?;
        total_balance_unconfirmed = total_balance_unconfirmed.checked_add(balance.unconfirmed).ok_or("unconfirmed balance overflow")?;

        // Fetch history from server
        let history = match bounded(deadline, async { client.get_history_with_budget(&target, response_budget.as_ref()).await.map_err(|e| e.to_string()) }).await {
            Ok(h) => h,
            Err(e) => return Err(format!("keyinstance {:?}: history error: {e}", key_ref)),
        };

        total_tx_count = total_tx_count.checked_add(history.len()).ok_or("history entry count overflow")?;
        if total_tx_count > MAX_SYNC_HISTORY_ENTRIES { return Err("sync history entry limit exceeded".into()); }
        let mut history_ids = std::collections::HashSet::new();
        if history.iter().any(|item| !history_ids.insert(item.tx_hash.to_ascii_lowercase())) {
            return Err("duplicate history transaction".into());
        }

        // Fetch UTXOs from server
        let utxos = match bounded(deadline, async { client.get_utxos_with_budget(&target, response_budget.as_ref()).await.map_err(|e| e.to_string()) }).await {
            Ok(u) => u,
            Err(e) => return Err(format!("keyinstance {:?}: utxos error: {e}", key_ref)),
        };
        total_utxo_count = total_utxo_count.checked_add(utxos.len()).ok_or("output count overflow")?;
        if scan.is_some() && total_utxo_count > MAX_SCAN_OUTPUTS { return Err("scan output limit exceeded".into()); }

        let mut coinbase_txids = std::collections::HashSet::new();
        let mut output_scripts = Vec::with_capacity(utxos.len());
        for utxo in &utxos {
            let (_, parsed) = bounded(deadline, fetch_sync_transaction(&client, &utxo.tx_hash, &mut tx_cache, &mut raw_bytes, false, response_budget.as_ref()))
                .await?.ok_or("UTXO transaction unavailable")?;
            let output = parsed.outputs.get(utxo.tx_pos as usize).ok_or("UTXO output index out of range")?;
            if output.satoshis != Some(utxo.value) || utxo.value > i64::MAX as u64 { return Err("UTXO amount mismatch".into()); }
            let output_script = hex::encode(output.locking_script.to_binary());
            if crate::network::backend::scripthash_from_script(&output_script).map_err(|e| e.to_string())? != scripthash {
                return Err("UTXO locking script mismatch".into());
            }
            output_scripts.push(output_script);
            if parsed.inputs.len() == 1 && parsed.inputs[0].source_output_index == u32::MAX && parsed.inputs[0].source_txid.as_deref().is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b == b'0')) {
                coinbase_txids.insert(utxo.tx_hash.clone());
            }
        }

        let mut transactions = Vec::new();
        for item in &history {
            let hash = crate::core::address::hex_str_to_hash(&item.tx_hash)
                .map_err(|e| format!("invalid tx_hash hex: {e}"))?;
            if hash.len() != 32 { return Err("invalid transaction hash length".into()); }
            let height = (item.height > 0).then_some(item.height);
            if let Some(previous) = heights.insert(hash.clone(), height) {
                if previous != height { return Err("inconsistent transaction heights across addresses".into()); }
            }
            transactions.push(repositories::SyncTransaction { hash, height, raw: std::sync::Arc::from([]), delta: None });
        }
        let mut outputs = Vec::new();
        for (output, script_pubkey) in utxos.iter().zip(output_scripts) {
            let hash = crate::core::address::hex_str_to_hash(&output.tx_hash)
                .map_err(|e| format!("invalid utxo tx_hash hex: {e}"))?;
            if hash.len() != 32 { return Err("invalid UTXO hash length".into()); }
            if !outpoints.insert((hash.clone(), output.tx_pos)) { return Err("duplicate UTXO outpoint".into()); }
            let height = (output.height > 0).then_some(output.height as i64);
            if let Some(previous) = heights.insert(hash.clone(), height) {
                if previous != height { return Err("inconsistent transaction heights across addresses".into()); }
            }
            outputs.push(repositories::SyncOutput { hash, height, index: output.tx_pos as i64,
                value: output.value as i64, coinbase: coinbase_txids.contains(&output.tx_hash), script_pubkey });
        }
        validate_utxo_history(&transactions, &outputs)?;
        snapshots.push(repositories::SyncKeySnapshot { key_id: *key_ref, transactions, outputs });

        // 6. Subscribe to scripthash updates for push notifications
        // Best-effort — don't fail the sync if subscription fails
        if scan.is_none() { if let Err(e) = client.subscribe_scripthash(&target).await {
            log::warn!(
                "sync_wallet: subscribe_scripthash failed for keyinstance {:?}: {e}",
                key_ref
            );
        } }

        synced_keys += 1;
    }

    bounded(deadline, resolve_sync_history(&mut snapshots, &wallet_scripts, &mut tx_cache, &mut raw_bytes, |key| {
        let client = &client;
        let budget = response_budget.clone();
        async move { client.call_with_budget("blockchain.transaction.get", serde_json::json!([key, false]), budget).await }
    })).await?;

    let _wallet_guard = bounded(deadline, async { Ok(state.wallet_operation.lock().await) }).await?;
    require_scan_wallet_session(state, &wallet_instance, acct_id, wallet_instance_token)?;
    if let Some((end,deadline)) = scan {
        repositories::merge_explicit_scan_snapshot(&pool, acct_id, &expected_keys, source.as_ref().ok_or("missing scan derivation source")?, discovered.as_deref().unwrap_or(&[]), &snapshots, end, deadline)
            .await.map_err(|e| format!("failed to merge scan snapshot: {e}"))?;
    } else {
        repositories::replace_sync_snapshot(&pool, acct_id, &expected_keys, discovered.as_deref(), &snapshots)
            .await.map_err(|e| format!("failed to store sync snapshot: {e}"))?;
    }
    {
        let active = state.active_wallet.lock().unwrap();
        if !active.as_ref().is_some_and(|wallet| std::sync::Arc::ptr_eq(&wallet.instance_id, &wallet_instance) && wallet.account_id == acct_id) {
            return Err(format!("synchronization saved to {wallet_path}, but active wallet changed"));
        }
    }
    let message = format!("synced wallet {}: {} keys, {} txs, {} utxos, balance {} confirmed + {} unconfirmed",
        wallet_path, synced_keys, total_tx_count, total_utxo_count, total_balance_confirmed, total_balance_unconfirmed);

    if scan.is_none() { log::info!("sync_wallet: account {} — {}", acct_id, message); }
    else { log::info!("explicit address scan completed for account {acct_id}: {new_keys} new keys"); }

    Ok((SyncResult {
        server_host: client.server_host(),
        account_id: acct_id,
        synced: synced_keys > 0,
        message,
    },new_keys))
}

/// Result of a wallet sync operation.
#[derive(Debug, serde::Serialize)]
pub struct SyncResult {
    pub server_host: String,
    pub account_id: i64,
    pub synced: bool,
    pub message: String,
}

/// Ban a server (AUD-Fund #6: for servers that return invalid data).
///
/// Permanently bans a server from the rotation. This should be called when
/// a server fails TLS validation, returns invalid merkle proofs, or sends
/// invalid block headers.
#[tauri::command]
pub async fn ban_server(state: State<'_, AppState>, host: String) -> Result<(), String> {
    log::warn!("Banning server: {host}");
    let mut net = state.network.lock().unwrap();
    net.begin_network_operation();
    let is_active = net.active_backend == Some(BackendType::ElectrumX)
        && net.client.as_ref().is_some_and(|client| client.server_host() == host);
    net.server_list.ban(&host);
    let old = if is_active { Some(net.take_active_network()) } else { None };
    drop(net);
    if let Some(old) = old { crate::network::service::cleanup(old); }
    Ok(())
}

/// Get the list of servers filtered by status.
#[tauri::command]
pub async fn get_servers_by_status(
    state: State<'_, AppState>,
    status: String,
) -> Result<Vec<ServerInfo>, String> {
    let (server_infos, _, _, _, _) = get_network_snapshot(&state);

    let filter_status = match status.as_str() {
        "unknown" => ServerStatus::Unknown,
        "connected" => ServerStatus::Connected,
        "disconnected" => ServerStatus::Disconnected,
        "failed" => ServerStatus::Failed,
        "banned" => ServerStatus::Banned,
        _ => return Err(format!("unknown status filter: {status}")),
    };

    Ok(server_infos
        .into_iter()
        .filter(|s| s.status == filter_status)
        .map(|s| ServerInfo {
            host: s.host,
            ssl_port: s.ssl_port,
            tcp_port: s.tcp_port,
            version: s.version,
            status: format!("{:?}", s.status).to_lowercase(),
            avg_latency_ms: s.avg_latency_ms,
            consecutive_failures: s.consecutive_failures,
        })
        .collect())
}

// ============================================================================
// Header Store commands (Milestone 4 — Header-Store / SPV)
// ============================================================================

/// Info about the header store — stored header count and tip height.
#[derive(Debug, serde::Serialize)]
pub struct HeaderStoreInfo {
    /// Whether the header store is initialized.
    pub initialized: bool,
    /// Number of stored block headers.
    pub header_count: u64,
    /// Height of the best stored header (tip), if any.
    pub tip_height: Option<u64>,
    /// Hash of the tip header (display hex), if any.
    pub tip_hash: Option<String>,
}

// The operation gate is acquired before initialization and never while holding
// the network mutex. The Arc remains in NetworkState when a future is cancelled.
async fn with_header_store<F, Fut, T>(state: &AppState, operation: F) -> Result<T, String>
where
    F: FnOnce(std::sync::Arc<HeaderStore>) -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let gate = state.network.lock().unwrap().header_store_operation.clone();
    let _operation = gate.lock().await;
    let existing = state.network.lock().unwrap().header_store.clone();
    let store = if let Some(store) = existing { store } else {
        let db_path = std::path::PathBuf::from(&state.data_dir).join("headers.sqlite");
        let store = std::sync::Arc::new(HeaderStore::open(&db_path.to_string_lossy()).await
            .map_err(|e| format!("failed to open header store: {e}"))?);
        store.ensure_genesis().await.map_err(|e| format!("failed to init genesis: {e}"))?;
        state.network.lock().unwrap().header_store = Some(store.clone());
        store
    };
    operation(store).await
}

/// Get header store status — number of stored headers, tip height/hash.
#[tauri::command]
pub async fn get_header_store_info(state: State<'_, AppState>) -> Result<HeaderStoreInfo, String> {
    header_store_info_inner(&state).await
}

async fn header_store_info_inner(state: &AppState) -> Result<HeaderStoreInfo, String> {
    with_header_store(state, |store| async move {
        let count = store.header_count().await.map_err(|e| e.to_string())?;
        let tip = store.get_tip().await.map_err(|e| e.to_string())?;
        let tip_height = tip.as_ref().map(|(height, _)| *height);
        let tip_hash = match tip {
            Some((height, hex)) => Some(ParsedHeader::from_hex(&hex, height).map_err(|e| e.to_string())?.hash),
            None => None,
        };
        Ok(HeaderStoreInfo { initialized: true, header_count: count, tip_height, tip_hash })
    }).await
}

fn matching_server_tip(height: u64, local_hex: &str, headers: &[crate::network::backend::BlockHeader]) -> Result<(), String> {
    if headers.len() != 1 || headers[0].height != height {
        return Err("server did not provide exactly the requested tip header".into());
    }
    let local = ParsedHeader::from_hex(local_hex, height).map_err(|e| e.to_string())?;
    let remote = ParsedHeader::from_hex(&headers[0].hex, height).map_err(|e| e.to_string())?;
    if local.hash != remote.hash { return Err("server tip conflicts with stored header; fork remains unresolved".into()); }
    Ok(())
}

fn server_tip_not_behind(current_tip: u64, server_tip: u64) -> Result<(), String> {
    if server_tip < current_tip { Err("server tip is below local height; chain identity is unverified".into()) }
    else { Ok(()) }
}

/// Sync block headers from the connected ElectrumX server.
/// Fetches headers from the current tip up to the server's chain tip.
#[tauri::command]
pub async fn sync_headers(
    state: State<'_, AppState>,
    max_count: Option<u64>,
) -> Result<SyncHeadersResult, String> {
    let client = {
        let net = state.network.lock().unwrap();
        if !net.connected { return Err("not connected to any server".into()); }
        net.client.clone().ok_or_else(|| "no active client".to_string())?
    };
    let server_tip = client.get_tip_height().await.map_err(|e| format!("failed to get server tip: {e}"))?;
    sync_headers_with_fetch(&state, server_tip, max_count, move |start, count| {
        let client = client.clone();
        async move { client.get_block_headers(start, count).await.map_err(|e| e.to_string()) }
    }).await
}

async fn sync_headers_with_fetch<F, Fut>(state: &AppState, server_tip: u64, max_count: Option<u64>, fetch: F) -> Result<SyncHeadersResult, String>
where
    F: FnMut(u64, u64) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<crate::network::backend::BlockHeader>, String>>,
{
    with_header_store(state, |store| async move {
        sync_headers_from_server(&store, server_tip, max_count, fetch).await
    }).await
}

async fn sync_headers_from_server<F, Fut>(
    store: &HeaderStore, server_tip: u64, max_count: Option<u64>, mut fetch: F,
) -> Result<SyncHeadersResult, String>
where
    F: FnMut(u64, u64) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<crate::network::backend::BlockHeader>, String>>,
{
    if max_count == Some(0) { return Err("max_count must be positive".into()); }
    let (current_tip, current_header) = store.get_tip().await
        .map_err(|e| format!("failed to get tip: {e}"))?.unwrap_or((0, String::new()));
    server_tip_not_behind(current_tip, server_tip)?;
    if server_tip == current_tip {
        let headers = fetch(server_tip, 1).await.map_err(|e| format!("failed to fetch server tip header: {e}"))?;
        matching_server_tip(current_tip, &current_header, &headers)?;
        return Ok(SyncHeadersResult { synced: 0, new_tip: current_tip, server_tip,
            message: "server tip matches stored header; independent consensus is not established".into() });
    }
    let start = current_tip.checked_add(1).ok_or("header height overflow")?;
    let count = max_count.unwrap_or(server_tip - current_tip).min(server_tip - current_tip).min(2016);
    let headers = fetch(start, count).await.map_err(|e| format!("failed to fetch headers: {e}"))?;
    if headers.is_empty() || u64::try_from(headers.len()).map_or(true, |received| received > count)
        || headers.iter().enumerate().any(|(index, header)| start.checked_add(index as u64) != Some(header.height)) {
        return Err("server returned an empty, oversized or misordered header batch".into());
    }
    let mut synced = 0u64;
    let mut new_tip = current_tip;
    let mut errors = Vec::new();
    for hdr in &headers {
        match store.connect_header(hdr.height, &hdr.hex).await {
            Ok(crate::network::header_store::ConnectResult::Connected { height }) => { synced += 1; new_tip = height; }
            Ok(crate::network::header_store::ConnectResult::AlreadyExists { height }) => { new_tip = new_tip.max(height); }
            Ok(crate::network::header_store::ConnectResult::Reorg { new_tip: nt, .. }) => { synced += 1; new_tip = nt; }
            Err(e) => { errors.push(format!("height {}: {e}", hdr.height)); break; }
        }
    }
    let message = header_sync_message(synced, new_tip, &errors)?;
    let message = if new_tip < server_tip { format!("{message}; partial progress, server reported tip {server_tip}") } else { message };
    Ok(SyncHeadersResult { synced, new_tip, server_tip, message })
}

fn header_sync_message(synced: u64, new_tip: u64, errors: &[String]) -> Result<String, String> {
    if errors.is_empty() {
        Ok(format!("synced {synced} headers, new tip: {new_tip}"))
    } else {
        Err(format!("header sync stopped after {synced} headers: {}", errors.join("; ")))
    }
}

/// Result of a header sync operation.
#[derive(Debug, serde::Serialize)]
pub struct SyncHeadersResult {
    /// Number of new headers connected.
    pub synced: u64,
    /// New chain tip height after sync.
    pub new_tip: u64,
    /// Server's reported chain tip height.
    pub server_tip: u64,
    /// Human-readable summary.
    pub message: String,
}

/// Verify a transaction's inclusion in a block via SPV merkle proof.
///
/// Checks a server-provided merkle proof against the stored header.
/// The header store does not independently establish chain consensus.
#[tauri::command]
pub async fn verify_transaction_proof(
    state: State<'_, AppState>,
    tx_hash: String,
    block_height: u64,
) -> Result<VerifyProofResult, String> {
    // Get client
    let client = {
        let net = state.network.lock().unwrap();
        if !net.connected {
            return Err("not connected to any server".to_string());
        }
        net.client
            .clone()
            .ok_or_else(|| "no active client".to_string())?
    };

    // Fetch merkle proof from server
    let proof = client
        .get_merkle_proof(&tx_hash, block_height)
        .await
        .map_err(|e| format!("failed to get merkle proof: {e}"))?;

    let branch: Vec<String> = proof.merkle_branch.iter().map(|(hash, _)| hash.clone()).collect();
    let position = proof.position.ok_or("merkle proof lacks transaction position")?;
    let checked_hash = tx_hash.clone();
    let verified = with_header_store(&state, |store| async move {
        store.verify_spv_proof_with_root(&checked_hash, block_height, &branch, position)
            .await.map_err(|error| format!("verification error: {error}"))
    }).await;
    let verified = verified.map_err(NetworkError::Protocol);

    proof_response(tx_hash, block_height, verified)
}

fn proof_response(tx_hash: String, block_height: u64, verified: Result<(bool, String), NetworkError>) -> Result<VerifyProofResult, String> {
    match verified {
        Ok((true, merkle_root)) => Ok(VerifyProofResult {
            verified: true,
            tx_hash,
            block_height,
            merkle_root,
            message: "merkle proof matches the stored header; independent consensus validation is not guaranteed".to_string(),
        }),
        Ok((false, merkle_root)) => Ok(VerifyProofResult {
            verified: false,
            tx_hash,
            block_height,
            merkle_root,
            message: "merkle proof verification failed — proof does not match stored header"
                .to_string(),
        }),
        Err(e) => Err(format!("verification error: {e}")),
    }
}

/// Result of an SPV proof verification.
#[derive(Debug, serde::Serialize)]
pub struct VerifyProofResult {
    /// Whether the transaction was verified.
    pub verified: bool,
    /// Transaction hash (display hex).
    pub tx_hash: String,
    /// Block height containing the transaction.
    pub block_height: u64,
    /// Merkle root from the block header.
    pub merkle_root: String,
    /// Human-readable result message.
    pub message: String,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #[test]
    fn explicit_scan_source_must_match_the_active_private_key() {
        use super::*;
        let key = ExtendedKey::from_seed(&[7; 64]).unwrap();
        let other = ExtendedKey::from_seed(&[8; 64]).unwrap();
        let mut source = repositories::ScanDerivationSource { account_id: 1, master: repositories::MasterKeyRow {
            masterkey_id:1, parent_masterkey_id:None, derivation_type:repositories::derivation_type::BIP32,
            derivation_data:serde_json::json!({"xpub":key.to_public().unwrap().to_base58()}).to_string().into_bytes(), date_created:1, date_updated:1,
        } };
        assert!(require_matching_scan_source(&key,&source).is_ok());
        assert!(require_matching_scan_source(&other,&source).is_err());
        source.master.derivation_type = -1;
        assert!(require_matching_scan_source(&key,&source).is_err());
    }
    #[tokio::test]
    async fn explicit_scan_wallet_session_rejects_close_reopen_and_wrong_token() {
        let dir = std::env::temp_dir().join(format!("electrumsv-scan-session-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = crate::state::AppState::new();
        state.data_dir = dir.to_str().unwrap().into();
        let created = crate::services::wallet_service::create_wallet(&state, "synthetic", "pw", Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), Some("")).await.unwrap();
        let (old_instance, old_token) = {
            let active = state.active_wallet.lock().unwrap();
            let wallet = active.as_ref().unwrap();
            (wallet.instance_id.clone(), wallet.instance_token.clone())
        };
        assert!(super::require_scan_wallet_session(&state, &old_instance, created.account_id, Some(&old_token)).is_ok());
        assert!(super::require_scan_wallet_session(&state, &old_instance, created.account_id, Some("wrong")).is_err());
        crate::services::wallet_service::close_wallet(&state).await.unwrap();
        assert!(super::require_scan_wallet_session(&state, &old_instance, created.account_id, Some(&old_token)).is_err());
        crate::services::wallet_service::open_wallet(&state, &created.wallet_path).await.unwrap();
        let (new_instance, new_token) = {
            let active = state.active_wallet.lock().unwrap();
            let wallet = active.as_ref().unwrap();
            (wallet.instance_id.clone(), wallet.instance_token.clone())
        };
        assert!(super::require_scan_wallet_session(&state, &old_instance, created.account_id, Some(&new_token)).is_err());
        assert!(super::require_scan_wallet_session(&state, &new_instance, created.account_id, Some(&old_token)).is_err());
        assert!(super::require_scan_wallet_session(&state, &new_instance, created.account_id, Some(&new_token)).is_ok());
        crate::services::wallet_service::close_wallet(&state).await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn explicit_range_scans_both_branches_past_gap_and_checks_bounds() {
        use super::*;
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        let account = ExtendedKey::from_seed(&[7; 64]).unwrap();
        let mut targets = std::collections::HashSet::new();
        for chain in 0..=1 {
            let public = account.derive(&format!("{chain}/25")).unwrap().public_key().unwrap();
            let address = address::pubkey_to_p2pkh_address(&public);
            targets.insert(crate::network::backend::scripthash_from_address(&address).unwrap());
        }
        let count = Arc::new(AtomicUsize::new(0));
        let (found, histories) = discover_explicit_range_with(&account, &[], 26, None, |target| {
            count.fetch_add(1, Ordering::SeqCst);
            let hit = targets.contains(target.as_str());
            async move { Ok(if hit { vec![crate::network::backend::TxHistoryEntry { tx_hash: "aa".into(), height: 1, verified: false }] } else { vec![] }) }
        }).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 52);
        assert_eq!(histories, 2);
        assert_eq!(found, [(0,25),(1,25)]);
        let overflow = discover_explicit_range_with(&account, &[], 1, None, |_| async {
            Ok(vec![crate::network::backend::TxHistoryEntry { tx_hash: "aa".into(), height: 1, verified: false }; 50_001])
        }).await.unwrap_err();
        assert!(overflow.contains("history entry limit"));
        for end in [0,1001] {
            assert!(discover_explicit_range_with(&account, &[], end, None, |_| async { panic!("invalid range must not query") }).await.is_err());
        }
        let count = Arc::new(AtomicUsize::new(0));
        let (found, _) = discover_explicit_range_with(&account, &[], 1000, None, |_| {
            count.fetch_add(1, Ordering::SeqCst);
            async { Ok(vec![]) }
        }).await.unwrap();
        assert!(found.is_empty());
        assert_eq!(count.load(Ordering::SeqCst), 2000);
    }
    #[tokio::test]
    async fn stale_connection_and_disconnect_cannot_replace_newer_connection() {
        let state = crate::state::AppState::new();
        let (server, first, second) = {
            let mut net = state.network.lock().unwrap();
            let server = net.server_list.all()[0].clone();
            let first = net.begin_network_operation();
            let second = net.begin_network_operation();
            (server, first, second)
        };
        let stale = crate::network::ElectrumXClient::new(server.clone());
        stale.mark_test_connected();
        let current = crate::network::ElectrumXClient::new(server.clone());
        current.mark_test_connected();
        super::register_connected_server(&state, &server, &current, second).unwrap();
        assert!(super::register_connected_server(&state, &server, &stale, first).is_err());
        assert!(!stale.is_connected());
        assert!(state.network.lock().unwrap().active_backend_snapshot().is_some());
        super::disconnect_server_inner(&state).await.unwrap();
        assert!(!current.is_connected());
        assert!(state.network.lock().unwrap().active_backend_snapshot().is_none());
    }
    #[tokio::test]
    async fn cancelled_header_sync_keeps_same_store_and_unblocks_parallel_info() {
        use std::sync::Arc;
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("wallet-header-cancel-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = crate::state::AppState::new(); state.data_dir = dir.to_string_lossy().into();
        let state = Arc::new(state);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let sync_state = state.clone();
        let sync = tokio::spawn(async move {
            let mut ready = Some(ready_tx);
            super::sync_headers_with_fetch(&sync_state, 1, None, move |_, _| {
                let signal = ready.take();
                async move {
                    if let Some(signal) = signal { let _ = signal.send(()); }
                    std::future::pending::<Result<Vec<crate::network::backend::BlockHeader>, String>>().await
                }
            }).await
        });
        tokio::time::timeout(Duration::from_secs(10), ready_rx).await.unwrap().unwrap();
        let first = state.network.lock().unwrap().header_store.clone().unwrap();
        let info_state = state.clone();
        let mut info = tokio::spawn(async move { super::header_store_info_inner(&info_state).await });
        assert!(tokio::time::timeout(Duration::from_millis(100), &mut info).await.is_err());
        sync.abort(); assert!(sync.await.unwrap_err().is_cancelled());
        let result = tokio::time::timeout(Duration::from_secs(10), info).await.unwrap().unwrap().unwrap();
        assert!(result.initialized); assert_eq!(result.tip_height, Some(0));
        let second = state.network.lock().unwrap().header_store.clone().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        drop(first); drop(second); drop(state);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn proof_response_reports_the_root_actually_checked() {
        let store = crate::network::header_store::HeaderStore::in_memory().await.unwrap();
        store.ensure_genesis().await.unwrap();
        let root = crate::network::header_store::ParsedHeader::from_hex(&store.get_header(0).await.unwrap().unwrap(), 0).unwrap().merkle_root;
        let checked = store.verify_spv_proof_with_root(&root, 0, &[], 0).await;
        let response = super::proof_response(root.clone(), 0, checked).unwrap();
        assert!(response.verified);
        assert_eq!(response.merkle_root, root);
        let wrong = "11".repeat(32);
        let checked = store.verify_spv_proof_with_root(&wrong, 0, &[], 0).await;
        let response = super::proof_response(wrong, 0, checked).unwrap();
        assert!(!response.verified);
        assert_eq!(response.merkle_root, root);
        assert!(super::proof_response("00".into(), 1, Err(crate::network::backend::NetworkError::NotFound("header".into()))).is_err());
    }
    #[tokio::test]
    async fn header_sync_rejects_empty_and_continues_short_valid_batches() {
        let store = crate::network::header_store::HeaderStore::in_memory().await.unwrap();
        store.ensure_genesis().await.unwrap();
        let before = store.get_tip().await.unwrap();
        let empty = super::sync_headers_from_server(&store, 2, None, |_, _| async { Ok(vec![]) }).await;
        assert!(empty.is_err());
        let parent = crate::network::header_store::ParsedHeader::from_hex(&before.as_ref().unwrap().1, 0).unwrap();
        let mut raw = vec![0u8; 80];
        let mut previous = hex::decode(parent.hash).unwrap(); previous.reverse();
        raw[4..36].copy_from_slice(&previous);
        raw[72..76].copy_from_slice(&0x207fffffu32.to_le_bytes());
        let mut found = false;
        for nonce in 0u32..1000 { raw[76..80].copy_from_slice(&nonce.to_le_bytes()); if crate::network::header_store::check_pow(&raw) { found = true; break; } }
        assert!(found);
        let first_hex = hex::encode(&raw);
        let short = super::sync_headers_from_server(&store, 2, None, |start, count| {
            assert_eq!((start, count), (1, 2));
            let hex = hex::encode(&raw);
            async move { Ok(vec![crate::network::backend::BlockHeader { height: start, hex }]) }
        }).await.unwrap();
        assert_eq!((short.synced, short.new_tip, short.server_tip), (1, 1, 2));
        assert!(short.message.contains("partial"));
        assert_eq!(store.get_tip().await.unwrap(), Some((1, first_hex.clone())));
        let parent = crate::network::header_store::ParsedHeader::from_hex(&first_hex, 1).unwrap();
        let mut previous = hex::decode(parent.hash).unwrap(); previous.reverse(); raw[4..36].copy_from_slice(&previous);
        let mut found = false;
        for nonce in 0u32..1000 { raw[76..80].copy_from_slice(&nonce.to_le_bytes()); if crate::network::header_store::check_pow(&raw) { found = true; break; } }
        assert!(found);
        let next = super::sync_headers_from_server(&store, 2, None, |start, count| {
            assert_eq!((start, count), (2, 1)); let hex = hex::encode(&raw);
            async move { Ok(vec![crate::network::backend::BlockHeader { height: start, hex }]) }
        }).await.unwrap();
        assert_eq!((next.synced, next.new_tip, next.server_tip), (1, 2, 2));
    }

    #[tokio::test]
    async fn header_sync_failure_keeps_committed_valid_prefix() {
        let store = crate::network::header_store::HeaderStore::in_memory().await.unwrap();
        store.ensure_genesis().await.unwrap();
        let genesis = store.get_tip().await.unwrap().unwrap().1;
        let parent = crate::network::header_store::ParsedHeader::from_hex(&genesis, 0).unwrap();
        let mut raw = vec![0u8; 80];
        let mut previous = hex::decode(parent.hash).unwrap(); previous.reverse();
        raw[4..36].copy_from_slice(&previous); raw[72..76].copy_from_slice(&0x207fffffu32.to_le_bytes());
        let mut found = false;
        for nonce in 0u32..1000 { raw[76..80].copy_from_slice(&nonce.to_le_bytes()); if crate::network::header_store::check_pow(&raw) { found = true; break; } }
        assert!(found);
        let first = hex::encode(raw);
        let result = super::sync_headers_from_server(&store, 2, None, |start, count| {
            assert_eq!((start, count), (1, 2)); let hex = first.clone();
            async move { Ok(vec![crate::network::backend::BlockHeader { height: 1, hex }, crate::network::backend::BlockHeader { height: 2, hex: "00".into() }]) }
        }).await;
        assert!(result.is_err());
        assert_eq!(store.get_tip().await.unwrap(), Some((1, first)));
    }

    #[tokio::test]
    async fn header_sync_rejects_zero_max_count_before_fetch() {
        let store = crate::network::header_store::HeaderStore::in_memory().await.unwrap();
        store.ensure_genesis().await.unwrap();
        let result = super::sync_headers_from_server(&store, 1, Some(0), |_, _| async {
            panic!("zero max_count must not issue a fetch");
            #[allow(unreachable_code)] Ok(vec![])
        }).await;
        assert!(result.is_err());
        let limited = super::sync_headers_from_server(&store, 5000, None, |start, count| async move {
            assert_eq!((start, count), (1, 2016)); Ok(vec![])
        }).await;
        assert!(limited.is_err());
    }
    #[test]
    fn equal_server_height_requires_matching_header() {
        assert!(super::server_tip_not_behind(5, 4).is_err());
        assert!(super::server_tip_not_behind(5, 5).is_ok());
        assert!(super::server_tip_not_behind(5, 6).is_ok());
        let header = "00".repeat(80);
        let different = "01".repeat(80);
        let matching = crate::network::backend::BlockHeader { height: 5, hex: header.clone() };
        assert!(super::matching_server_tip(5, &header, &[matching]).is_ok());
        let conflicting = crate::network::backend::BlockHeader { height: 5, hex: different };
        assert!(super::matching_server_tip(5, &header, &[conflicting]).is_err());
        assert!(super::matching_server_tip(5, &header, &[]).is_err());
        assert!(super::header_sync_message(1, 6, &["fork remains unresolved".into()]).is_err());
        assert!(super::header_sync_message(1, 6, &[]).is_ok());
    }
    #[tokio::test]
    async fn resolver_fetch_snapshot_history_detail_integration() {
        use bsv::transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput};
        use bsv::script::locking_script::LockingScript;
        use crate::db::{connection, repositories as repo};
        fn out(value: u64, script: u8) -> TransactionOutput {
            TransactionOutput { satoshis: Some(value), locking_script: LockingScript::from_binary(&[script]), change: false }
        }
        fn coinbase(value: u64, script: u8) -> Transaction {
            let mut tx = Transaction::new();
            tx.inputs.push(TransactionInput { source_txid: Some("00".repeat(32)), source_output_index: u32::MAX, ..Default::default() });
            tx.outputs.push(out(value, script));
            tx
        }
        fn spend(parent: &Transaction, value: u64, script: u8) -> Transaction {
            let mut tx = Transaction::new();
            tx.inputs.push(TransactionInput { source_txid: Some(parent.id().unwrap()), source_output_index: 0, ..Default::default() });
            tx.outputs.push(out(value, script));
            tx
        }
        fn entry(tx: &Transaction) -> repo::SyncTransaction {
            repo::SyncTransaction { hash: crate::core::address::hex_str_to_hash(&tx.id().unwrap()).unwrap(),
                height: Some(10), raw: std::sync::Arc::from([]), delta: None }
        }
        let path = std::env::temp_dir().join(format!("electrumsv-resolver-{}-{}.sqlite", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        connection::create_wallet_db(path.to_str().unwrap()).await.unwrap();
        let pool = connection::open_wallet_db(path.to_str().unwrap()).await.unwrap();
        let master = repo::insert_master_key(&pool, None, repo::derivation_type::BIP32, b"test").await.unwrap();
        let account = repo::insert_account(&pool, Some(master), repo::script_type::P2PKH, "test").await.unwrap();
        let a = repo::insert_keyinstance(&pool, account, Some(master), repo::derivation_type::BIP32, br#"{"subpath":[0,0]}"#, repo::script_type::P2PKH, 0, None).await.unwrap();
        let b = repo::insert_keyinstance(&pool, account, Some(master), repo::derivation_type::BIP32, br#"{"subpath":[0,1]}"#, repo::script_type::P2PKH, 0, None).await.unwrap();
        let keys = repo::get_keyinstances_for_account(&pool, account).await.unwrap();
        let scripts = [(crate::network::backend::scripthash_from_script("51").unwrap(), repo::SyncKeyRef::Existing(a)),
            (crate::network::backend::scripthash_from_script("52").unwrap(), repo::SyncKeyRef::Existing(b))].into_iter().collect();
        let receive = coinbase(100, 0x51);
        let transfer = spend(&receive, 90, 0x52);
        let external = coinbase(7, 0x53);
        let pending = spend(&external, 5, 0x52);
        let graphs = [&receive, &transfer, &external, &pending].into_iter()
            .map(|tx| (tx.id().unwrap(), tx.to_hex().unwrap())).collect::<std::collections::HashMap<_, _>>();
        let snapshots = || vec![
            repo::SyncKeySnapshot { key_id: repo::SyncKeyRef::Existing(a), transactions: vec![entry(&receive), entry(&transfer)], outputs: vec![] },
            repo::SyncKeySnapshot { key_id: repo::SyncKeyRef::Existing(b), transactions: vec![entry(&transfer), entry(&pending)], outputs: vec![] },
        ];
        let find_value = |rows: Vec<repo::TxDeltaHistoryRow>, tx: &Transaction| rows.into_iter().find(|r| r.tx_hash_hex == tx.id().unwrap()).unwrap().value_delta;
        let missing_id = external.id().unwrap();
        let mut first = snapshots();
        super::resolve_sync_history(&mut first, &scripts, &mut super::RawTransactionCache::new(), &mut 0,
            |id| { let data = if id == missing_id { None } else { graphs.get(&id).cloned() }; async move { Ok(data.map_or(serde_json::Value::Null, |raw| serde_json::json!(raw))) } }).await.unwrap();
        repo::replace_sync_snapshot(&pool, account, &keys, None, &first).await.unwrap();
        let history = repo::get_tx_history_for_account(&pool, account, 50, 0).await.unwrap();
        assert_eq!(find_value(history.clone(), &receive), Some(100));
        assert_eq!(find_value(history.clone(), &transfer), Some(-10));
        assert_eq!(find_value(history, &pending), None);
        let detail = crate::commands::extra::transaction_detail(&pool, account, &transfer.id().unwrap()).await.unwrap();
        assert!(detail.detail_complete);
        assert_eq!(detail.inputs.unwrap()[0].prev_tx_hash, receive.id().unwrap());
        assert_eq!(detail.outputs.unwrap()[0].value, 90);
        let mut second = snapshots();
        super::resolve_sync_history(&mut second, &scripts, &mut super::RawTransactionCache::new(), &mut 0,
            |id| { let data = graphs.get(&id).cloned(); async move { Ok(data.map_or(serde_json::Value::Null, |raw| serde_json::json!(raw))) } }).await.unwrap();
        repo::replace_sync_snapshot(&pool, account, &keys, None, &second).await.unwrap();
        let history = repo::get_tx_history_for_account(&pool, account, 50, 0).await.unwrap();
        assert_eq!(find_value(history, &pending), Some(5));
        let mut malformed = snapshots();
        assert!(super::resolve_sync_history(&mut malformed, &scripts, &mut super::RawTransactionCache::new(), &mut 0,
            |_| { let raw = transfer.to_hex().unwrap(); async move { Ok(serde_json::json!(raw)) } }).await.is_err());
        let mut omitted = snapshots();
        omitted[0].transactions.retain(|item| item.hash != entry(&transfer).hash);
        assert!(super::resolve_sync_history(&mut omitted, &scripts, &mut super::RawTransactionCache::new(), &mut 0,
            |id| { let data = graphs.get(&id).cloned(); async move { Ok(data.map_or(serde_json::Value::Null, |raw| serde_json::json!(raw))) } }).await.is_err());
        let unchanged = repo::get_tx_history_for_account(&pool, account, 50, 0).await.unwrap();
        assert_eq!(find_value(unchanged.clone(), &transfer), Some(-10));
        assert_eq!(find_value(unchanged, &pending), Some(5));
        pool.close().await;
        std::fs::remove_file(path).ok();
    }

    #[tokio::test]
    async fn fake_fetch_distinguishes_missing_server_errors_and_bad_hashes() {
        use bsv::transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput};
        use bsv::script::locking_script::LockingScript;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let mut tx = Transaction::new();
        tx.inputs.push(TransactionInput { source_txid: Some(hex::encode((0u8..32).collect::<Vec<_>>())), source_output_index: 1, ..Default::default() });
        tx.outputs.push(TransactionOutput { satoshis: Some(7), locking_script: LockingScript::from_binary(&[0x51]), change: false });
        let raw = tx.to_hex().unwrap();
        let id = tx.id().unwrap();
        let calls = AtomicUsize::new(0);
        let mut cache = super::RawTransactionCache::new();
        let mut bytes = 0;
        let fetch = |_: String| { calls.fetch_add(1, Ordering::SeqCst); let raw = raw.clone(); async move { Ok(serde_json::json!(raw)) } };
        let (_, parsed) = super::fetch_sync_transaction_with(&id.to_uppercase(), &mut cache, &mut bytes, false, fetch).await.unwrap().unwrap();
        assert_eq!(parsed.inputs[0].source_txid.as_deref(), Some(hex::encode((0u8..32).collect::<Vec<_>>()).as_str()));
        let display = parsed.inputs[0].source_txid.as_ref().unwrap();
        assert_eq!(crate::core::address::hash_to_hex_str(&crate::core::address::hex_str_to_hash(display).unwrap()), *display);
        super::fetch_sync_transaction_with(&id, &mut cache, &mut bytes, false, |_| async { panic!("cache was not used") }).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let missing = "ff".repeat(32);
        assert!(super::fetch_sync_transaction_with(&missing, &mut cache, &mut bytes, true, |_| async { Err(super::NetworkError::NotFound("missing".into())) }).await.unwrap().is_none());
        let failed = "ee".repeat(32);
        assert!(super::fetch_sync_transaction_with(&failed, &mut cache, &mut bytes, true, |_| async { Err(super::NetworkError::Server("overloaded".into())) }).await.is_err());
        let wrong = "dd".repeat(32);
        assert!(super::fetch_sync_transaction_with(&wrong, &mut cache, &mut bytes, false, |_| async { Ok(serde_json::json!(raw)) }).await.is_err());
    }

    #[test]
    fn history_must_include_every_wallet_utxo() {
        let hash = vec![42; 32];
        let output = super::repositories::SyncOutput { hash: hash.clone(), height: Some(1), index: 0, value: 100,
            coinbase: false, script_pubkey: "51".into() };
        assert!(super::validate_utxo_history(&[], &[output]).is_err());
        let output = super::repositories::SyncOutput { hash: hash.clone(), height: Some(1), index: 0, value: 100,
            coinbase: false, script_pubkey: "51".into() };
        let history = super::repositories::SyncTransaction { hash, height: Some(1), raw: std::sync::Arc::from([]), delta: None };
        assert!(super::validate_utxo_history(&[history], &[output]).is_ok());
    }

    #[test]
    fn history_membership_rejects_omitted_and_unrelated_keys() {
        use super::SyncKeyRef::Existing;
        let amounts = [(Existing(1), -100), (Existing(2), 90)].into_iter().collect();
        let only_b = [Existing(2)].into_iter().collect();
        assert!(super::validate_history_membership(&amounts, &only_b, true).is_err());
        let extra = [Existing(1), Existing(2), Existing(3)].into_iter().collect();
        assert!(super::validate_history_membership(&amounts, &extra, true).is_err());
        assert!(super::validate_history_membership(&amounts, &extra, false).is_ok());
        let all = [Existing(1), Existing(2)].into_iter().collect();
        assert!(super::validate_history_membership(&amounts, &all, true).is_ok());
    }

    #[test]
    fn history_graph_computes_wallet_net_and_missing_prevout_is_unknown() {
        use bsv::transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput};
        use bsv::script::locking_script::LockingScript;
        fn out(value: u64, script: u8) -> TransactionOutput {
            TransactionOutput { satoshis: Some(value), locking_script: LockingScript::from_binary(&[script]), change: false }
        }
        let mut parent = Transaction::new();
        parent.inputs.push(TransactionInput { source_txid: Some("00".repeat(32)), source_output_index: u32::MAX, ..Default::default() });
        parent.outputs = vec![out(100_000, 0x51)];
        let parent_id = parent.id().unwrap();
        let mut tx = Transaction::new();
        tx.inputs.push(TransactionInput { source_txid: Some(parent_id.clone()), source_output_index: 0, ..Default::default() });
        tx.outputs = vec![out(25_000, 0x52), out(74_000, 0x51), out(0, 0x6a)];
        let scripts = [(crate::network::backend::scripthash_from_script("51").unwrap(), super::SyncKeyRef::Existing(-1)),
            (crate::network::backend::scripthash_from_script("52").unwrap(), super::SyncKeyRef::Discovered(0))].into_iter().collect();
        let mut cache = super::RawTransactionCache::new();
        let (_, complete) = super::calculate_history_values(&tx, &scripts, &cache).unwrap();
        assert!(!complete);
        cache.insert(parent_id, Some((hex::decode(parent.to_hex().unwrap()).unwrap(), parent)));
        let (values, complete) = super::calculate_history_values(&tx, &scripts, &cache).unwrap();
        assert!(complete);
        assert_eq!(values[&super::SyncKeyRef::Existing(-1)], -26_000);
        assert_eq!(values[&super::SyncKeyRef::Discovered(0)], 25_000);
        assert_eq!(values.values().sum::<i64>(), -1_000);
        tx.inputs[0].source_output_index = 99;
        assert!(super::calculate_history_values(&tx, &scripts, &cache).is_err());
        let raw = hex::decode(tx.to_hex().unwrap()).unwrap();
        assert!(super::validate_transaction_wire(&raw).is_ok());
        assert!(super::validate_transaction_wire(&[1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]).is_err());
    }

    use super::*;
    use crate::network::server_list::ServerList;

    #[test]
    fn test_network_info_serialize() {
        let info = NetworkInfo {
            connected: false,
            backend_type: None,
            active_server: None,
            tip_height: None,
            server_count: 9,
            connected_count: 0,
            banned_count: 0,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"connected\":false"));
        assert!(json.contains("\"server_count\":9"));
    }

    #[test]
    fn test_server_info_serialize() {
        let info = ServerInfo {
            host: "electrum.api.sv".to_string(),
            ssl_port: 50002,
            tcp_port: Some(50001),
            version: "1.4".to_string(),
            status: "unknown".to_string(),
            avg_latency_ms: None,
            consecutive_failures: 0,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"host\":\"electrum.api.sv\""));
        assert!(json.contains("\"ssl_port\":50002"));
    }

    #[test]
    fn test_sync_result_serialize() {
        let result = SyncResult {
            server_host: "electrum.api.sv".to_string(),
            account_id: 1,
            synced: true,
            message: "synced 3 keys: 5 txs, 2 utxos".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"synced\":true"));
        assert!(json.contains("\"account_id\":1"));
        assert!(json.contains("synced 3 keys"));
    }

    #[test]
    fn test_sync_result_not_synced() {
        let result = SyncResult {
            server_host: "electrum.api.sv".to_string(),
            account_id: 1,
            synced: false,
            message: "no keyinstances found".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"synced\":false"));
    }

    #[test]
    fn test_network_command_error_display() {
        let e = NetworkCommandError::NotConnected;
        assert!(e.to_string().contains("not connected"));

        let e = NetworkCommandError::NoWalletOpen;
        assert!(e.to_string().contains("no wallet"));

        let e = NetworkCommandError::ConnectionFailed("timeout".to_string());
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn test_network_command_error_serialize() {
        let e = NetworkCommandError::NotConnected;
        let json = serde_json::to_string(&e).unwrap();
        // Serialized as a plain string
        assert!(json.contains("not connected"));
    }

    #[test]
    fn test_backend_type_string() {
        assert_eq!(BackendType::ElectrumX.to_string(), "electrumx");
        assert_eq!(BackendType::WhatsOnChain.to_string(), "whatsonchain");
    }

    #[test]
    fn test_server_list_default_in_network_state() {
        let ns = crate::state::NetworkState::new();
        assert_eq!(ns.server_list.len(), 9);
        assert!(!ns.connected);
    }

    #[test]
    fn test_get_network_snapshot() {
        let state = AppState::new();
        let (servers, connected, conn_count, banned, total) = get_network_snapshot(&state);
        assert_eq!(total, 9);
        assert!(!connected);
        assert_eq!(conn_count, 0);
        assert_eq!(banned, 0);
        assert_eq!(servers.len(), 9);
    }

    #[test]
    fn test_status_string_conversion() {
        assert_eq!(
            format!("{:?}", ServerStatus::Unknown).to_lowercase(),
            "unknown"
        );
        assert_eq!(
            format!("{:?}", ServerStatus::Connected).to_lowercase(),
            "connected"
        );
        assert_eq!(
            format!("{:?}", ServerStatus::Banned).to_lowercase(),
            "banned"
        );
        assert_eq!(
            format!("{:?}", ServerStatus::Failed).to_lowercase(),
            "failed"
        );
    }
}
