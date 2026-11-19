//! Private synthetic Wry scan integration host.
use std::{borrow::Cow, path::PathBuf, sync::{Arc, atomic::{AtomicU8, AtomicUsize, Ordering}}, time::Duration};
use tauri::{Assets, Runtime, State, WebviewUrl, WebviewWindowBuilder};
use tauri::utils::assets::{AssetKey, AssetsIter, CspHash};
use bsv::{compat::bip32::ExtendedKey, script::templates::{p2pkh::P2PKH, ScriptTemplateLock}, transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput}};
use serde_json::{json, Value};

struct ScanAssets(PathBuf);
impl<R: Runtime> Assets<R> for ScanAssets {
    fn get(&self, key: &AssetKey) -> Option<Cow<'_, [u8]>> {
        let name = match key.as_ref() { "/" | "/index.html" => "index.html", "/gate.js" => "gate.js", "/gate.css" => "gate.css", _ => return None };
        std::fs::read(self.0.join(name)).ok().map(Cow::Owned)
    }
    fn iter(&self) -> Box<AssetsIter<'_>> { Box::new(std::iter::empty()) }
    fn csp_hashes(&self, _: &AssetKey) -> Box<dyn Iterator<Item = CspHash<'_>> + '_> { Box::new(std::iter::empty()) }
}
struct Fixture { path: String, token: String, account: i64, histories: Arc<AtomicUsize> }
#[tauri::command]
fn scan_identity(fixture: State<'_, Fixture>) -> Value { json!({"path":fixture.path,"token":fixture.token,"account":fixture.account}) }
#[tauri::command]
async fn scan_observe(state: State<'_, crate::state::AppState>, fixture: State<'_, Fixture>, after_sync: bool) -> Result<(), String> {
    let pool = state.active_wallet.lock().unwrap().as_ref().ok_or("no wallet")?.db_pool.clone();
    let keys = crate::db::repositories::get_keyinstances_for_account(&pool, fixture.account).await.map_err(|e| e.to_string())?;
    let outputs = crate::db::repositories::get_utxos_for_account(&pool, fixture.account).await.map_err(|e| e.to_string())?;
    for chain in 0..=1 {
        let key = keys.iter().find(|key| serde_json::from_slice::<Value>(&key.derivation_data).ok().is_some_and(|data| data["subpath"] == json!([chain,25]))).ok_or("missing derived key")?;
        if !outputs.iter().any(|output| output.keyinstance_id == key.keyinstance_id && output.value == 50_000 + chain) { return Err("missing output".into()); }
    }
    let histories = fixture.histories.load(Ordering::SeqCst);
    if keys.len() != 2 || outputs.len() != 2 || (!after_sync && histories != 54) || (after_sync && histories <= 54) { return Err("unexpected scan data or request count".into()); }
    let marker = crate::db::repositories::get_wallet_data(&pool, &format!("address_discovery_v1_{}", fixture.account)).await.map_err(|e| e.to_string())?;
    if marker.as_deref() != if after_sync { Some("done") } else { None } { return Err("unexpected discovery marker".into()); }
    Ok(())
}

#[test]
#[ignore = "private Wry scan host; isolated child process only"]
fn real_wry_address_scan_with_local_tls() {
    std::thread::spawn(|| { std::thread::sleep(Duration::from_secs(90)); eprintln!("WRY_SCAN_TIMEOUT"); std::process::exit(124); });
    let assets = PathBuf::from(std::env::var_os("WALLET_WRY_SCAN_ASSET_DIR").expect("asset directory"));
    let dir = PathBuf::from(std::env::var_os("WALLET_WRY_SCAN_DATA_DIR").expect("private data directory"));
    let mut state = crate::state::AppState::new(); state.data_dir = dir.to_string_lossy().into();
    let histories = Arc::new(AtomicUsize::new(0));
    let (created, server) = tauri::async_runtime::block_on(async {
        let created = crate::services::wallet_service::create_wallet(&state, "synthetic", "test-password", Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), None).await.unwrap();
        let xprv = state.active_wallet.lock().unwrap().as_ref().unwrap().decrypted_xprv.clone().unwrap();
        let key = ExtendedKey::from_string(&xprv).unwrap();
        let mut targets = std::collections::HashMap::new();
        for chain in 0..=1 {
            let public = key.derive(&format!("{chain}/25")).unwrap().public_key().unwrap();
            let address = crate::core::address::pubkey_to_p2pkh_address(&public);
            let target = crate::network::backend::scripthash_from_address(&address).unwrap();
            let mut tx = Transaction::new();
            tx.inputs.push(TransactionInput { source_txid: Some("00".repeat(32)), source_output_index: u32::MAX, ..Default::default() });
            tx.outputs.push(TransactionOutput { satoshis: Some(50_000 + chain), locking_script: P2PKH::from_address(&address).unwrap().lock().unwrap(), change: false });
            targets.insert(target, (tx.to_hex().unwrap(), tx.id().unwrap(), 50_000 + chain));
        }
        let (port, server) = crate::agent::agent_tls_test::scan_server(targets, histories.clone(), None, false).await;
        crate::commands::network::connect_explicit_server_with_test_roots(&state, crate::network::server_list::ServerEntry::new("127.0.0.1",port), crate::agent::agent_tls_test::roots()).await.unwrap();
        (created, server)
    });
    let result = Arc::new(AtomicU8::new(0));
    let mut context = tauri::generate_context!(); context.config_mut().build.dev_url = None; context.config_mut().app.windows.clear(); context.set_assets(Box::new(ScanAssets(assets)));
    let setup_result = result.clone();
    let app = tauri::Builder::default().any_thread().manage(state).manage(Fixture { path: created.wallet_path, token: created.wallet_instance_token, account: created.account_id, histories })
        .invoke_handler(tauri::generate_handler![scan_identity, scan_observe, crate::commands::network::get_network_info, crate::commands::network::get_servers, crate::commands::network::get_header_store_info, crate::commands::network::scan_address_range, crate::commands::network::sync_wallet])
        .setup(move |app| {
            let handle = app.handle().clone(); let result = setup_result.clone();
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into())).title("Private scan test")
                .on_navigation(move |url| {
                    if url.scheme() == "https" && url.host_str() == Some("wallet-scan.invalid") {
                        let pass = url.path() == "/pass"; if !pass { eprintln!("WRY_SCAN_FAIL {}", url.path()); } result.store(if pass {1} else {2}, Ordering::SeqCst); handle.exit(if pass {0} else {1}); return false;
                    }
                    url.scheme() == "tauri" || (url.scheme() == "http" && url.host_str() == Some("tauri.localhost"))
                }).build()?; Ok(())
        }).build(context).expect("build scan Wry host");
    let exit = app.run_return(|_, _| {}); server.abort();
    assert_eq!(exit, 0); assert_eq!(result.load(Ordering::SeqCst), 1);
    println!("WRY_SCAN_PASS gui ipc local_tls two_branches persisted bound_sync");
}
