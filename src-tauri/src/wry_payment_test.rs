//! Isolated, ignored payment integration host. Never compiled into the application.
use std::{borrow::Cow, path::PathBuf, sync::{Arc, Mutex, atomic::{AtomicU8, Ordering}}, time::Duration};
use tauri::{Assets, Runtime, State, WebviewUrl, WebviewWindowBuilder};
use tauri::utils::assets::{AssetKey, AssetsIter, CspHash};
use bsv::script::{spend::{Spend, SpendParams}, templates::{p2pkh::P2PKH, ScriptTemplateLock}};
use bsv::transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use serde_json::{json, Value};

const SECRET: &[u8] = b"12345678901234567890";
const CA: &[u8] = include_bytes!("../tests/fixtures/tls/ca.pem");
const CERT: &[u8] = include_bytes!("../tests/fixtures/tls/server.pem");
const KEY: &[u8] = include_bytes!("../tests/fixtures/tls/server-key.pem");
struct PaymentAssets(PathBuf);
impl<R: Runtime> Assets<R> for PaymentAssets {
    fn get(&self, key: &AssetKey) -> Option<Cow<'_, [u8]>> {
        let name = match key.as_ref() { "/" | "/index.html" => "index.html", "/gate.js" => "gate.js", "/gate.css" => "gate.css", _ => return None };
        std::fs::read(self.0.join(name)).ok().map(Cow::Owned)
    }
    fn iter(&self) -> Box<AssetsIter<'_>> { Box::new(std::iter::empty()) }
    fn csp_hashes(&self, _: &AssetKey) -> Box<dyn Iterator<Item = CspHash<'_>> + '_> { Box::new(std::iter::empty()) }
}
struct Fixture { port: u16, path: String, token: String, payloads: Arc<Mutex<Vec<String>>> }
fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut &CA[..]) { roots.add(c.unwrap()).unwrap(); }
    roots
}
#[tauri::command]
fn payment_identity(fixture: State<'_, Fixture>) -> Value { json!({"path":fixture.path,"token":fixture.token}) }
#[tauri::command]
fn payment_code() -> String { crate::security::totp::TotpInstance::from_secret_bytes(SECRET, "ElectrumSV-Mc", "wallet").unwrap().generate_current().unwrap() }
#[tauri::command]
fn payment_wrong_code() -> String {
    let totp = crate::security::totp::TotpInstance::from_secret_bytes(SECRET, "ElectrumSV-Mc", "wallet").unwrap();
    ["000000", "111111", "222222", "333333"].into_iter().find(|code| !totp.verify_current(code).unwrap()).unwrap().into()
}
#[tauri::command]
async fn payment_observe(state: State<'_, crate::state::AppState>) -> Result<String, String> {
    let pool = state.active_wallet.lock().unwrap().as_ref().ok_or("no wallet")?.db_pool.clone();
    let rows: Vec<(String,)> = sqlx::query_as("SELECT state FROM SpendPlans").fetch_all(&pool).await.map_err(|e| e.to_string())?;
    let reservations: (i64,) = sqlx::query_as("SELECT count(*) FROM SpendReservations").fetch_one(&pool).await.map_err(|e| e.to_string())?;
    if rows.len() != 1 || reservations.0 != 1 { return Err("plan/reservation invariant".into()); }
    Ok(rows[0].0.clone())
}
#[tauri::command]
async fn payment_reconnect(state: State<'_, crate::state::AppState>, fixture: State<'_, Fixture>) -> Result<(), String> {
    let client = state.network.lock().unwrap().client.clone().ok_or("no client")?;
    for _ in 0..100 { if !client.is_connected() { break; } tokio::time::sleep(Duration::from_millis(50)).await; }
    if client.is_connected() { return Err("EOF did not disconnect client".into()); }
    tokio::time::sleep(Duration::from_millis(500)).await;
    if fixture.payloads.lock().unwrap().len() != 1 { return Err("unexpected automatic retry".into()); }
    crate::commands::network::connect_explicit_server_with_test_roots(&state, crate::network::server_list::ServerEntry::new("127.0.0.1", fixture.port), roots()).await.map_err(|e| e.to_string())?;
    if fixture.payloads.lock().unwrap().len() != 1 { return Err("retry during reconnect".into()); }
    Ok(())
}
#[test]
#[ignore = "private Wry payment host; isolated child process only"]
fn real_wry_send_payment_with_local_tls() {
    std::thread::spawn(|| { std::thread::sleep(Duration::from_secs(90)); eprintln!("WRY_PAYMENT_TIMEOUT"); std::process::exit(124); });
    let assets = PathBuf::from(std::env::var_os("WALLET_WRY_PAYMENT_ASSET_DIR").expect("asset directory"));
    let dir = PathBuf::from(std::env::var_os("WALLET_WRY_PAYMENT_DATA_DIR").expect("private RAM data directory"));
    assert!(assets.join("index.html").is_file() && assets.join("gate.js").is_file());
    let mut state = crate::state::AppState::new(); state.data_dir = dir.to_string_lossy().into();
    let payloads = Arc::new(Mutex::new(Vec::<String>::new())); let failure = Arc::new(AtomicU8::new(0));
    let (created, port, server) = tauri::async_runtime::block_on(async {
        let created = crate::services::wallet_service::create_wallet(&state, "synthetic", "test-password", Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), None).await.unwrap();
        {
            let mut active = state.active_wallet.lock().unwrap();
            let wallet = active.as_mut().unwrap();
            wallet.secure_wallet.as_mut().unwrap().bundle.as_mut().unwrap().totp = Some(crate::security::wallet_bundle::TotpPolicy { secret: SECRET.to_vec(), recovery_hashes: vec![] });
        }
        let address = crate::services::account_service::get_receive_address(&state, Some(created.account_id)).await.unwrap().address;
        let target = crate::network::backend::scripthash_from_address(&address).unwrap();
        let locking = P2PKH::from_address(&address).unwrap().lock().unwrap();
        let mut parent = Transaction::new();
        parent.inputs.push(TransactionInput { source_txid: Some("00".repeat(32)), source_output_index: u32::MAX, ..Default::default() });
        let external_script = P2PKH::from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap().lock().unwrap();
        parent.outputs.push(TransactionOutput { satoshis: Some(60_000), locking_script: external_script, change: false });
        let parent_id = parent.id().unwrap(); let parent_raw = parent.to_hex().unwrap();
        let mut funding = Transaction::new();
        funding.inputs.push(TransactionInput { source_txid: Some(parent_id.clone()), source_output_index: 0, ..Default::default() });
        funding.outputs.push(TransactionOutput { satoshis: Some(50_000), locking_script: locking.clone(), change: false });
        let id = funding.id().unwrap(); let raw = funding.to_hex().unwrap();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap(); let port = listener.local_addr().unwrap().port();
        let chain = rustls_pemfile::certs(&mut &CERT[..]).collect::<Result<Vec<_>, _>>().unwrap();
        let key = rustls_pemfile::private_key(&mut &KEY[..]).unwrap().unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider())).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(chain, key).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let seen = payloads.clone(); let bad = failure.clone();
        let task = tauri::async_runtime::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone(); let target = target.clone(); let id = id.clone(); let raw = raw.clone(); let parent_id = parent_id.clone(); let parent_raw = parent_raw.clone(); let locking = locking.clone(); let seen = seen.clone(); let bad = bad.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(socket).await else { bad.store(1, Ordering::SeqCst); return; };
                    let (read, mut write) = tokio::io::split(tls); let mut lines = BufReader::new(read).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let Ok(req) = serde_json::from_str::<Value>(&line) else { bad.store(2, Ordering::SeqCst); break; };
                        let key = req["params"][0].as_str().unwrap_or("");
                        let result = match req["method"].as_str() {
                            Some("server.version") => json!(["private-test", "1.4"]),
                            Some("blockchain.scripthash.get_balance") => json!({"confirmed":if key == target {50_000} else {0},"unconfirmed":0}),
                            Some("blockchain.scripthash.get_history") => if key == target { json!([{"tx_hash":id,"height":123}]) } else { json!([]) },
                            Some("blockchain.scripthash.listunspent") => if key == target { json!([{"tx_hash":id,"tx_pos":0,"value":50_000,"height":123}]) } else { json!([]) },
                            Some("blockchain.transaction.get") if key == id => json!(raw),
                            Some("blockchain.transaction.get") if key == parent_id => json!(parent_raw),
                            Some("blockchain.scripthash.subscribe") => Value::Null,
                            Some("blockchain.transaction.broadcast") => {
                                let Ok(tx) = Transaction::from_hex(key) else { bad.store(3, Ordering::SeqCst); break; };
                                let recipient = P2PKH::from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap().lock().unwrap();
                                let valid = tx.outputs.iter().any(|o| o.satoshis == Some(10_000) && o.locking_script.to_binary() == recipient.to_binary()) && tx.inputs.len() == 1 && tx.inputs[0].source_txid.as_deref() == Some(id.as_str()) && tx.inputs[0].source_output_index == 0 && tx.outputs.iter().map(|o| o.satoshis.unwrap_or(u64::MAX)).sum::<u64>() <= 50_000;
                                if !valid { bad.store(4, Ordering::SeqCst); break; }
                                let fee = 50_000 - tx.outputs.iter().map(|o| o.satoshis.unwrap()).sum::<u64>();
                                let Some(unlocking) = tx.inputs[0].unlocking_script.clone() else { bad.store(5, Ordering::SeqCst); break; };
                                let mut spend = Spend::new(SpendParams { locking_script: locking.clone(), unlocking_script: unlocking, source_txid: id.clone(), source_output_index: 0, source_satoshis: 50_000, transaction_version: tx.version, transaction_lock_time: tx.lock_time, transaction_sequence: tx.inputs[0].sequence, other_inputs: vec![], other_outputs: tx.outputs.clone(), input_index: 0 });
                                if !matches!(spend.validate(), Ok(true)) || fee < (key.len() / 2 * 10) as u64 { bad.store(6, Ordering::SeqCst); break; }
                                let mut seen = seen.lock().unwrap(); seen.push(key.to_string());
                                if seen.len() == 1 { break; }
                                if seen.len() != 2 || seen[0] != seen[1] { bad.store(7, Ordering::SeqCst); break; }
                                json!(tx.id().unwrap())
                            }
                            _ => { bad.store(8, Ordering::SeqCst); break; }
                        };
                        if write.write_all(format!("{}\n", json!({"jsonrpc":"2.0","id":req["id"],"result":result})).as_bytes()).await.is_err() { break; }
                    }
                });
            }
        });
        crate::commands::network::connect_explicit_server_with_test_roots(&state, crate::network::server_list::ServerEntry::new("127.0.0.1", port), roots()).await.unwrap();
        if let Err(error) = crate::commands::network::sync_wallet_inner(&state, Some(created.account_id)).await {
            panic!("sync failed: {error}; mock failure code {}", failure.load(Ordering::SeqCst));
        }
        let balance = crate::services::account_service::get_balance(&state, Some(created.account_id)).await.unwrap();
        assert_eq!(balance.confirmed, 50_000);
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        assert_eq!(crate::db::repositories::get_wallet_data(&pool, "migration").await.unwrap().as_deref(), Some("34"));
        (created, port, task)
    });
    let result = Arc::new(AtomicU8::new(0));
    let mut context = tauri::generate_context!(); context.config_mut().build.dev_url = None; context.config_mut().app.windows.clear(); context.set_assets(Box::new(PaymentAssets(assets)));
    let setup_result = result.clone();
    let app = tauri::Builder::default().any_thread().manage(state).manage(Fixture { port, path: created.wallet_path, token: created.wallet_instance_token, payloads: payloads.clone() })
        .invoke_handler(tauri::generate_handler![payment_identity, payment_code, payment_wrong_code, payment_observe, payment_reconnect,
            crate::commands::wallet::get_wallet_status, crate::commands::network::get_network_info,
            crate::commands::account::get_accounts, crate::commands::account::get_balance, crate::commands::account::get_multisig_config,
            crate::commands::contacts::get_contacts, crate::commands::extra::get_totp_status,
            crate::commands::transactions::list_spend_plans, crate::commands::transactions::get_spend_plan_status,
            crate::commands::transactions::prepare_tx, crate::commands::transactions::estimate_fee,
            crate::commands::transactions::sign_tx, crate::commands::transactions::broadcast_spend_plan])
        .setup(move |app| {
            let handle = app.handle().clone(); let result = setup_result.clone();
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into())).title("Private payment test")
                .on_navigation(move |url| {
                    if url.scheme() == "https" && url.host_str() == Some("wallet-payment.invalid") {
                        let pass = url.path() == "/pass"; if !pass { eprintln!("WRY_PAYMENT_FAIL {}", url.path()); } result.store(if pass {1} else {2}, Ordering::SeqCst); handle.exit(if pass {0} else {1}); return false;
                    }
                    url.scheme() == "tauri" || (url.scheme() == "http" && url.host_str() == Some("tauri.localhost"))
                }).build()?; Ok(())
        }).build(context).expect("build payment Wry host");
    let exit = app.run_return(|_, _| {}); server.abort();
    assert_eq!(exit, 0); assert_eq!(result.load(Ordering::SeqCst), 1); assert_eq!(failure.load(Ordering::SeqCst), 0);
    assert_eq!(payloads.lock().unwrap().len(), 2);
    println!("WRY_PAYMENT_PASS sync prepare wrong_totp sign eof unknown retry broadcast");
}
