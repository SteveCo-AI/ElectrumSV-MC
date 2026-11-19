// These certificates and keys are public test fixtures, never wallet credentials.
use super::{dispatch_inner, Capabilities};
use crate::state::AppState;
use bsv::script::templates::{p2pkh::P2PKH, ScriptTemplateLock};
use bsv::transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput};
use serde_json::{json, Value};
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const CA: &[u8] = include_bytes!("../tests/fixtures/tls/ca.pem");
const CERT: &[u8] = include_bytes!("../tests/fixtures/tls/server.pem");
const WRONG_HOST_CERT: &[u8] = include_bytes!("../tests/fixtures/tls/wrong-host.pem");
const KEY: &[u8] = include_bytes!("../tests/fixtures/tls/server-key.pem");

fn roots() -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &CA[..]) { store.add(cert.unwrap()).unwrap(); }
    store
}

fn server_config(cert: &[u8]) -> rustls::ServerConfig {
    let chain = rustls_pemfile::certs(&mut &cert[..]).collect::<Result<Vec<_>, _>>().unwrap();
    let key = rustls_pemfile::private_key(&mut &KEY[..]).unwrap().unwrap();
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(chain, key).unwrap()
}

#[test]
fn tls_fixture_config_uses_explicit_provider_without_network() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    let _ = server_config(CERT);
    let _ = server_config(WRONG_HOST_CERT);
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
}

async fn server(cert: &'static [u8], target: String, raw: String, txid: String,
    bad_value: Arc<AtomicBool>, broadcast_seen: Arc<AtomicBool>, history_requests: Option<Arc<AtomicUsize>>) -> (u16, tokio::task::JoinHandle<()>) {
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert)));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("loopback permission required");
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            let (target, raw, txid) = (target.clone(), raw.clone(), txid.clone());
            let (bad_value, broadcast_seen) = (bad_value.clone(), broadcast_seen.clone());
            let history_requests = history_requests.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(socket).await else { return };
                let (read, mut write) = tokio::io::split(tls);
                let mut lines = BufReader::new(read).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let req: Value = serde_json::from_str(&line).unwrap();
                    let method = req["method"].as_str().unwrap();
                    if method == "blockchain.scripthash.get_history" {
                        if let Some(counter) = &history_requests { counter.fetch_add(1, Ordering::SeqCst); }
                    }
                    let key = req["params"][0].as_str().unwrap_or("");
                    let matches_key = key == target;
                    let result = match method {
                        "server.version" => json!(["local-test", "1.4"]),
                        "blockchain.scripthash.get_balance" => json!({"confirmed": if matches_key { 50_000 } else { 0 }, "unconfirmed":0}),
                        "blockchain.scripthash.get_history" => if matches_key { json!([{"tx_hash":txid,"height":123}]) } else { json!([]) },
                        "blockchain.scripthash.listunspent" => if matches_key {
                            json!([{"tx_hash":txid,"tx_pos":0,"value":if bad_value.load(Ordering::SeqCst) { 49_999 } else { 50_000 },"height":123}])
                        } else { json!([]) },
                        "blockchain.transaction.get" if key == txid => json!(raw),
                        "blockchain.scripthash.subscribe" => Value::Null,
                        "blockchain.transaction.broadcast" => { broadcast_seen.store(true, Ordering::SeqCst); break; },
                        _ => panic!("unexpected mock RPC method {method}"),
                    };
                    let response = json!({"jsonrpc":"2.0","id":req["id"],"result":result});
                    if write.write_all(format!("{response}\n").as_bytes()).await.is_err() { break; }
                }
            });
        }
    });
    (port, task)
}

#[tokio::test]
async fn agent_tls_synthetic_negative_key_and_discovery_sync() {
    use bsv::compat::bip32::ExtendedKey;
    use crate::db::repositories;
    let dir = std::env::temp_dir().join(format!("electrumsv-negative-sync-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut state = AppState::new();
    state.data_dir = dir.to_str().unwrap().into();
    let caps = Capabilities { network: true, payments: false, broadcast: false, ..Default::default() };
    let call = |method, params| dispatch_inner(&state, caps, method, params, None);
    let created = call("create_wallet", json!({"name":"synthetic","password":"pw","mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"})).await.unwrap();
    let account = created["account_id"].as_i64().unwrap();
    let (pool, xprv) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        (active.db_pool.clone(), active.decrypted_xprv.clone().unwrap())
    };
    let master: (i64,) = sqlx::query_as("SELECT default_masterkey_id FROM Accounts WHERE account_id=?").bind(account).fetch_one(&pool).await.unwrap();
    sqlx::query("INSERT INTO KeyInstances (keyinstance_id,account_id,masterkey_id,derivation_type,derivation_data,script_type,flags,date_created,date_updated) VALUES (-1,?,?,?,?,?,0,1,1)")
        .bind(account).bind(master.0).bind(repositories::derivation_type::BIP32).bind(br#"{"subpath":[0,0]}"#.as_slice()).bind(repositories::script_type::P2PKH).execute(&pool).await.unwrap();
    let account_key = ExtendedKey::from_string(&xprv).unwrap();
    let pubkey = account_key.derive("0/1").unwrap().public_key().unwrap();
    let address = crate::core::address::pubkey_to_p2pkh_address(&pubkey);
    let target = crate::network::backend::scripthash_from_address(&address).unwrap();
    let script = P2PKH::from_address(&address).unwrap().lock().unwrap();
    let mut funding = Transaction::new();
    funding.inputs.push(TransactionInput { source_txid: Some("00".repeat(32)), source_output_index: u32::MAX, ..Default::default() });
    funding.outputs.push(TransactionOutput { satoshis: Some(50_000), locking_script: script, change: false });
    let txid = funding.id().unwrap();
    let sent = Arc::new(AtomicBool::new(false));
    let history_requests = Arc::new(AtomicUsize::new(0));
    let (port, server_task) = server(CERT, target, funding.to_hex().unwrap(), txid.clone(), Arc::new(AtomicBool::new(false)), sent.clone(), Some(history_requests.clone())).await;
    dispatch_inner(&state, caps, "connect_server", json!({"host":"127.0.0.1","port":port}), Some(roots())).await.unwrap();
    assert_eq!(call("sync_wallet", json!({"account_id":account})).await.unwrap()["synced"], true);
    let keys = repositories::get_keyinstances_for_account(&pool, account).await.unwrap();
    assert!(keys.iter().any(|key| key.keyinstance_id == -1));
    let discovered = keys.iter().find(|key| serde_json::from_slice::<Value>(&key.derivation_data).unwrap()["subpath"] == json!([0,1])).unwrap();
    assert_ne!(discovered.keyinstance_id, -1);
    let outputs = repositories::get_utxos_for_account(&pool, account).await.unwrap();
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].keyinstance_id, discovered.keyinstance_id);
    assert_eq!(outputs[0].value, 50_000);
    assert_eq!(repositories::get_wallet_data(&pool, &format!("address_discovery_v1_{account}")).await.unwrap().as_deref(), Some("done"));
    let history = call("get_history", json!({"account_id":account})).await.unwrap();
    assert_eq!(history[0]["tx_hash"], txid);
    assert_eq!(history[0]["value_delta"], 50_000);
    let first_history_requests = history_requests.load(Ordering::SeqCst);
    assert!(first_history_requests > keys.len());
    let key_snapshot = keys.iter().map(|key| (key.keyinstance_id, key.derivation_data.clone())).collect::<Vec<_>>();
    let output_snapshot = outputs.iter().map(|output| (output.tx_hash.clone(), output.tx_index, output.keyinstance_id, output.value, output.script_pubkey.clone())).collect::<Vec<_>>();
    assert_eq!(call("sync_wallet", json!({"account_id":account})).await.unwrap()["synced"], true);
    assert_eq!(history_requests.load(Ordering::SeqCst) - first_history_requests, keys.len());
    let after_keys = repositories::get_keyinstances_for_account(&pool, account).await.unwrap();
    assert_eq!(after_keys.iter().map(|key| (key.keyinstance_id, key.derivation_data.clone())).collect::<Vec<_>>(), key_snapshot);
    let after_outputs = repositories::get_utxos_for_account(&pool, account).await.unwrap();
    assert_eq!(after_outputs.iter().map(|output| (output.tx_hash.clone(), output.tx_index, output.keyinstance_id, output.value, output.script_pubkey.clone())).collect::<Vec<_>>(), output_snapshot);
    assert_eq!(call("get_history", json!({"account_id":account})).await.unwrap(), history);
    assert_eq!(repositories::get_wallet_data(&pool, &format!("address_discovery_v1_{account}")).await.unwrap().as_deref(), Some("done"));
    assert!(!sent.load(Ordering::SeqCst));
    call("disconnect_server", json!({})).await.unwrap();
    server_task.abort();
    drop(pool);
    call("close_wallet", json!({})).await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn agent_tls_connect_sync_history_and_atomic_error() {
    let dir = std::env::temp_dir().join(format!("electrumsv-agent-tls-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut state = AppState::new();
    state.data_dir = dir.to_str().unwrap().into();
    let caps = Capabilities { network: true, payments: false, broadcast: false, ..Default::default() };
    let call = |method, params| dispatch_inner(&state, caps, method, params, None);
    let created = call("create_wallet", json!({"name":"synthetic","password":"pw","mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"})).await.unwrap();
    let account = created["account_id"].as_i64().unwrap();
    let receive = call("get_receive_address", json!({"account_id":account})).await.unwrap();
    let address = receive["address"].as_str().unwrap();
    let target = crate::network::backend::scripthash_from_address(address).unwrap();
    let script = P2PKH::from_address(address).unwrap().lock().unwrap();
    let mut funding = Transaction::new();
    funding.inputs.push(TransactionInput { source_txid: Some("00".repeat(32)), source_output_index: u32::MAX, ..Default::default() });
    funding.outputs.push(TransactionOutput { satoshis: Some(50_000), locking_script: script, change: false });
    let txid = funding.id().unwrap();
    let bad = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicBool::new(false));
    let (port, server_task) = server(CERT, target.clone(), funding.to_hex().unwrap(), txid.clone(), bad.clone(), sent.clone(), None).await;
    let connect = dispatch_inner(&state, caps, "connect_server", json!({"host":"127.0.0.1","port":port}), Some(roots())).await.unwrap();
    assert_eq!(connect, json!("127.0.0.1"));
    let sync = call("sync_wallet", json!({"account_id":account})).await.unwrap();
    assert_eq!(sync["synced"], true);
    let balance = call("get_balance", json!({"account_id":account})).await.unwrap();
    assert_eq!(balance["confirmed"], 50_000);
    let history = call("get_history", json!({"account_id":account})).await.unwrap();
    assert_eq!(history.as_array().unwrap().len(), 1);
    assert_eq!(history[0]["tx_hash"], txid);
    assert_eq!(history[0]["value_delta"], 50_000);
    assert_eq!(call("get_history", json!({"account_id":account,"limit":1,"offset":0})).await.unwrap(), history);
    assert_eq!(call("get_history", json!({"account_id":account,"limit":1,"offset":1})).await.unwrap(), json!([]));
    assert_eq!(call("get_history", json!({"account_id":account,"limit":500})).await.unwrap(), history);
    for params in [json!({"limit":0}), json!({"limit":-1}), json!({"limit":501}), json!({"offset":-1})] {
        assert_eq!(call("get_history", params).await.unwrap_err().0, -32602);
    }
    let next = call("get_receive_address", json!({"account_id":account})).await.unwrap();
    assert_ne!(next["address"], receive["address"]);
    bad.store(true, Ordering::SeqCst);
    assert!(call("sync_wallet", json!({"account_id":account})).await.is_err());
    assert_eq!(call("get_balance", json!({"account_id":account})).await.unwrap(), balance);
    assert_eq!(call("get_history", json!({"account_id":account})).await.unwrap(), history);
    assert!(!sent.load(Ordering::SeqCst));
    call("disconnect_server", json!({})).await.unwrap();
    server_task.abort();

    let (port, wrong_host) = server(WRONG_HOST_CERT, target.clone(), funding.to_hex().unwrap(), txid.clone(), bad.clone(), sent.clone(), None).await;
    let failure = dispatch_inner(&state, caps, "connect_server", json!({"host":"127.0.0.1","port":port}), Some(roots())).await.unwrap_err();
    assert!(failure.1.contains("TLS error"));
    assert!(!state.network.lock().unwrap().connected);
    wrong_host.abort();
    let (port, foreign_ca) = server(CERT, target, funding.to_hex().unwrap(), txid, bad, sent.clone(), None).await;
    let failure = dispatch_inner(&state, caps, "connect_server", json!({"host":"127.0.0.1","port":port}), Some(rustls::RootCertStore::empty())).await.unwrap_err();
    assert!(failure.1.contains("TLS error"));
    assert!(!state.network.lock().unwrap().connected);
    assert!(!sent.load(Ordering::SeqCst));
    foreign_ca.abort();
    call("close_wallet", json!({})).await.unwrap();
}
