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

pub(crate) fn roots() -> rustls::RootCertStore {
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

pub(crate) async fn scan_server(targets: std::collections::HashMap<String, (String,String,u64)>, histories: Arc<AtomicUsize>, gate: Option<(tokio::sync::oneshot::Sender<()>,tokio::sync::oneshot::Receiver<()>)>, bad_index: bool) -> (u16, tokio::task::JoinHandle<()>) {
    let acceptor = TlsAcceptor::from(Arc::new(server_config(CERT)));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let targets = Arc::new(targets);
    let task = tokio::spawn(async move {
        let mut gate = gate;
        let (socket, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(socket).await.unwrap();
        let (read, mut write) = tokio::io::split(tls);
        let mut lines = BufReader::new(read).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let req: Value = serde_json::from_str(&line).unwrap();
            let method = req["method"].as_str().unwrap();
            let key = req["params"][0].as_str().unwrap_or("");
            let target = targets.get(key);
            let result = match method {
                "server.version" => json!(["local-test", "1.4"]),
                "blockchain.scripthash.get_history" => {
                    histories.fetch_add(1, Ordering::SeqCst);
                    if let Some((started,resume)) = gate.take() { let _ = started.send(()); let _ = resume.await; }
                    target.map_or(json!([]), |(_,txid,_)| json!([{"tx_hash":txid,"height":123}]))
                }
                "blockchain.scripthash.get_balance" => json!({"confirmed":target.map_or(0, |(_,_,value)| *value), "unconfirmed":0}),
                "blockchain.scripthash.listunspent" => target.map_or(json!([]), |(_,txid,value)| json!([{"tx_hash":txid,"tx_pos":if bad_index { u64::from(u32::MAX)+1 } else { 0 },"value":value,"height":123}])),
                "blockchain.transaction.get" => targets.values().find(|(_,txid,_)| txid == key).map_or(Value::Null, |(raw,_,_)| json!(raw)),
                "blockchain.scripthash.subscribe" => Value::Null,
                _ => panic!("unexpected scan RPC method {method}"),
            };
            let response = json!({"id":req["id"], "result":result});
            if write.write_all(format!("{response}\n").as_bytes()).await.is_err() { break; }
        }
    });
    (port, task)
}

#[tokio::test]
async fn agent_tls_empty_wallet_sync_and_address_lifecycle() {
    use crate::db::repositories;
    let dir = std::env::temp_dir().join(format!("electrumsv-empty-sync-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut state = AppState::new();
    state.data_dir = dir.to_str().unwrap().into();
    let caps = Capabilities { network: true, ..Default::default() };
    let call = |method, params| dispatch_inner(&state, caps, method, params, None);
    let created = call("create_wallet", json!({"name":"synthetic","password":"pw","mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"})).await.unwrap();
    let account = created["account_id"].as_i64().unwrap();
    let token = created["wallet_instance_token"].as_str().unwrap();
    let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
    let histories = Arc::new(AtomicUsize::new(0));
    let (port, server_task) = scan_server(std::collections::HashMap::new(), histories.clone(), None, false).await;
    dispatch_inner(&state, caps, "connect_server", json!({"host":"127.0.0.1","port":port}), Some(roots())).await.unwrap();
    let marker = format!("address_discovery_v1_{account}");
    sqlx::query("INSERT INTO WalletData(key,value,date_created,date_updated) VALUES (?,'done',1,1)").bind(&marker).execute(&pool).await.unwrap();
    let marked = call("sync_wallet",json!({"account_id":account,"wallet_instance_token":token})).await.unwrap();
    assert_eq!(marked["synced"],false);
    assert!(marked["message"].as_str().unwrap().contains("already marked complete"));
    assert_eq!(histories.load(Ordering::SeqCst),0);
    sqlx::query("DELETE FROM WalletData WHERE key=?").bind(&marker).execute(&pool).await.unwrap();
    let result = call("sync_wallet",json!({"account_id":account,"wallet_instance_token":token})).await.unwrap();
    assert_eq!(result["synced"], true);
    assert!(result["message"].as_str().unwrap().contains("No activity"));
    assert_eq!(histories.load(Ordering::SeqCst),40);
    assert!(repositories::get_keyinstances_for_account(&pool,account).await.unwrap().is_empty());
    assert!(repositories::get_wallet_data(&pool,&marker).await.unwrap().is_none());
    assert_eq!(call("get_balance",json!({"account_id":account})).await.unwrap()["total"],0);
    let second = call("sync_wallet",json!({"account_id":account,"wallet_instance_token":token})).await.unwrap();
    assert_eq!(second["synced"],true);
    assert_eq!(histories.load(Ordering::SeqCst),80);
    assert!(repositories::get_wallet_data(&pool,&marker).await.unwrap().is_none());
    let address = call("get_receive_address",json!({"account_id":account})).await.unwrap();
    assert_eq!(address["derivation_index"],0);
    assert_eq!(call("sync_wallet",json!({"account_id":account,"wallet_instance_token":token})).await.unwrap()["synced"],true);
    assert_eq!(repositories::get_keyinstances_for_account(&pool,account).await.unwrap().len(),1);
    assert_eq!(repositories::get_wallet_data(&pool,&marker).await.unwrap().as_deref(),Some("done"));
    call("disconnect_server",json!({})).await.unwrap();
    server_task.abort();
    drop(pool);
    call("close_wallet",json!({})).await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn agent_tls_empty_wallet_sync_rejects_changed_wallet_key_and_server_failure() {
    use crate::db::repositories;
    for case in ["reopen", "new_key", "server_eof"] {
        let dir = std::env::temp_dir().join(format!("electrumsv-empty-race-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = AppState::new(); state.data_dir = dir.to_str().unwrap().into();
        let caps = Capabilities { network: true, ..Default::default() };
        let call = |method, params| dispatch_inner(&state, caps, method, params, None);
        let created = call("create_wallet", json!({"name":"synthetic","password":"pw","mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"})).await.unwrap();
        let account = created["account_id"].as_i64().unwrap();
        let token = created["wallet_instance_token"].as_str().unwrap();
        let (started_tx,started_rx) = tokio::sync::oneshot::channel();
        let (resume_tx,resume_rx) = tokio::sync::oneshot::channel();
        let (port,server_task) = scan_server(std::collections::HashMap::new(), Arc::new(AtomicUsize::new(0)), Some((started_tx,resume_rx)), false).await;
        dispatch_inner(&state,caps,"connect_server",json!({"host":"127.0.0.1","port":port}),Some(roots())).await.unwrap();
        let sync = crate::commands::network::sync_wallet_with_token_inner(&state,Some(account),Some(token));
        tokio::pin!(sync);
        tokio::select! { result = &mut sync => panic!("sync finished before barrier: {result:?}"), _ = started_rx => {} }
        match case {
            "reopen" => {
                call("close_wallet",json!({})).await.unwrap();
                call("open_wallet",json!({"wallet_path":"synthetic"})).await.unwrap();
                resume_tx.send(()).unwrap();
            }
            "new_key" => {
                call("get_receive_address",json!({"account_id":account})).await.unwrap();
                resume_tx.send(()).unwrap();
            }
            _ => { server_task.abort(); drop(resume_tx); }
        }
        let error = sync.await.unwrap_err();
        assert!(error.contains(match case { "reopen" => "active wallet changed", "new_key" => "account keys changed", _ => "address discovery failed" }), "{case}: {error}");
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        assert_eq!(repositories::get_keyinstances_for_account(&pool,account).await.unwrap().len(),usize::from(case == "new_key"));
        assert!(repositories::get_wallet_data(&pool,&format!("address_discovery_v1_{account}")).await.unwrap().is_none());
        assert!(repositories::get_utxos_for_account(&pool,account).await.unwrap().is_empty());
        call("disconnect_server",json!({})).await.unwrap();
        server_task.abort(); drop(pool);
        call("close_wallet",json!({})).await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn agent_tls_explicit_scan_both_branches_preserves_marker() {
    use bsv::compat::bip32::ExtendedKey;
    use crate::db::repositories;
    for marker in [false,true] {
        let dir = std::env::temp_dir().join(format!("electrumsv-explicit-scan-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = AppState::new();
        state.data_dir = dir.to_str().unwrap().into();
        let caps = Capabilities { network: true, ..Default::default() };
        let call = |method, params| dispatch_inner(&state, caps, method, params, None);
        let created = call("create_wallet", json!({"name":"synthetic","password":"pw","mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"})).await.unwrap();
        let account = created["account_id"].as_i64().unwrap();
        let (pool,xprv,token) = {
            let guard = state.active_wallet.lock().unwrap();
            let wallet = guard.as_ref().unwrap();
            (wallet.db_pool.clone(),wallet.decrypted_xprv.clone().unwrap(),wallet.instance_token.clone())
        };
        let master: (i64,) = sqlx::query_as("SELECT default_masterkey_id FROM Accounts WHERE account_id=?").bind(account).fetch_one(&pool).await.unwrap();
        sqlx::query("INSERT INTO KeyInstances (keyinstance_id,account_id,masterkey_id,derivation_type,derivation_data,script_type,flags,date_created,date_updated) VALUES (-1,?,?,?,?,?,0,1,1)")
            .bind(account).bind(master.0).bind(repositories::derivation_type::BIP32).bind(br#"{"subpath":[0,0]}"#.as_slice()).bind(repositories::script_type::P2PKH).execute(&pool).await.unwrap();
        if marker { sqlx::query("INSERT INTO WalletData(key,value,date_created,date_updated) VALUES (?,?,1,1)").bind(format!("address_discovery_v1_{account}")).bind("done").execute(&pool).await.unwrap(); }
        let key = ExtendedKey::from_string(&xprv).unwrap();
        let mut targets = std::collections::HashMap::new();
        for chain in 0..=1 {
            let public = key.derive(&format!("{chain}/25")).unwrap().public_key().unwrap();
            let address = crate::core::address::pubkey_to_p2pkh_address(&public);
            let target = crate::network::backend::scripthash_from_address(&address).unwrap();
            let mut tx = Transaction::new();
            tx.inputs.push(TransactionInput { source_txid: Some("00".repeat(32)), source_output_index: u32::MAX, ..Default::default() });
            tx.outputs.push(TransactionOutput { satoshis: Some(50_000 + chain), locking_script: P2PKH::from_address(&address).unwrap().lock().unwrap(), change: false });
            targets.insert(target, (tx.to_hex().unwrap(),tx.id().unwrap(),50_000+chain));
        }
        let histories = Arc::new(AtomicUsize::new(0));
        let (port, server_task) = scan_server(targets, histories.clone(), None, false).await;
        dispatch_inner(&state, caps, "connect_server", json!({"host":"127.0.0.1","port":port}), Some(roots())).await.unwrap();
        let params = json!({"account_id":account,"wallet_instance_token":token,"end_index_exclusive":26});
        assert_eq!(dispatch_inner(&state, Capabilities::default(), "scan_address_range", params.clone(), None).await.unwrap_err().0, -32000);
        assert_eq!(call("scan_address_range", json!({"account_id":account,"wallet_instance_token":token,"end_index_exclusive":1001})).await.unwrap_err().0, -32602);
        let result = call("scan_address_range", params).await.unwrap();
        assert_eq!((result["start_index"].as_u64(),result["end_index_exclusive"].as_u64(),result["new_keys"].as_u64()),(Some(0),Some(26),Some(2)));
        assert_eq!(histories.load(Ordering::SeqCst),55);
        let keys = repositories::get_keyinstances_for_account(&pool,account).await.unwrap();
        assert_eq!(keys.len(),3);
        assert!(keys.iter().any(|key| key.keyinstance_id == -1));
        let outputs = repositories::get_utxos_for_account(&pool,account).await.unwrap();
        for chain in 0..=1 {
            let discovered = keys.iter().find(|key| serde_json::from_slice::<Value>(&key.derivation_data).unwrap()["subpath"] == json!([chain,25])).unwrap();
            let output = outputs.iter().find(|out| out.value == 50_000 + chain).unwrap();
            assert_eq!(output.keyinstance_id,discovered.keyinstance_id);
        }
        assert_eq!(repositories::get_wallet_data(&pool,&format!("address_discovery_v1_{account}")).await.unwrap().as_deref(),marker.then_some("done"));
        let history = call("get_history",json!({"account_id":account})).await.unwrap();
        assert_eq!(history.as_array().unwrap().len(),2);
        let balance = call("get_balance",json!({"account_id":account})).await.unwrap();
        let key_snapshot = keys.iter().map(|key| (key.keyinstance_id,key.derivation_data.clone())).collect::<Vec<_>>();
        let output_snapshot = outputs.iter().map(|out| (out.tx_hash.clone(),out.tx_index,out.keyinstance_id,out.value,out.script_pubkey.clone())).collect::<Vec<_>>();
        let history_count = histories.load(Ordering::SeqCst);
        drop(pool);
        call("close_wallet",json!({})).await.unwrap();
        let wallet_path = created["wallet_path"].as_str().unwrap();
        crate::services::wallet_service::open_wallet(&state,wallet_path).await.unwrap();
        crate::services::wallet_service::unlock_wallet_authorized(&state,"pw",None).await.unwrap();
        let pool = { state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone() };
        let reopened_keys = repositories::get_keyinstances_for_account(&pool,account).await.unwrap();
        assert_eq!(reopened_keys.iter().map(|key| (key.keyinstance_id,key.derivation_data.clone())).collect::<Vec<_>>(),key_snapshot);
        let reopened_outputs = repositories::get_utxos_for_account(&pool,account).await.unwrap();
        assert_eq!(reopened_outputs.iter().map(|out| (out.tx_hash.clone(),out.tx_index,out.keyinstance_id,out.value,out.script_pubkey.clone())).collect::<Vec<_>>(),output_snapshot);
        assert_eq!(call("get_history",json!({"account_id":account})).await.unwrap(),history);
        assert_eq!(call("get_balance",json!({"account_id":account})).await.unwrap(),balance);
        assert_eq!(repositories::get_wallet_data(&pool,&format!("address_discovery_v1_{account}")).await.unwrap().as_deref(),marker.then_some("done"));
        assert!(crate::commands::network::sync_wallet_inner(&state,Some(account)).await.unwrap().synced);
        let extra_histories = histories.load(Ordering::SeqCst)-history_count;
        if marker { assert_eq!(extra_histories,keys.len()); } else { assert!(extra_histories > keys.len()); }
        let resynced_keys = repositories::get_keyinstances_for_account(&pool,account).await.unwrap();
        assert_eq!(resynced_keys.iter().map(|key| (key.keyinstance_id,key.derivation_data.clone())).collect::<Vec<_>>(),key_snapshot);
        let resynced_outputs = repositories::get_utxos_for_account(&pool,account).await.unwrap();
        assert_eq!(resynced_outputs.iter().map(|out| (out.tx_hash.clone(),out.tx_index,out.keyinstance_id,out.value,out.script_pubkey.clone())).collect::<Vec<_>>(),output_snapshot);
        assert_eq!(call("get_history",json!({"account_id":account})).await.unwrap(),history);
        assert_eq!(call("get_balance",json!({"account_id":account})).await.unwrap(),balance);
        assert_eq!(repositories::get_wallet_data(&pool,&format!("address_discovery_v1_{account}")).await.unwrap().as_deref(),Some("done"));
        call("disconnect_server",json!({})).await.unwrap();
        server_task.abort();
        drop(pool);
        call("close_wallet",json!({})).await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn agent_tls_explicit_scan_rejects_wallet_reopen_before_commit() {
    use crate::db::repositories;
    let dir = std::env::temp_dir().join(format!("electrumsv-scan-reopen-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut state = AppState::new();
    state.data_dir = dir.to_str().unwrap().into();
    let caps = Capabilities { network: true, ..Default::default() };
    let call = |method, params| dispatch_inner(&state, caps, method, params, None);
    let created = call("create_wallet", json!({"name":"synthetic","password":"pw","mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"})).await.unwrap();
    let account = created["account_id"].as_i64().unwrap();
    let path = created["wallet_path"].as_str().unwrap().to_owned();
    let (pool,token) = {
        let guard = state.active_wallet.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        (wallet.db_pool.clone(),wallet.instance_token.clone())
    };
    let master: (i64,) = sqlx::query_as("SELECT default_masterkey_id FROM Accounts WHERE account_id=?").bind(account).fetch_one(&pool).await.unwrap();
    sqlx::query("INSERT INTO KeyInstances (keyinstance_id,account_id,masterkey_id,derivation_type,derivation_data,script_type,flags,date_created,date_updated) VALUES (-1,?,?,?,?,?,0,1,1)")
        .bind(account).bind(master.0).bind(repositories::derivation_type::BIP32).bind(br#"{"subpath":[0,0]}"#.as_slice()).bind(repositories::script_type::P2PKH).execute(&pool).await.unwrap();
    let (started_tx,started_rx) = tokio::sync::oneshot::channel();
    let (resume_tx,resume_rx) = tokio::sync::oneshot::channel();
    let (port,server_task) = scan_server(std::collections::HashMap::new(), Arc::new(AtomicUsize::new(0)), Some((started_tx,resume_rx)), false).await;
    dispatch_inner(&state,caps,"connect_server",json!({"host":"127.0.0.1","port":port}),Some(roots())).await.unwrap();
    let scan = crate::commands::network::scan_address_range_inner(&state,account,&token,1);
    tokio::pin!(scan);
    tokio::select! { result = &mut scan => panic!("scan finished before barrier: {result:?}"), _ = started_rx => {} }
    drop(pool);
    call("close_wallet",json!({})).await.unwrap();
    crate::services::wallet_service::open_wallet(&state,&path).await.unwrap();
    resume_tx.send(()).unwrap();
    assert!(scan.await.unwrap_err().contains("active wallet changed"));
    let pool = { state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone() };
    let keys = repositories::get_keyinstances_for_account(&pool,account).await.unwrap();
    assert_eq!(keys.len(),1);
    assert_eq!(keys[0].keyinstance_id,-1);
    assert!(repositories::get_wallet_data(&pool,&format!("address_discovery_v1_{account}")).await.unwrap().is_none());
    assert!(repositories::get_utxos_for_account(&pool,account).await.unwrap().is_empty());
    call("disconnect_server",json!({})).await.unwrap();
    server_task.abort();
    drop(pool);
    call("close_wallet",json!({})).await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn agent_tls_explicit_scan_rejects_overflowing_index_without_commit() {
    use bsv::compat::bip32::ExtendedKey;
    use crate::db::repositories;
    let dir = std::env::temp_dir().join(format!("electrumsv-scan-bad-index-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut state = AppState::new();
    state.data_dir = dir.to_str().unwrap().into();
    let caps = Capabilities { network: true, ..Default::default() };
    let call = |method, params| dispatch_inner(&state,caps,method,params,None);
    let created = call("create_wallet",json!({"name":"synthetic","password":"pw","mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"})).await.unwrap();
    let account = created["account_id"].as_i64().unwrap();
    let (pool,xprv,token) = {
        let guard = state.active_wallet.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        (wallet.db_pool.clone(),wallet.decrypted_xprv.clone().unwrap(),wallet.instance_token.clone())
    };
    let public = ExtendedKey::from_string(&xprv).unwrap().derive("0/0").unwrap().public_key().unwrap();
    let address = crate::core::address::pubkey_to_p2pkh_address(&public);
    let target = crate::network::backend::scripthash_from_address(&address).unwrap();
    let mut funding = Transaction::new();
    funding.inputs.push(TransactionInput { source_txid:Some("00".repeat(32)), source_output_index:u32::MAX, ..Default::default() });
    funding.outputs.push(TransactionOutput { satoshis:Some(50), locking_script:P2PKH::from_address(&address).unwrap().lock().unwrap(), change:false });
    let mut targets = std::collections::HashMap::new();
    targets.insert(target,(funding.to_hex().unwrap(),funding.id().unwrap(),50));
    let (port,server_task) = scan_server(targets,Arc::new(AtomicUsize::new(0)),None,true).await;
    dispatch_inner(&state,caps,"connect_server",json!({"host":"127.0.0.1","port":port}),Some(roots())).await.unwrap();
    assert!(crate::commands::network::scan_address_range_inner(&state,account,&token,1).await.unwrap_err().contains("tx_pos"));
    assert!(repositories::get_keyinstances_for_account(&pool,account).await.unwrap().is_empty());
    assert!(repositories::get_wallet_data(&pool,&format!("address_discovery_v1_{account}")).await.unwrap().is_none());
    assert!(repositories::get_utxos_for_account(&pool,account).await.unwrap().is_empty());
    assert!(call("get_history",json!({"account_id":account})).await.unwrap().as_array().unwrap().is_empty());
    let transactions: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM Transactions").fetch_one(&pool).await.unwrap();
    let deltas: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM TransactionDeltas").fetch_one(&pool).await.unwrap();
    assert_eq!((transactions.0,deltas.0),(0,0));
    call("disconnect_server",json!({})).await.unwrap();
    server_task.abort();
    drop(pool);
    call("close_wallet",json!({})).await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
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
    let token = created["wallet_instance_token"].as_str().unwrap();
    assert!(call("sync_wallet", json!({"account_id":account,"wallet_instance_token":"wrong"})).await.unwrap_err().1.contains("token changed"));
    assert_eq!(history_requests.load(Ordering::SeqCst), 0);
    assert_eq!(call("sync_wallet", json!({"account_id":account,"wallet_instance_token":token})).await.unwrap()["synced"], true);
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
    drop(pool);
    call("close_wallet", json!({})).await.unwrap();
    let reopened = call("open_wallet", json!({"wallet_path":"synthetic"})).await.unwrap();
    let history_before_stale = history_requests.load(Ordering::SeqCst);
    assert!(call("sync_wallet", json!({"account_id":account,"wallet_instance_token":token})).await.unwrap_err().1.contains("token changed"));
    assert_eq!(history_requests.load(Ordering::SeqCst), history_before_stale);
    call("unlock_wallet", json!({"password":"pw"})).await.unwrap();
    assert_eq!(call("sync_wallet", json!({"account_id":account,"wallet_instance_token":reopened["wallet_instance_token"]})).await.unwrap()["synced"], true);
    call("disconnect_server", json!({})).await.unwrap();
    server_task.abort();
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
