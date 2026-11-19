// These certificates and keys are public test fixtures, never wallet credentials.
use super::{dispatch_inner, Capabilities};
use crate::state::AppState;
use bsv::script::templates::{p2pkh::P2PKH, ScriptTemplateLock};
use bsv::transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput};
use serde_json::{json, Value};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
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
    bad_value: Arc<AtomicBool>, broadcast_seen: Arc<AtomicBool>) -> (u16, tokio::task::JoinHandle<()>) {
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert)));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("loopback permission required");
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            let (target, raw, txid) = (target.clone(), raw.clone(), txid.clone());
            let (bad_value, broadcast_seen) = (bad_value.clone(), broadcast_seen.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(socket).await else { return };
                let (read, mut write) = tokio::io::split(tls);
                let mut lines = BufReader::new(read).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let req: Value = serde_json::from_str(&line).unwrap();
                    let method = req["method"].as_str().unwrap();
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
    let (port, server_task) = server(CERT, target.clone(), funding.to_hex().unwrap(), txid.clone(), bad.clone(), sent.clone()).await;
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

    let (port, wrong_host) = server(WRONG_HOST_CERT, target.clone(), funding.to_hex().unwrap(), txid.clone(), bad.clone(), sent.clone()).await;
    let failure = dispatch_inner(&state, caps, "connect_server", json!({"host":"127.0.0.1","port":port}), Some(roots())).await.unwrap_err();
    assert!(failure.1.contains("TLS error"));
    assert!(!state.network.lock().unwrap().connected);
    wrong_host.abort();
    let (port, foreign_ca) = server(CERT, target, funding.to_hex().unwrap(), txid, bad, sent.clone()).await;
    let failure = dispatch_inner(&state, caps, "connect_server", json!({"host":"127.0.0.1","port":port}), Some(rustls::RootCertStore::empty())).await.unwrap_err();
    assert!(failure.1.contains("TLS error"));
    assert!(!state.network.lock().unwrap().connected);
    assert!(!sent.load(Ordering::SeqCst));
    foreign_ca.abort();
    call("close_wallet", json!({})).await.unwrap();
}
