//! Private ignored test host; this module is never compiled into the application.
use std::{borrow::Cow, path::PathBuf, sync::{Arc, atomic::{AtomicU8, Ordering}}, time::Duration};
use tauri::{Assets, Manager, Runtime, WebviewUrl, WebviewWindowBuilder};
use tauri::utils::assets::{AssetKey, AssetsIter, CspHash};

struct GateAssets { dir: PathBuf }
impl<R: Runtime> Assets<R> for GateAssets {
    fn get(&self, key: &AssetKey) -> Option<Cow<'_, [u8]>> {
        let filename = match key.as_ref() { "/" | "/index.html" => "index.html", "/gate.js" => "gate.js", _ => return None };
        std::fs::read(self.dir.join(filename)).ok().map(Cow::Owned)
    }
    fn iter(&self) -> Box<AssetsIter<'_>> { Box::new(std::iter::empty()) }
    fn csp_hashes(&self, _: &AssetKey) -> Box<dyn Iterator<Item = CspHash<'_>> + '_> { Box::new(std::iter::empty()) }
}

#[test]
#[ignore = "private Xvfb/Wry IPC gate; execute only in isolated child process"]
fn real_wry_production_api_to_readonly_command() {
    let dir = PathBuf::from(std::env::var_os("WALLET_WRY_GATE_ASSET_DIR").expect("WALLET_WRY_GATE_ASSET_DIR required"));
    assert!(dir.join("index.html").is_file() && dir.join("gate.js").is_file());
    let result = Arc::new(AtomicU8::new(0));
    std::thread::spawn(|| { std::thread::sleep(Duration::from_secs(30)); eprintln!("WRY_GATE_TIMEOUT"); std::process::exit(124); });
    let mut context = tauri::generate_context!();
    context.config_mut().build.dev_url = None;
    context.config_mut().app.windows.clear();
    context.set_assets(Box::new(GateAssets { dir }));
    let setup_result = result.clone();
    let app = tauri::Builder::default().any_thread()
        .invoke_handler(tauri::generate_handler![crate::get_app_version])
        .setup(move |app| {
            let handle = app.handle().clone();
            let navigation_result = setup_result.clone();
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Wallet IPC gate")
                .on_navigation(move |url| {
                    if url.scheme() == "https" && url.host_str() == Some("wallet-gate.invalid") {
                        let valid = url.path() == "/pass" && url.query_pairs().find(|(key, _)| key == "version").is_some_and(|(_, value)| value == env!("CARGO_PKG_VERSION"));
                        navigation_result.store(if valid { 1 } else { 2 }, Ordering::SeqCst);
                        handle.exit(if valid { 0 } else { 1 });
                        return false;
                    }
                    url.scheme() == "tauri" || (url.scheme() == "http" && url.host_str() == Some("tauri.localhost"))
                }).build()?;
            Ok(())
        })
        .build(context).expect("build real Wry host");
    let exit_code = app.run_return(|_, _| {});
    assert_eq!(exit_code, 0, "private IPC host exited with failure");
    assert_eq!(result.load(Ordering::SeqCst), 1, "private IPC gate failed or closed before response");
    println!("WRY_GATE_PASS production_api_getAppVersion real_tauri_command");
}

#[test]
#[ignore = "private Xvfb/Wry proof IPC gate; execute only in isolated child process"]
fn real_wry_production_proof_api_with_local_tls() {
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    const CA: &[u8] = include_bytes!("../tests/fixtures/tls/ca.pem");
    const CERT: &[u8] = include_bytes!("../tests/fixtures/tls/server.pem");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/tls/server-key.pem");
    let assets = PathBuf::from(std::env::var_os("WALLET_WRY_PROOF_ASSET_DIR").expect("WALLET_WRY_PROOF_ASSET_DIR required"));
    assert!(assets.join("index.html").is_file() && assets.join("gate.js").is_file());
    let dir = std::env::temp_dir().join(format!("wallet-wry-proof-{}", std::process::id()));
    std::fs::create_dir(&dir).expect("fresh private proof directory");
    let mut state = crate::state::AppState::new(); state.data_dir = dir.to_string_lossy().into();
    let calls = Arc::new(AtomicUsize::new(0));
    let unexpected = Arc::new(AtomicU8::new(0));
    let (port, server_task) = tauri::async_runtime::block_on(async {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("private loopback unavailable");
        let port = listener.local_addr().unwrap().port();
        let chain = rustls_pemfile::certs(&mut &CERT[..]).collect::<Result<Vec<_>, _>>().unwrap();
        let key = rustls_pemfile::private_key(&mut &KEY[..]).unwrap().unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(chain, key).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let count = calls.clone(); let invalid = unexpected.clone();
        let server_task = tauri::async_runtime::spawn(async move {
            let Ok((socket, _)) = listener.accept().await else { invalid.store(1, Ordering::SeqCst); return; };
            let Ok(tls) = acceptor.accept(socket).await else { invalid.store(1, Ordering::SeqCst); return; };
            let (read, mut write) = tokio::io::split(tls);
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(req) = serde_json::from_str::<serde_json::Value>(&line) else { invalid.store(1, Ordering::SeqCst); break; };
                let result = match req["method"].as_str() {
                    Some("server.version") => serde_json::json!(["private-fixture", "1.4"]),
                    Some("blockchain.transaction.get_merkle") => {
                        const GENESIS_TX: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
                        let index = count.fetch_add(1, Ordering::SeqCst);
                        let expected = match index {
                            0 => serde_json::json!([GENESIS_TX, 0]),
                            1 => serde_json::json!(["11".repeat(32), 0]),
                            2 => serde_json::json!([GENESIS_TX, 1]),
                            _ => { invalid.store(1, Ordering::SeqCst); break; }
                        };
                        if req["params"] != expected { invalid.store(1, Ordering::SeqCst); break; }
                        serde_json::json!({"merkle": [], "pos": 0})
                    }
                    _ => { invalid.store(1, Ordering::SeqCst); break; }
                };
                let response = serde_json::json!({"jsonrpc":"2.0", "id":req["id"], "result":result});
                if write.write_all(format!("{response}\n").as_bytes()).await.is_err() {
                    invalid.store(1, Ordering::SeqCst);
                    break;
                }
            }
        });
        (port, server_task)
    });
    tauri::async_runtime::block_on(async {
        let header_path = dir.join("headers.sqlite");
        let store = Arc::new(crate::network::header_store::HeaderStore::open(&header_path.to_string_lossy()).await.unwrap());
        store.ensure_genesis().await.unwrap();
        state.network.lock().unwrap().header_store = Some(store);
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut &CA[..]) { roots.add(cert.unwrap()).unwrap(); }
        crate::commands::network::connect_explicit_server_with_test_roots(&state, crate::network::server_list::ServerEntry::new("127.0.0.1", port), roots).await.expect("preconnect private TLS mock");
    });
    let result = Arc::new(AtomicU8::new(0));
    std::thread::spawn(|| { std::thread::sleep(Duration::from_secs(30)); eprintln!("WRY_PROOF_GATE_TIMEOUT"); std::process::exit(124); });
    let mut context = tauri::generate_context!();
    context.config_mut().build.dev_url = None;
    context.config_mut().app.windows.clear();
    context.set_assets(Box::new(GateAssets { dir: assets }));
    let setup_result = result.clone();
    let app = tauri::Builder::default().any_thread().manage(state)
        .invoke_handler(tauri::generate_handler![crate::commands::network::verify_transaction_proof])
        .setup(move |app| {
            let handle = app.handle().clone(); let navigation_result = setup_result.clone();
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into())).title("Wallet proof IPC gate")
                .on_navigation(move |url| {
                    if url.scheme() == "https" && url.host_str() == Some("wallet-gate.invalid") {
                        let valid = url.path() == "/proof-pass";
                        navigation_result.store(if valid { 1 } else { 2 }, Ordering::SeqCst);
                        handle.exit(if valid { 0 } else { 1 }); return false;
                    }
                    url.scheme() == "tauri" || (url.scheme() == "http" && url.host_str() == Some("tauri.localhost"))
                }).build()?;
            Ok(())
        }).build(context).expect("build real proof Wry host");
    let exit_code = app.run_return(|_, _| {});
    server_task.abort();
    assert_eq!(exit_code, 0, "proof IPC host exited with failure");
    assert_eq!(result.load(Ordering::SeqCst), 1, "proof IPC gate failed or closed before response");
    assert_eq!(calls.load(Ordering::SeqCst), 3, "expected true, false, missing-header RPCs only");
    assert_eq!(unexpected.load(Ordering::SeqCst), 0, "unexpected fixture request");
    println!("WRY_PROOF_GATE_PASS true false invalid_argument missing_header rpc_count_3");
}
