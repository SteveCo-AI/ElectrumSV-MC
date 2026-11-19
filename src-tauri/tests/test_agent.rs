use electrumsv_mc_lib::{
    db::repositories, security::totp::TotpInstance, services::wallet_service, state::AppState,
};
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn temp_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "electrumsv-agent-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn setup_secure_totp(dir: &std::path::Path, name: &str, password: &str) -> TotpInstance {
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard { fn drop(&mut self) { if self.0.try_wait().ok().flatten().is_none() { let _=self.0.kill(); let _=self.0.wait(); } } }
    let mut child=ChildGuard(Command::new(env!("CARGO_BIN_EXE_electrumsv-mc")).args(["--agent","--data-dir"]).arg(dir).arg("--enable-payments").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap());
    let mut input=child.0.stdin.take().unwrap();let stdout=child.0.stdout.take().unwrap();let (tx,rx)=std::sync::mpsc::channel();
    std::thread::spawn(move || { for line in BufReader::new(stdout).lines() { if tx.send(line).is_err() { break; } } });
    let mut request=|id:u32,method:&str,params:Value| -> Value {
        writeln!(input,"{}",json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).unwrap();input.flush().unwrap();
        let line=rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap_or_else(|_| panic!("agent timeout: {method}")).unwrap();
        let v:Value=serde_json::from_str(&line).unwrap();assert_eq!(v["id"],id);assert!(v.get("error").is_none(),"RPC failed: {method}");v["result"].clone()
    };
    request(1,"open_wallet",json!({"wallet_path":name}));
    request(2,"unlock_wallet",json!({"password":password}));
    let setup=request(3,"begin_totp_setup",json!({"password":password}));
    let secret=totp_rs::Secret::Encoded(setup["secret_base32"].as_str().unwrap().to_string()).to_bytes().unwrap();
    let totp=TotpInstance::from_secret_bytes(&secret,"ElectrumSV-Mc",name).unwrap();
    request(4,"confirm_totp_setup",json!({"password":password,"code":totp.generate_current().unwrap()}));
    drop(request);drop(input);assert!(child.0.wait().unwrap().success());totp
}

#[test]
fn stdio_lifecycle_and_directory_lock() {
    let dir = temp_dir();
    let bin = env!("CARGO_BIN_EXE_electrumsv-mc");
    let missing = Command::new(bin).arg("--agent").output().unwrap();
    assert!(!missing.status.success());
    let mut child = Command::new(bin)
        .args(["--agent", "--data-dir"])
        .arg(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    fn call(
        input: &mut impl Write,
        output: &mut impl BufRead,
        id: u32,
        method: &str,
        params: Value,
    ) -> Value {
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
        )
        .unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], id);
        response
    }
    let created = call(
        &mut input,
        &mut output,
        1,
        "create_wallet",
        json!({"name":"test", "password":"test-password"}),
    );
    assert_eq!(created["result"]["is_new_mnemonic"], true);
    assert_eq!(
        created["result"]["mnemonic"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .count(),
        12
    );
    let occupied = Command::new(bin)
        .args(["--agent", "--data-dir"])
        .arg(&dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!occupied.status.success());
    assert!(occupied.stdout.is_empty());
    assert_eq!(
        call(&mut input, &mut output, 2, "get_balance", json!({}))["result"]["total"],
        0
    );
    assert_eq!(
        call(&mut input, &mut output, 3, "get_receive_address", json!({}))["result"]
            ["derivation_index"],
        0
    );
    assert!(call(&mut input, &mut output, 4, "close_wallet", json!({}))["error"].is_null());
    assert_eq!(
        call(
            &mut input,
            &mut output,
            5,
            "open_wallet",
            json!({"wallet_path":"test"})
        )["result"]["is_unlocked"],
        false
    );
    assert_eq!(
        call(
            &mut input,
            &mut output,
            6,
            "unlock_wallet",
            json!({"password":"wrong"})
        )["error"]["code"],
        -32000
    );
    assert!(call(
        &mut input,
        &mut output,
        7,
        "unlock_wallet",
        json!({"password":"test-password"})
    )["error"]
        .is_null());
    assert_eq!(
        call(&mut input, &mut output, 8, "missing", json!({}))["error"]["code"],
        -32601
    );
    drop(input);
    assert!(child.wait().unwrap().success());
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn authorized_unlock_requires_valid_totp() {
    let dir = temp_dir();
    let mut state = AppState::new();
    state.data_dir = dir.to_str().unwrap().into();
    wallet_service::create_wallet(&state, "totp", "password", None, None)
        .await
        .unwrap();
    wallet_service::close_wallet(&state).await.unwrap();
    let totp=setup_secure_totp(&dir,"totp","password");
    wallet_service::open_wallet(&state, "totp").await.unwrap();
    let pool=state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
    repositories::store_totp_secret(&pool, &[1u8;20]).await.unwrap();
    drop(pool);
    assert!(
        wallet_service::unlock_wallet_authorized(&state, "wrong", None)
            .await
            .is_err()
    );
    assert!(
        wallet_service::unlock_wallet_authorized(&state, "password", None)
            .await
            .is_err()
    );
    assert!(
        wallet_service::unlock_wallet_authorized(&state, "password", Some("invalid"))
            .await
            .is_err()
    );
    assert!(!wallet_service::get_wallet_status(&state).is_unlocked);
    let code = totp.generate_current().unwrap();
    wallet_service::unlock_wallet_authorized(&state, "password", Some(&code))
        .await
        .unwrap();
    assert!(wallet_service::get_wallet_status(&state).is_unlocked);
    wallet_service::close_wallet(&state).await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn nested_data_roots_cannot_open_same_wallet() {
    let dir = temp_dir();
    let nested = dir.join("nested");
    std::fs::create_dir(&nested).unwrap();
    let mut inner = AppState::new();
    inner.data_dir = nested.to_str().unwrap().into();
    let mut outer = AppState::new();
    outer.data_dir = dir.to_str().unwrap().into();
    wallet_service::create_wallet(&inner, "shared", "password", None, None)
        .await
        .unwrap();
    let result =
        wallet_service::open_wallet(&outer, nested.join("shared.sqlite").to_str().unwrap()).await;
    assert!(result.is_err());
    wallet_service::close_wallet(&inner).await.unwrap();
    wallet_service::open_wallet(&outer, nested.join("shared.sqlite").to_str().unwrap())
        .await
        .unwrap();
    wallet_service::close_wallet(&outer).await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn directory_lock_symlink_alias_explicit_unlock() {
    let dir = temp_dir();
    let target = dir.join("target");
    let alias = dir.join("alias");
    std::fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let (guard, _) = electrumsv_mc_lib::agent::lock_data_dir(&target).unwrap();
    assert!(electrumsv_mc_lib::agent::lock_data_dir(&alias).is_err());
    guard.unlock().unwrap();
    drop(guard);
    assert!(electrumsv_mc_lib::agent::lock_data_dir(&alias).is_ok());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn protocol_rejects_invalid_requests_and_handles_notification() {
    let dir = temp_dir();
    let bin = env!("CARGO_BIN_EXE_electrumsv-mc");
    for flag in ["--help", "--invalid-option"] {
        let output = Command::new(bin)
            .arg(flag)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.success(), flag == "--help");
    }
    let mut child = Command::new(bin)
        .args(["--agent", "--data-dir"])
        .arg(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    fn exchange(input: &mut impl Write, output: &mut impl BufRead, request: &str) -> Value {
        writeln!(input, "{request}").unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
    assert_eq!(
        exchange(&mut input, &mut output, "{")["error"]["code"],
        -32700
    );
    assert_eq!(
        exchange(
            &mut input,
            &mut output,
            r#"{"jsonrpc":"1.0","method":"get_wallet_status","id":1}"#
        )["error"]["code"],
        -32600
    );
    assert_eq!(
        exchange(
            &mut input,
            &mut output,
            r#"{"jsonrpc":"2.0","method":"get_wallet_status","id":{}}"#
        )["error"]["code"],
        -32600
    );
    assert_eq!(
        exchange(
            &mut input,
            &mut output,
            r#"{"jsonrpc":"2.0","method":"get_wallet_status","params":{"unexpected":1},"id":2}"#
        )["error"]["code"],
        -32602
    );
    assert_eq!(
        exchange(
            &mut input,
            &mut output,
            r#"{"jsonrpc":"2.0","method":"open_wallet","params":{"wrong":"x"},"id":3}"#
        )["error"]["code"],
        -32602
    );
    assert_eq!(
        exchange(
            &mut input,
            &mut output,
            r#"{"jsonrpc":"2.0","method":"unknown","id":4}"#
        )["error"]["code"],
        -32601
    );
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0", "method":"get_wallet_status"})
    )
    .unwrap();
    let response = exchange(
        &mut input,
        &mut output,
        r#"{"jsonrpc":"2.0","method":"get_wallet_status","id":5}"#,
    );
    assert_eq!(response["id"], 5);
    drop(input);
    assert!(child.wait().unwrap().success());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn oversized_request_exits_without_unbounded_input() {
    let dir = temp_dir();
    let bin = env!("CARGO_BIN_EXE_electrumsv-mc");
    let mut child = Command::new(bin)
        .args(["--agent", "--data-dir"])
        .arg(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(&vec![b'x'; 65537]).unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exceeds maximum size"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn close_waits_for_checked_out_connection_then_reopens() {
    use std::{future::Future, task::Poll};
    let dir = temp_dir();
    let mut first = AppState::new();
    first.data_dir = dir.to_str().unwrap().into();
    let mut second = AppState::new();
    second.data_dir = first.data_dir.clone();
    wallet_service::create_wallet(&first, "shared", "password", None, None)
        .await
        .unwrap();
    let pool = first
        .active_wallet
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .db_pool
        .clone();
    let connection = pool.acquire().await.unwrap();
    let mut close = Box::pin(wallet_service::close_wallet(&first));
    std::future::poll_fn(|cx| match close.as_mut().poll(cx) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("close returned while a connection was checked out"),
    })
    .await;
    assert!(wallet_service::open_wallet(&second, "shared")
        .await
        .is_err());
    drop(connection);
    close.await.unwrap();
    assert!(pool.is_closed());
    assert!(pool.acquire().await.is_err());
    wallet_service::open_wallet(&second, "shared")
        .await
        .unwrap();
    wallet_service::close_wallet(&second).await.unwrap();
    drop(pool);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn lifecycle_and_receive_operations_serialize() {
    let dir = temp_dir();
    let mut app = AppState::new();
    app.data_dir = dir.to_str().unwrap().into();
    let state = std::sync::Arc::new(app);
    let (first, second) = tokio::join!(
        wallet_service::create_wallet(&state, "same", "password", None, None),
        wallet_service::create_wallet(&state, "same", "password", None, None),
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let (first, second) = tokio::join!(
        electrumsv_mc_lib::services::account_service::get_receive_address(&state, None),
        electrumsv_mc_lib::services::account_service::get_receive_address(&state, None),
    );
    let mut indices = [
        first.unwrap().derivation_index,
        second.unwrap().derivation_index,
    ];
    indices.sort();
    assert_eq!(indices, [0, 1]);
    {
        let _held = state.wallet_operation.lock().await;
        assert!(matches!(
            wallet_service::close_wallet(&state).await,
            Err(wallet_service::WalletError::Busy)
        ));
        assert!(wallet_service::get_wallet_status(&state).is_open);
    }
    wallet_service::close_wallet(&state).await.unwrap();
    let (first, second) = tokio::join!(
        wallet_service::open_wallet(&state, "same"),
        wallet_service::open_wallet(&state, "same"),
    );
    assert!(first.is_ok() && second.is_ok());
    wallet_service::close_wallet(&state).await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn mutating_notification_has_no_effect() {
    let dir = temp_dir();
    let bin = env!("CARGO_BIN_EXE_electrumsv-mc");
    let mut child = Command::new(bin)
        .args(["--agent", "--data-dir"])
        .arg(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    writeln!(input, "{}", json!({"jsonrpc":"2.0", "method":"create_wallet", "params":{"name":"unreturned", "password":"test"}})).unwrap();
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0", "id":7, "method":"list_wallets"})
    )
    .unwrap();
    input.flush().unwrap();
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["id"], 7);
    assert_eq!(response["result"], json!([]));
    assert!(!dir.join("unreturned.sqlite").exists());
    drop(input);
    assert!(child.wait().unwrap().success());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn optional_capabilities_require_explicit_flags_and_do_not_connect_on_start() {
    let bin = env!("CARGO_BIN_EXE_electrumsv-mc");
    let dir = temp_dir();
    for flags in [vec!["--allow-broadcast"], vec!["--allow-broadcast", "--enable-payments"], vec!["--allow-broadcast", "--allow-network"], vec!["--allow-network", "--allow-network"], vec!["--enable-wallet-maintenance", "--enable-wallet-maintenance"]] {
        let out = Command::new(bin).args(["--agent", "--data-dir"]).arg(&dir).args(flags).stdin(Stdio::null()).output().unwrap();
        assert!(!out.status.success());
    }
    for (flags, expected) in [
        (vec![], json!({"payments":false,"network":false,"broadcast":false,"wallet_maintenance":false})),
        (vec!["--enable-payments", "--allow-network", "--allow-broadcast"], json!({"payments":true,"network":true,"broadcast":true,"wallet_maintenance":false})),
    ] {
        let mut child = Command::new(bin).args(["--agent", "--data-dir"]).arg(&dir).args(flags.clone()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        fn request(input: &mut impl Write, output: &mut impl BufRead, id: i32, method: &str, params: Value) -> Value {
            writeln!(input, "{}", json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params})).unwrap();
            input.flush().unwrap();
            let mut line = String::new(); output.read_line(&mut line).unwrap();
            serde_json::from_str(&line).unwrap()
        }
        assert_eq!(request(&mut input, &mut output, 1, "get_capabilities", json!({}))["result"], expected);
        if flags.is_empty() {
            for (id, method) in [(2,"prepare_tx"), (3,"connect_server"), (4,"broadcast_plan"), (5,"get_spend_plan_status")] {
                assert_eq!(request(&mut input, &mut output, id, method, json!({}))["error"]["code"], -32000);
            }
        } else {
            assert_eq!(request(&mut input, &mut output, 2, "sync_wallet", json!({}))["error"]["code"], -32000);
            assert_eq!(request(&mut input, &mut output, 3, "connect_server", json!({}))["error"]["code"], -32602);
            assert_eq!(request(&mut input, &mut output, 4, "prepare_tx", json!({"outputs":[]}))["error"]["code"], -32602);
            assert!(request(&mut input, &mut output, 5, "create_wallet", json!({"name":"test", "password":"test-password"}))["result"].is_object());
            writeln!(input, "{}", json!({"jsonrpc":"2.0", "method":"begin_totp_setup", "params":{"password":"test-password"}})).unwrap();
            input.flush().unwrap();
            assert_eq!(request(&mut input, &mut output, 6, "is_totp_enabled", json!({}))["result"], false);
            assert_eq!(request(&mut input, &mut output, 7, "begin_totp_setup", json!({"password":"wrong"}))["error"]["code"], -32000);
            let setup = request(&mut input, &mut output, 8, "begin_totp_setup", json!({"password":"test-password"}));
            let secret = totp_rs::Secret::Encoded(setup["result"]["secret_base32"].as_str().unwrap().to_string()).to_bytes().unwrap();
            let code = TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "test").unwrap().generate_current().unwrap();
            assert_eq!(request(&mut input, &mut output, 9, "is_totp_enabled", json!({}))["result"], false);
            assert!(request(&mut input, &mut output, 91, "confirm_totp_setup", json!({"password":"test-password", "code":code}))["error"].is_null());
            assert_eq!(request(&mut input, &mut output, 10, "verify_totp", json!({"code":code}))["result"], true);
            assert_eq!(request(&mut input, &mut output, 11, "begin_totp_setup", json!({"password":"test-password"}))["error"]["code"], -32000);
        }
        drop(input); assert!(child.wait().unwrap().success());
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn signed_plan_and_reservation_survive_process_crash() {
    use bsv::compat::bip32::ExtendedKey;
    use bsv::script::templates::{p2pkh::P2PKH, ScriptTemplateLock};
    use bsv::transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput};
    let dir = temp_dir();
    let mut state = AppState::new();
    state.data_dir = dir.to_str().unwrap().into();
    wallet_service::create_wallet(&state, "synthetic", "test-password", Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), None).await.unwrap();
    let (pool, account, xprv) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        (active.db_pool.clone(), active.account_id, active.decrypted_xprv.clone().unwrap())
    };
    let account_key = ExtendedKey::from_string(&xprv).unwrap();
    let address = electrumsv_mc_lib::core::address::pubkey_to_p2pkh_address(&account_key.derive("0/0").unwrap().public_key().unwrap());
    let script = P2PKH::from_address(&address).unwrap().lock().unwrap();
    let master = repositories::get_first_master_key(&pool).await.unwrap().unwrap();
    let key = repositories::insert_keyinstance(&pool, account, Some(master.masterkey_id), repositories::derivation_type::BIP32, br#"{"subpath":[0,0]}"#, repositories::script_type::P2PKH, 0, None).await.unwrap();
    let mut funding = Transaction::new();
    funding.inputs.push(TransactionInput { source_txid: Some(hex::encode((0u8..32).collect::<Vec<_>>())), source_output_index: 1, ..Default::default() });
    funding.outputs.push(TransactionOutput { satoshis: Some(100_000), locking_script: script.clone(), change: false });
    let hash = electrumsv_mc_lib::core::address::hex_str_to_hash(&funding.id().unwrap()).unwrap();
    repositories::upsert_transaction(&pool, &hash, Some(10), Some(&hex::decode(funding.to_hex().unwrap()).unwrap())).await.unwrap();
    repositories::upsert_transaction_output(&pool, &hash, 0, 100_000, key, 0, Some(&hex::encode(script.to_binary()))).await.unwrap();
    pool.close().await;
    drop(pool);
    wallet_service::close_wallet(&state).await.unwrap();
    let totp=setup_secure_totp(&dir,"synthetic","test-password");
    fn spawn(dir: &std::path::Path) -> std::process::Child {
        Command::new(env!("CARGO_BIN_EXE_electrumsv-mc")).args(["--agent", "--data-dir"]).arg(dir).arg("--enable-payments").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap()
    }
    fn request(input: &mut impl Write, output: &mut impl BufRead, id: u32, method: &str, params: Value) -> Value {
        writeln!(input, "{}", json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).unwrap();
        input.flush().unwrap();
        let mut line = String::new(); output.read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], id);
        response
    }
    let mut child = spawn(&dir);
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    assert!(request(&mut input, &mut output, 1, "open_wallet", json!({"wallet_path":"synthetic"}))["result"].is_object());
    assert!(request(&mut input, &mut output, 2, "unlock_wallet", json!({"password":"test-password","totp_code":totp.generate_current().unwrap()}))["error"].is_null());
    let params = json!({"outputs":[{"address":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","satoshis":10000}],"fee_rate":1});
    let plan = request(&mut input, &mut output, 3, "prepare_tx", params.clone());
    let expired_id = plan["result"]["plan_id"].as_str().unwrap().to_string();
    let probe = sqlx::SqlitePool::connect(&format!("sqlite://{}", dir.join("synthetic.sqlite").display())).await.unwrap();
    sqlx::query("UPDATE SpendPlans SET expires_at=0 WHERE plan_id=?").bind(&expired_id).execute(&probe).await.unwrap();
    for (method, notification_params) in [("get_balance", json!({})), ("list_spend_plans", json!({})), ("get_spend_plan_status", json!({"plan_id":expired_id}))] {
        writeln!(input, "{}", json!({"jsonrpc":"2.0","method":method,"params":notification_params})).unwrap();
    }
    input.flush().unwrap();
    assert!(request(&mut input, &mut output, 30, "get_capabilities", json!({}))["result"].is_object());
    let state_before: (String,) = sqlx::query_as("SELECT state FROM SpendPlans WHERE plan_id=?").bind(&expired_id).fetch_one(&probe).await.unwrap();
    let reservations_before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM SpendReservations WHERE plan_id=?").bind(&expired_id).fetch_one(&probe).await.unwrap();
    assert_eq!((state_before.0.as_str(), reservations_before.0), ("PREPARED", 1));
    assert_eq!(request(&mut input, &mut output, 31, "get_spend_plan_status", json!({"plan_id":expired_id}))["result"]["state"], "EXPIRED");
    let reservations_after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM SpendReservations WHERE plan_id=?").bind(&expired_id).fetch_one(&probe).await.unwrap();
    assert_eq!(reservations_after.0, 0);
    probe.close().await;
    let plan = request(&mut input, &mut output, 32, "prepare_tx", params.clone());
    let plan_id = plan["result"]["plan_id"].as_str().unwrap().to_string();
    let signed = request(&mut input, &mut output, 4, "sign_tx", json!({"plan_id":plan_id,"totp_code":totp.generate_current().unwrap()}));
    let txid = signed["result"]["txid"].as_str().unwrap().to_string();
    child.kill().unwrap(); child.wait().unwrap(); drop(input); drop(output);
    let mut child = spawn(&dir);
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    assert!(request(&mut input, &mut output, 5, "open_wallet", json!({"wallet_path":"synthetic"}))["result"].is_object());
    let plans = request(&mut input, &mut output, 6, "list_spend_plans", json!({}));
    assert!(plans["result"].as_array().unwrap().iter().any(|p| p["plan_id"] == plan_id && p["state"] == "SIGNED" && p["txid"] == txid));
    let balance = request(&mut input, &mut output, 7, "get_balance", json!({}));
    assert_eq!(balance["result"]["reserved"], 100000);
    assert_eq!(balance["result"]["available"], 0);
    assert!(request(&mut input, &mut output, 8, "unlock_wallet", json!({"password":"test-password","totp_code":totp.generate_current().unwrap()}))["error"].is_null());
    assert!(request(&mut input, &mut output, 9, "prepare_tx", params)["error"].is_object());
    drop(input); assert!(child.wait().unwrap().success());
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn maintenance_capability_backup_password_restart_and_restore() {
    fn start(dir: &std::path::Path, enabled: bool) -> (std::process::Child, std::process::ChildStdin, BufReader<std::process::ChildStdout>) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_electrumsv-mc"));
        cmd.args(["--agent", "--data-dir"]).arg(dir);
        if enabled { cmd.arg("--enable-wallet-maintenance"); }
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        (child, input, output)
    }
    fn call(input: &mut impl Write, output: &mut impl BufRead, id: u32, method: &str, params: Value) -> Value {
        writeln!(input, "{}", json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["id"], id);
        value
    }
    let dir = temp_dir();
    let backup = dir.join("backup.sqlite");
    let backup_path = backup.to_str().unwrap();
    let (mut child, mut input, mut output) = start(&dir, false);
    assert_eq!(call(&mut input, &mut output, 1, "get_capabilities", json!({}))["result"]["wallet_maintenance"], false);
    assert!(call(&mut input, &mut output, 2, "create_wallet", json!({"name":"synthetic","password":"old-test-password","mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}))["result"].is_object());
    for (id, method, params) in [
        (3, "backup_wallet", json!({"backup_path":backup_path,"password":"old-test-password"})),
        (4, "change_password", json!({"old_password":"old-test-password","new_password":"new-test-password"})),
    ] { assert_eq!(call(&mut input, &mut output, id, method, params)["error"]["code"], -32000); }
    assert!(!backup.exists());
    drop(input); assert!(child.wait().unwrap().success());
    let (mut child, mut input, mut output) = start(&dir, true);
    assert_eq!(call(&mut input, &mut output, 5, "get_capabilities", json!({}))["result"]["wallet_maintenance"], true);
    assert!(call(&mut input, &mut output, 6, "open_wallet", json!({"wallet_path":"synthetic"}))["result"].is_object());
    for (method, params) in [("backup_wallet", json!({"backup_path":backup_path,"password":"old-test-password"})), ("change_password", json!({"old_password":"old-test-password","new_password":"new-test-password"}))] {
        writeln!(input, "{}", json!({"jsonrpc":"2.0","method":method,"params":params})).unwrap();
    }
    input.flush().unwrap();
    assert!(call(&mut input, &mut output, 7, "unlock_wallet", json!({"password":"old-test-password"}))["error"].is_null());
    assert!(!backup.exists());
    for (id, method, params) in [
        (8,"backup_wallet",json!({"backup_path":backup_path,"password":"wrong"})),
        (9,"backup_wallet",json!({"backup_path":backup_path,"password":""})),
        (10,"change_password",json!({"old_password":"wrong","new_password":"new-test-password"})),
        (11,"change_password",json!({"old_password":"old-test-password","new_password":""})),
    ] { assert_eq!(call(&mut input, &mut output, id, method, params)["error"]["code"], -32000); }
    assert!(!backup.exists());
    assert_eq!(call(&mut input, &mut output, 12, "backup_wallet", json!({"backup_path":backup_path,"password":"old-test-password","extra":true}))["error"]["code"], -32602);
    assert_eq!(call(&mut input, &mut output, 13, "change_password", json!({"old_password":"old-test-password","new_password":"new-test-password","extra":true}))["error"]["code"], -32602);
    assert!(call(&mut input, &mut output, 14, "backup_wallet", json!({"backup_path":backup_path,"password":"old-test-password"}))["error"].is_null());
    let original_backup = std::fs::read(&backup).unwrap();
    assert_eq!(call(&mut input, &mut output, 15, "backup_wallet", json!({"backup_path":backup_path,"password":"old-test-password"}))["error"]["code"], -32000);
    assert_eq!(std::fs::read(&backup).unwrap(), original_backup);
    assert!(call(&mut input, &mut output, 16, "change_password", json!({"old_password":"old-test-password","new_password":"new-test-password"}))["error"].is_null());
    drop(input); assert!(child.wait().unwrap().success());
    let (mut child, mut input, mut output) = start(&dir, false);
    assert!(call(&mut input, &mut output, 17, "open_wallet", json!({"wallet_path":"synthetic"}))["result"].is_object());
    assert_eq!(call(&mut input, &mut output, 18, "unlock_wallet", json!({"password":"old-test-password"}))["error"]["code"], -32000);
    assert!(call(&mut input, &mut output, 19, "unlock_wallet", json!({"password":"new-test-password"}))["error"].is_null());
    drop(input); assert!(child.wait().unwrap().success());
    let restore = temp_dir();
    std::fs::copy(&backup, restore.join("restored.sqlite")).unwrap();
    let (mut child, mut input, mut output) = start(&restore, false);
    assert!(call(&mut input, &mut output, 20, "open_wallet", json!({"wallet_path":"restored"}))["result"].is_object());
    assert!(call(&mut input, &mut output, 21, "unlock_wallet", json!({"password":"old-test-password"}))["error"].is_null());
    drop(input); assert!(child.wait().unwrap().success());
    std::fs::remove_dir_all(dir).unwrap();
    std::fs::remove_dir_all(restore).unwrap();
}

#[test]
fn secure_wallet_totp_setup_reauth_recovery_and_backup() {
    let dir = temp_dir();
    let backup = dir.join("backup.sqlite");
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard { fn drop(&mut self) { if self.0.try_wait().ok().flatten().is_none() { let _ = self.0.kill(); let _ = self.0.wait(); } } }
    let child = Command::new(env!("CARGO_BIN_EXE_electrumsv-mc"))
        .args(["--agent", "--data-dir"]).arg(&dir)
        .args(["--enable-payments", "--enable-wallet-maintenance"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut child = ChildGuard(child);
    let mut input = child.0.stdin.take().unwrap();
    let stdout = child.0.stdout.take().unwrap();
    let (sender, output) = std::sync::mpsc::channel();
    std::thread::spawn(move || { for line in BufReader::new(stdout).lines() { if sender.send(line).is_err() { break; } } });
    fn call(input: &mut impl Write, output: &std::sync::mpsc::Receiver<std::io::Result<String>>, id: u32, method: &str, params: Value) -> Value {
        writeln!(input, "{}", json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params})).unwrap();
        input.flush().unwrap();
        let line=output.recv_timeout(std::time::Duration::from_secs(30)).unwrap_or_else(|_| panic!("agent RPC timeout: {method}")).unwrap();
        let value:Value=serde_json::from_str(&line).unwrap(); assert_eq!(value["id"],id); value
    }
    assert!(call(&mut input,&output,1,"create_wallet",json!({"name":"secure","password":"old-password"}))["result"].is_object());
    assert!(call(&mut input,&output,2,"enable_totp",json!({"password":"old-password"}))["error"].is_object());
    let pending=call(&mut input,&output,3,"begin_totp_setup",json!({"password":"old-password"}));
    let secret=totp_rs::Secret::Encoded(pending["result"]["secret_base32"].as_str().unwrap().to_string()).to_bytes().unwrap();
    let totp=TotpInstance::from_secret_bytes(&secret,"ElectrumSV-Mc","secure").unwrap();
    assert!(call(&mut input,&output,4,"confirm_totp_setup",json!({"password":"old-password","code":"invalid"}))["error"].is_object());
    assert_eq!(call(&mut input,&output,5,"is_totp_enabled",json!({}))["result"],false);
    assert!(call(&mut input,&output,6,"confirm_totp_setup",json!({"password":"old-password","code":totp.generate_current().unwrap()}))["error"].is_null());
    assert_eq!(call(&mut input,&output,7,"is_totp_enabled",json!({}))["result"],true);
    let path=backup.to_str().unwrap();
    assert!(call(&mut input,&output,8,"backup_wallet",json!({"backup_path":path,"password":"old-password"}))["error"].is_object());
    assert!(!backup.exists());
    assert!(call(&mut input,&output,9,"backup_wallet",json!({"backup_path":path,"password":"old-password","totp_code":totp.generate_current().unwrap()}))["error"].is_null());
    assert!(call(&mut input,&output,10,"change_password",json!({"old_password":"old-password","new_password":"new-password","totp_code":"invalid"}))["error"].is_object());
    assert!(call(&mut input,&output,11,"change_password",json!({"old_password":"old-password","new_password":"new-password","totp_code":totp.generate_current().unwrap()}))["error"].is_null());
    let codes=call(&mut input,&output,12,"generate_totp_recovery_codes",json!({"password":"new-password","code":totp.generate_current().unwrap()}));
    let recovery=codes["result"][0].as_str().unwrap().to_string();
    assert!(call(&mut input,&output,13,"close_wallet",json!({}))["error"].is_null());
    assert!(call(&mut input,&output,14,"open_wallet",json!({"wallet_path":"secure"}))["result"].is_object());
    assert!(call(&mut input,&output,15,"is_totp_enabled",json!({}))["result"].is_null());
    assert!(call(&mut input,&output,16,"unlock_wallet",json!({"password":"new-password"}))["error"].is_object());
    assert!(call(&mut input,&output,17,"unlock_wallet",json!({"password":"new-password","totp_code":totp.generate_current().unwrap()}))["error"].is_null());
    assert!(call(&mut input,&output,18,"recover_totp",json!({"password":"wrong","recovery_code":recovery}))["error"].is_object());
    assert!(call(&mut input,&output,19,"recover_totp",json!({"password":"new-password","recovery_code":recovery}))["error"].is_null());
    assert!(call(&mut input,&output,20,"is_totp_enabled",json!({}))["result"].is_null());
    assert!(call(&mut input,&output,21,"unlock_wallet",json!({"password":"new-password"}))["error"].is_null());
    assert_eq!(call(&mut input,&output,22,"is_totp_enabled",json!({}))["result"],false);
    drop(input);assert!(child.0.wait().unwrap().success());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn migration_requires_maintenance_and_notifications_do_nothing() {
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard { fn drop(&mut self) { if self.0.try_wait().ok().flatten().is_none() { let _=self.0.kill(); let _=self.0.wait(); } } }
    let dir=temp_dir();let backup=dir.join("never.sqlite");
    for enabled in [false,true] {
        let mut cmd=Command::new(env!("CARGO_BIN_EXE_electrumsv-mc"));cmd.args(["--agent","--data-dir"]).arg(&dir);
        if enabled { cmd.arg("--enable-wallet-maintenance"); }
        let mut child=ChildGuard(cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap());
        let mut input=child.0.stdin.take().unwrap();let stdout=child.0.stdout.take().unwrap();let (tx,rx)=std::sync::mpsc::channel();
        std::thread::spawn(move || { for line in BufReader::new(stdout).lines() { if tx.send(line).is_err(){break;} } });
        for method in ["preview_migration","migrate_wallet"] {
            writeln!(input,"{}",json!({"jsonrpc":"2.0","method":method,"params":{"password":"synthetic","backup_path":backup,"confirmation_token":"invalid"}})).unwrap();
        }
        writeln!(input,"{}",json!({"jsonrpc":"2.0","id":1,"method":"get_wallet_status"})).unwrap();input.flush().unwrap();
        let line=rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();let response:Value=serde_json::from_str(&line.unwrap()).unwrap();assert_eq!(response["id"],1);assert_eq!(response["result"]["is_open"],false);assert!(!backup.exists());
        if !enabled {
            for (id,method) in [(2,"preview_migration"),(3,"migrate_wallet")] {
                writeln!(input,"{}",json!({"jsonrpc":"2.0","id":id,"method":method,"params":{}})).unwrap();input.flush().unwrap();
                let response:Value=serde_json::from_str(&rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap().unwrap()).unwrap();assert_eq!(response["error"]["code"],-32000);
            }
        }
        drop(input);assert!(child.0.wait().unwrap().success());
    }
    std::fs::remove_dir_all(dir).unwrap();
}
