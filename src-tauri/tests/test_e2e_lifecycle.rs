// tests/test_e2e_lifecycle.rs — End-to-end wallet lifecycle integration test
//
// Exercises the full wallet flow as far as possible without a live ElectrumX
// network connection:
//
//   create wallet -> open -> unlock -> get receive address -> check balance
//   -> get UTXOs -> prepare_tx (empty UTXOs -> NoUtxos error)
//   -> change password -> export seed -> close -> reopen (locked)
//   -> unlock with new password -> cleanup
//
// All assertions exercise real wallet_service + repositories + keystore logic.
// No mocks, no #[ignore] — the test runs and passes on every `cargo test`.

use electrumsv_mc_lib::core::keystore;
use electrumsv_mc_lib::core::transaction::{PaymentOutput, SelectedUtxo, TxBuilder, TransactionError};
use electrumsv_mc_lib::db::repositories;
use electrumsv_mc_lib::security::envelope::{self, WalletContext};
use std::io::{BufRead, BufReader, Write};
use serde_json::{json, Value};
use electrumsv_mc_lib::services::wallet_service;
use electrumsv_mc_lib::state::AppState;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Known BIP39 test vector (all "abandon" + "about").
const KNOWN_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Build a fresh AppState backed by a unique temp data_dir.
fn make_test_state(test_name: &str) -> AppState {
    let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let temp_dir = std::env::temp_dir().join(format!("electrumsv_mc_e2e_{}_{}", test_name, id));
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir).ok();
    }
    std::fs::create_dir_all(&temp_dir).unwrap();
    AppState {
        data_dir: temp_dir.to_string_lossy().to_string(),
        active_wallet: std::sync::Mutex::new(None),
        network: std::sync::Mutex::new(electrumsv_mc_lib::state::NetworkState::new()),
        pending_plans: std::sync::Mutex::new(std::collections::HashMap::new()),
        wallet_operation: tokio::sync::Mutex::new(()),
    }
}

/// Extract (db_pool, account_id, keystore_data, decrypted_xprv) from the active wallet.
fn grab_active_wallet(state: &AppState) -> (sqlx::SqlitePool, i64, keystore::KeyStoreData, Option<String>) {
    let guard = state.active_wallet.lock().unwrap();
    let active = guard.as_ref().expect("wallet should be open");
    (
        active.db_pool.clone(),
        active.account_id,
        active.keystore_data.clone(),
        active.decrypted_xprv.clone(),
    )
}

// ---------------------------------------------------------------------------
// The single E2E test — everything in one #[tokio::test] so the steps run
// sequentially against the same wallet/state, exactly like a real user session.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_e2e_wallet_lifecycle() {
    let state = make_test_state("lifecycle");
    let password = "testpw123";
    let new_password = "new_password_456";

    // -----------------------------------------------------------------
    // Step 1: Create wallet with a known mnemonic
    // -----------------------------------------------------------------
    let result = wallet_service::create_wallet(&state, "e2e_test", password, Some(KNOWN_MNEMONIC), None)
        .await
        .expect("create_wallet should succeed");

    assert!(!result.is_new_mnemonic, "using a known mnemonic -> is_new_mnemonic=false");
    assert_eq!(result.mnemonic, KNOWN_MNEMONIC, "mnemonic should match the input");
    assert_eq!(result.account_id, 1, "first account should have id=1");

    let wallet_path = result.wallet_path.clone();
    let account_id = result.account_id;

    // Verify the wallet file exists on disk
    assert!(std::path::Path::new(&wallet_path).exists(), "wallet file must exist after create");

    // Verify active_wallet is set and unlocked (decrypted_xprv present)
    {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().expect("active_wallet should be set after create");
        assert_eq!(active.wallet_path, wallet_path);
        assert!(active.is_unlocked(), "freshly created wallet should be unlocked");
        assert!(active.decrypted_xprv.is_some(), "decrypted_xprv must be Some after create");
    }

    // -----------------------------------------------------------------
    // Step 2: Get accounts — at least one must exist
    // -----------------------------------------------------------------
    let (pool, _, _, _) = grab_active_wallet(&state);
    let accounts = repositories::get_all_accounts(&pool)
        .await
        .expect("get_all_accounts should succeed");
    assert!(!accounts.is_empty(), "fresh wallet should have at least one account");
    assert_eq!(accounts[0].account_id, account_id, "account_id should match create result");

    // -----------------------------------------------------------------
    // Step 3: Get a receive address — must be a mainnet P2PKH address ("1...")
    // -----------------------------------------------------------------
    let (pool, default_acct_id, _, xprv_opt) = grab_active_wallet(&state);
    let xprv = xprv_opt.expect("wallet should be unlocked for address derivation");

    // Derive the next receive address (0/N) — mirrors get_receive_address logic
    let (receiving_count, _) = repositories::get_keyinstance_counts(&pool, default_acct_id)
        .await
        .expect("get_keyinstance_counts should succeed");
    let next_index = receiving_count;

    let account_key = bsv::compat::bip32::ExtendedKey::from_string(&xprv)
        .expect("xprv should parse");
    let child_key = account_key
        .derive(&format!("0/{}", next_index))
        .expect("derivation should succeed");
    let pubkey = child_key
        .public_key()
        .expect("public_key derivation should succeed");
    let address = electrumsv_mc_lib::core::address::pubkey_to_p2pkh_address(&pubkey);

    assert!(
        address.starts_with('1'),
        "mainnet P2PKH address must start with '1', got: {}",
        address
    );
    assert!(address.len() >= 26 && address.len() <= 35, "address length in valid range");

    // -----------------------------------------------------------------
    // Step 4: Check balance — fresh wallet must have zero balance
    // -----------------------------------------------------------------
    let (pool, default_acct_id, _, _) = grab_active_wallet(&state);
    let (confirmed, unconfirmed, total) = repositories::get_balance_for_account(&pool, default_acct_id)
        .await
        .expect("get_balance_for_account should succeed");
    assert_eq!(confirmed, 0, "fresh wallet confirmed balance must be 0");
    assert_eq!(unconfirmed, 0, "fresh wallet unconfirmed balance must be 0");
    assert_eq!(total, 0, "fresh wallet total balance must be 0");

    // -----------------------------------------------------------------
    // Step 5: Get UTXOs — fresh wallet must have no UTXOs
    // -----------------------------------------------------------------
    let (pool, default_acct_id, _, _) = grab_active_wallet(&state);
    let utxos = repositories::get_utxo_infos_for_account(&pool, default_acct_id)
        .await
        .expect("get_utxo_infos_for_account should succeed");
    assert!(utxos.is_empty(), "fresh wallet must have zero UTXOs");

    // -----------------------------------------------------------------
    // Step 6: Prepare TX with empty UTXOs — should return NoUtxos error
    // -----------------------------------------------------------------
    let empty_utxos: Vec<SelectedUtxo> = vec![];
    let outputs = vec![PaymentOutput {
        address: address.clone(),
        satoshis: 1000,
    }];
    let result = TxBuilder::build_unsigned(
        &empty_utxos,
        &outputs,
        Some(&address), // change address
        1,              // fee_rate: 1 sat/byte
        None,           // no OP_RETURN
        None,           // default largest-first strategy
    );
    assert!(
        matches!(result, Err(TransactionError::NoUtxos)),
        "build_unsigned with empty UTXOs must return NoUtxos error, got: {:?}",
        result
    );

    // Change the password through the actual maintenance RPC, not a replicated CBC path.
    wallet_service::close_wallet(&state).await.unwrap();
    {
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard { fn drop(&mut self) { if self.0.try_wait().ok().flatten().is_none() { let _=self.0.kill(); let _=self.0.wait(); } } }
        let mut child=ChildGuard(std::process::Command::new(env!("CARGO_BIN_EXE_electrumsv-mc"))
            .args(["--agent","--data-dir"]).arg(&state.data_dir).arg("--enable-wallet-maintenance")
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().unwrap());
        let mut input=child.0.stdin.take().unwrap(); let stdout=child.0.stdout.take().unwrap();
        let (tx,rx)=std::sync::mpsc::channel();
        std::thread::spawn(move || { for line in BufReader::new(stdout).lines() { if tx.send(line).is_err() { break; } } });
        for (id,method,params) in [(1,"open_wallet",json!({"wallet_path":"e2e_test"})),(2,"change_password",json!({"old_password":password,"new_password":new_password})),(3,"close_wallet",json!({}))] {
            writeln!(input,"{}",json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).unwrap();input.flush().unwrap();
            let line=rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap_or_else(|_| panic!("agent timeout: {method}")).unwrap();
            let response:Value=serde_json::from_str(&line).unwrap();assert_eq!(response["id"],id);assert!(response.get("error").is_none(),"RPC failed: {method}");
        }
        drop(input);assert!(child.0.wait().unwrap().success());
    }
    wallet_service::open_wallet(&state, &wallet_path).await.unwrap();
    let (pool, _, _, _) = grab_active_wallet(&state);
    let row=repositories::get_first_master_key(&pool).await.unwrap().unwrap();
    let record:Value=serde_json::from_slice(&row.derivation_data).unwrap();
    assert_eq!(record["format"],"wallet-envelope-v1");
    let context=WalletContext { wallet_id:serde_json::from_value(record["wallet_id"].clone()).unwrap(), xpub:record["xpub"].as_str().unwrap().into(), derivation:record["derivation"].as_str().unwrap().into() };
    let serialized=record["envelope"].as_str().unwrap().as_bytes();
    assert!(envelope::open(password,&context,serialized).await.is_err());
    let decrypted=envelope::open(new_password,&context,serialized).await.unwrap();
    let payload:Value=serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(payload["mnemonic"],KNOWN_MNEMONIC);
    let seed=electrumsv_mc_lib::core::mnemonic::mnemonic_to_seed(KNOWN_MNEMONIC, "").unwrap();
    let expected=keystore::derive_keys_from_seed(&seed).unwrap();
    assert_eq!(context.xpub,expected.xpub);
    assert_eq!(payload["xprv"],expected.xprv);
    drop(pool);

    // -----------------------------------------------------------------
    // Step 9: Close wallet — active_wallet must become None
    // -----------------------------------------------------------------
    wallet_service::close_wallet(&state).await.expect("close_wallet should succeed");
    {
        let guard = state.active_wallet.lock().unwrap();
        assert!(guard.is_none(), "active_wallet must be None after close");
    }

    // -----------------------------------------------------------------
    // Step 10: Reopen wallet — must be open but LOCKED (no decrypted_xprv)
    // -----------------------------------------------------------------
    let open_result = wallet_service::open_wallet(&state, &wallet_path)
        .await
        .expect("open_wallet should succeed");
    assert!(!open_result.is_unlocked, "reopened wallet must be locked");

    {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().expect("active_wallet should be set after open");
        assert!(!active.is_unlocked(), "wallet must be locked after reopen");
        assert!(active.decrypted_xprv.is_none(), "decrypted_xprv must be None after reopen");
    }

    // -----------------------------------------------------------------
    // Step 11: Unlock wallet with the NEW password — must succeed
    // -----------------------------------------------------------------
    // First verify old password fails on the reopened wallet
    let old_pw_unlock = wallet_service::unlock_wallet_authorized(&state, password, None).await;
    assert!(old_pw_unlock.is_err(), "old password must fail to unlock the reopened wallet");

    // Still locked after a failed unlock attempt
    {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().expect("wallet still open");
        assert!(!active.is_unlocked(), "wallet must remain locked after wrong password");
    }

    // Now unlock with the new password
    wallet_service::unlock_wallet_authorized(&state, new_password, None).await
        .expect("unlock_wallet with new password should succeed");
    {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().expect("wallet still open after unlock");
        assert!(active.is_unlocked(), "wallet must be unlocked after correct password");
        assert!(active.decrypted_xprv.is_some(), "decrypted_xprv must be Some after unlock");
    }

    // -----------------------------------------------------------------
    // Step 12: Cleanup — close wallet, remove temp dir
    // -----------------------------------------------------------------
    wallet_service::close_wallet(&state).await.expect("final close_wallet should succeed");

    // Extract data_dir before dropping state
    let data_dir = state.data_dir.clone();
    std::fs::remove_dir_all(&data_dir).ok();
}