use super::*;
use crate::{core::transaction::PaymentOutput, db::repositories, security::totp::TotpInstance, services::{account_service, wallet_service}};
use bsv::{compat::bip32::ExtendedKey, script::templates::{p2pkh::P2PKH, ScriptTemplateLock}, transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput}};
use sha2::{Digest, Sha256};
use std::{path::Path, process::{Command, Stdio}, time::{Duration, Instant}};

const SECRET: [u8; 20] = [37; 20];
const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn totp() -> String { TotpInstance::from_secret_bytes(&SECRET, "ElectrumSV-Mc", "wallet").unwrap().generate_current().unwrap() }
fn payment() -> Vec<PaymentOutput> { vec![PaymentOutput { address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into(), satoshis: 10_000 }] }
fn state(dir: &Path) -> AppState { let mut s = AppState::new(); s.data_dir = dir.to_str().unwrap().into(); s }
fn ready(dir: &Path, value: serde_json::Value) {
    let staging = dir.join("ready-staging");
    std::fs::write(&staging, value.to_string()).unwrap();
    std::fs::rename(staging, dir.join("ready")).unwrap();
}
struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
}

async fn fixture(dir: &Path) {
    let s = state(dir);
    wallet_service::create_legacy_fixture(&s, "synthetic", "pw", WORDS, None).await.unwrap();
    let (pool, account, _, xprv) = get_wallet_data(&s).unwrap();
    let key = ExtendedKey::from_string(&xprv.unwrap()).unwrap().derive("0/0").unwrap();
    let address = crate::core::address::pubkey_to_p2pkh_address(&key.public_key().unwrap());
    let script = P2PKH::from_address(&address).unwrap().lock().unwrap();
    let master = repositories::get_first_master_key(&pool).await.unwrap().unwrap();
    let key_id = repositories::insert_keyinstance(&pool, account, Some(master.masterkey_id), repositories::derivation_type::BIP32, br#"{"subpath":[0,0]}"#, repositories::script_type::P2PKH, 0, None).await.unwrap();
    let mut funding = Transaction::new();
    funding.inputs.push(TransactionInput { source_txid: Some(hex::encode((0u8..32).collect::<Vec<_>>())), source_output_index: 1, ..Default::default() });
    funding.outputs.push(TransactionOutput { satoshis: Some(100_000), locking_script: script.clone(), change: false });
    let hash = crate::core::address::hex_str_to_hash(&funding.id().unwrap()).unwrap();
    repositories::upsert_transaction(&pool, &hash, Some(10), Some(&hex::decode(funding.to_hex().unwrap()).unwrap())).await.unwrap();
    repositories::upsert_transaction_output(&pool, &hash, 0, 100_000, key_id, 0, Some(&hex::encode(script.to_binary()))).await.unwrap();
    repositories::store_totp_secret(&pool, &SECRET).await.unwrap();
    drop(pool); wallet_service::close_wallet(&s).await.unwrap();
}

#[tokio::test]
#[ignore = "child harness, invoked by payment_crash_boundaries"]
async fn payment_crash_child() {
    let dir = std::path::PathBuf::from(std::env::var("WALLET_PAYMENT_CRASH_DIR").unwrap());
    let phase = std::env::var("WALLET_PAYMENT_CRASH_PHASE").unwrap();
    let s = state(&dir);
    wallet_service::open_wallet(&s, "synthetic").await.unwrap();
    wallet_service::unlock_wallet_authorized(&s, "pw", Some(&totp())).await.unwrap();
    let plan = prepare_tx(&s, payment(), Some(1), None, None).await.unwrap();
    if phase.starts_with("prepared") {
        ready(&dir, serde_json::json!({"plan_id":plan.plan_id}));
        std::future::pending::<()>().await;
    }
    let signed = sign_tx(&s, plan.plan_id.clone(), totp()).await.unwrap();
    let expected = signed.txid.clone();
    let marker_id = plan.plan_id.clone();
    let marker_txid = expected.clone();
    let _ = broadcast_plan_with(&s, &plan.plan_id, &expected, false, |bytes| async move {
        let digest = hex::encode(Sha256::digest(&bytes));
        // The marker represents synthetic callback acceptance, not a server or chain confirmation.
        if phase == "accepted" { std::fs::write(dir.join("mock-accepted"), &digest).unwrap(); }
        ready(&dir, serde_json::json!({"plan_id":marker_id,"txid":marker_txid,"wire_sha256":digest}));
        std::future::pending::<Result<String,String>>().await
    }).await;
}

#[tokio::test]
async fn payment_crash_boundaries() {
    for phase in ["prepared_cancel", "prepared_expire", "before_send", "accepted"] {
        let dir = std::env::temp_dir().join(format!("wallet-payment-crash-{}-{}-{}",std::process::id(),phase,chrono::Utc::now().timestamp_nanos_opt().unwrap()));
        std::fs::create_dir_all(&dir).unwrap(); fixture(&dir).await;
        let mut child = ChildGuard(Command::new(std::env::current_exe().unwrap()).args(["--exact", "services::transaction_service::transaction_crash_tests::payment_crash_child", "--ignored"]).env("WALLET_PAYMENT_CRASH_DIR", &dir).env("WALLET_PAYMENT_CRASH_PHASE",phase).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(45);
        while !dir.join("ready").exists() {
            assert!(child.0.try_wait().unwrap().is_none(), "child exited before {phase} barrier");
            assert!(Instant::now() < deadline, "child timed out before {phase} barrier");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        child.0.kill().unwrap();child.0.wait().unwrap();
        let marker: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("ready")).unwrap()).unwrap();
        let plan = marker["plan_id"].as_str().unwrap();
        let s = state(&dir);wallet_service::open_wallet(&s,"synthetic").await.unwrap();
        let (pool, _, _, _) = get_wallet_data(&s).unwrap();
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM SpendReservations WHERE plan_id=?").bind(plan).fetch_one(&pool).await.unwrap();assert_eq!(count.0,1);
        let balance = account_service::get_balance(&s, None).await.unwrap();assert_eq!((balance.reserved,balance.available),(100_000,0));
        if phase.starts_with("prepared") {
            assert_eq!(get_spend_plan_status(&s,plan).await.unwrap().state,"PREPARED");
            wallet_service::unlock_wallet_authorized(&s,"pw",Some(&totp())).await.unwrap();
            assert!(sign_tx(&s,plan.into(),totp()).await.is_err());
            if phase == "prepared_cancel" { cancel_spend_plan(&s,plan).await.unwrap();assert_eq!(get_spend_plan_status(&s,plan).await.unwrap().state,"CANCELLED"); }
            else { sqlx::query("UPDATE SpendPlans SET expires_at=0 WHERE plan_id=?").bind(plan).execute(&pool).await.unwrap();assert_eq!(get_spend_plan_status(&s,plan).await.unwrap().state,"EXPIRED"); }
            let count: (i64,) = sqlx::query_as("SELECT count(*) FROM SpendReservations WHERE plan_id=?").bind(plan).fetch_one(&pool).await.unwrap();assert_eq!(count.0,0);
        } else {
            let id = marker["txid"].as_str().unwrap();let digest = marker["wire_sha256"].as_str().unwrap();
            assert_eq!(get_spend_plan_status(&s,plan).await.unwrap().state,"BROADCAST_UNKNOWN");
            let stored: (String,String) = sqlx::query_as("SELECT signed_raw,txid FROM SpendPlans WHERE plan_id=?").bind(plan).fetch_one(&pool).await.unwrap();
            assert_eq!(stored.1,id);assert_eq!(hex::encode(Sha256::digest(hex::decode(&stored.0).unwrap())),digest);
            assert_eq!(dir.join("mock-accepted").exists(),phase=="accepted");
            assert!(broadcast_plan_with(&s,plan,id,false, |_| async { panic!("implicit retry") }).await.is_err());
            let result = broadcast_plan_with(&s,plan,id,true, |wire| async { assert_eq!(hex::encode(Sha256::digest(wire)),digest);Ok(id.to_string()) }).await.unwrap();assert_eq!(result,id);
            assert_eq!(get_spend_plan_status(&s,plan).await.unwrap().state,"BROADCASTED");
        }
        drop(pool);wallet_service::close_wallet(&s).await.unwrap();std::fs::remove_dir_all(dir).unwrap();
    }
}
