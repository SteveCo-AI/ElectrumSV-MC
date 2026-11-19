//! Explicit cross-version test; requires the separately supplied S1 executable.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{io::{BufRead, BufReader, Write}, path::{Path, PathBuf}, process::{Child, ChildStdin, Command, Stdio}, sync::mpsc::{self, Receiver}, time::Duration};

const OLD_SHA: &str = "45659e194a4b6836981f48ac7d47c99bc3304d054e6c156f722dd64a8d3ed121";
const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
struct Agent { child: Child, input: ChildStdin, output: Receiver<std::io::Result<String>> }
impl Agent {
    fn start(binary: &Path, dir: &Path) -> Self {
        Self::start_with_payments(binary, dir, false)
    }
    fn start_with_payments(binary: &Path, dir: &Path, payments: bool) -> Self {
        let mut command=Command::new(binary);
        command.args(["--agent","--data-dir"]).arg(dir).arg("--enable-wallet-maintenance");
        if payments { command.arg("--enable-payments"); }
        let mut child=command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let input=child.stdin.take().unwrap(); let stdout=child.stdout.take().unwrap(); let (tx,output)=mpsc::channel();
        std::thread::spawn(move || { for line in BufReader::new(stdout).lines() { if tx.send(line).is_err() { break; } } });
        Self { child,input,output }
    }
    fn call(&mut self, id:u32, method:&str, params:Value)->Value {
        writeln!(self.input,"{}",json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).unwrap(); self.input.flush().unwrap();
        let line=self.output.recv_timeout(Duration::from_secs(40)).unwrap_or_else(|_| panic!("agent timeout: {method}")).unwrap();
        let value:Value=serde_json::from_str(&line).unwrap(); assert_eq!(value["id"],id); value
    }
}
impl Drop for Agent { fn drop(&mut self) { let _=self.child.kill(); let _=self.child.wait(); } }
fn digest_path(p:&Path)->String { hex::encode(Sha256::digest(std::fs::read(p).unwrap())) }
async fn fingerprint(path:&Path)->([u8;32],i64) {
    let opts=sqlx::sqlite::SqliteConnectOptions::new().filename(path).read_only(true).immutable(true);
    let pool=sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect_with(opts).await.unwrap();
    let version:(String,)=sqlx::query_as("SELECT value FROM WalletData WHERE key='migration'").fetch_one(&pool).await.unwrap();
    let tables:Vec<(String,String)>=sqlx::query_as("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetch_all(&pool).await.unwrap();
    let mut hash=Sha256::new();
    for (table,schema) in tables {
        let quoted=table.replace('"',"\"\"");
        let cols=sqlx::query(&format!("PRAGMA table_info(\"{quoted}\")")).fetch_all(&pool).await.unwrap();
        let expressions:Vec<String>=cols.iter().map(|r| format!("quote(\"{}\")",r.get::<String,_>("name").replace('"',"\"\""))).collect();
        let rows=sqlx::query(&format!("SELECT {} FROM \"{quoted}\"",expressions.join(","))).fetch_all(&pool).await.unwrap();
        hash.update((table.len() as u64).to_le_bytes());hash.update(table.as_bytes());hash.update((schema.len() as u64).to_le_bytes());hash.update(schema.as_bytes());
        let mut encoded=Vec::new();
        for row in rows { let mut bytes=Vec::new(); for index in 0..expressions.len() { let v:String=row.get(index); bytes.extend_from_slice(&(v.len() as u64).to_le_bytes()); bytes.extend_from_slice(v.as_bytes()); } encoded.push(bytes); }
        encoded.sort(); for row in encoded { hash.update((row.len() as u64).to_le_bytes());hash.update(row); }
    }
    pool.close().await; (hash.finalize().into(),version.0.parse().unwrap())
}
#[tokio::test]
#[ignore = "requires explicit WALLET_COMPAT_OLD_BINARY artifact; not a default-suite pass"]
async fn old_reader_rejects_34_and_new_reader_preserves_33() {
    let old=PathBuf::from(std::env::var_os("WALLET_COMPAT_OLD_BINARY").expect("set WALLET_COMPAT_OLD_BINARY to the preserved S1 binary"));
    assert_eq!(digest_path(&old),OLD_SHA,"old binary hash mismatch");
    let new=Path::new(env!("CARGO_BIN_EXE_electrumsv-mc"));
    let root=std::env::temp_dir().join(format!("wallet-compat-{}-{}",std::process::id(),chrono::Utc::now().timestamp_nanos_opt().unwrap()));
    let old_dir=root.join("legacy");let new_dir=root.join("secure");std::fs::create_dir_all(&old_dir).unwrap();std::fs::create_dir_all(&new_dir).unwrap();
    { let mut a=Agent::start(new,&new_dir);assert!(a.call(1,"create_wallet",json!({"name":"modern","password":"test-password","mnemonic":WORDS}))["result"].is_object());assert!(a.call(2,"close_wallet",json!({}))["error"].is_null()); }
    let modern=new_dir.join("modern.sqlite"); let (modern_before,v)=fingerprint(&modern).await;assert_eq!(v,34);
    { let mut a=Agent::start(&old,&new_dir); assert!(a.call(3,"open_wallet",json!({"wallet_path":"modern"}))["error"].is_object());assert_eq!(a.call(4,"get_wallet_status",json!({}))["result"]["is_open"],false);assert!(a.call(5,"unlock_wallet",json!({"password":"test-password"}))["error"].is_object()); }
    assert_eq!(fingerprint(&modern).await,(modern_before,34));
    { let mut a=Agent::start(&old,&old_dir);assert!(a.call(6,"create_wallet",json!({"name":"legacy","password":"old-password","mnemonic":WORDS}))["result"].is_object());assert!(a.call(7,"close_wallet",json!({}))["error"].is_null()); }
    let legacy=old_dir.join("legacy.sqlite");let (legacy_before,v)=fingerprint(&legacy).await;assert_eq!(v,33);
    { let mut a=Agent::start(new,&old_dir);assert!(a.call(8,"open_wallet",json!({"wallet_path":"legacy"}))["result"].is_object());assert!(a.call(9,"unlock_wallet",json!({"password":"old-password"}))["error"].is_null());assert!(a.call(10,"close_wallet",json!({}))["error"].is_null()); }
    assert_eq!(fingerprint(&legacy).await,(legacy_before,33));
    { let mut a=Agent::start(new,&old_dir);assert!(a.call(11,"open_wallet",json!({"wallet_path":"legacy"}))["result"].is_object());assert!(a.call(12,"unlock_wallet",json!({"password":"old-password"}))["error"].is_null());let backup=old_dir.join("backup.sqlite");assert!(a.call(13,"backup_wallet",json!({"backup_path":backup.to_str().unwrap(),"password":"old-password"}))["error"].is_null());assert!(a.call(14,"change_password",json!({"old_password":"old-password","new_password":"new-password"}))["error"].is_null());assert!(a.call(15,"close_wallet",json!({}))["error"].is_null());assert!(a.call(16,"open_wallet",json!({"wallet_path":"backup"}))["result"].is_object());assert!(a.call(17,"unlock_wallet",json!({"password":"old-password"}))["error"].is_null());assert!(a.call(18,"close_wallet",json!({}))["error"].is_null()); }
    assert_eq!(fingerprint(&legacy).await.1,33);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[ignore = "requires WALLET_COMPAT_OLD_BINARY and WALLET_COMPAT_S2_BINARY release artifacts"]
async fn recovery_codes_are_cross_version_compatible_for_33_and_34() {
    let old=PathBuf::from(std::env::var_os("WALLET_COMPAT_OLD_BINARY").expect("set WALLET_COMPAT_OLD_BINARY"));
    let s2=PathBuf::from(std::env::var_os("WALLET_COMPAT_S2_BINARY").expect("set WALLET_COMPAT_S2_BINARY"));
    assert_eq!(digest_path(&old),OLD_SHA,"S1 binary hash mismatch");
    assert_eq!(digest_path(&s2),"23d1d4b4ba257ee5ef69b542a5dd37407227ca26f70d2f5f8aa92a3d9e0c8f0e","S2 binary hash mismatch");
    let current=Path::new(env!("CARGO_BIN_EXE_electrumsv-mc"));
    let root=std::env::temp_dir().join(format!("wallet-recovery-compat-{}-{}",std::process::id(),chrono::Utc::now().timestamp_nanos_opt().unwrap()));
    std::fs::create_dir_all(&root).unwrap();
    for version in [33,34] {
        let dir=root.join(format!("v{version}"));std::fs::create_dir(&dir).unwrap();
        { let binary=if version==33 { &old } else { &s2 }; let mut a=Agent::start_with_payments(binary,&dir,true);
          assert!(a.call(1,"create_wallet",json!({"name":"wallet","password":"test-password","mnemonic":WORDS}))["result"].is_object());
          assert!(a.call(2,"close_wallet",json!({}))["error"].is_null()); }
        let wallet=dir.join("wallet.sqlite");assert_eq!(fingerprint(&wallet).await.1,version);
        let old_code;
        let secret;
        { let mut a=Agent::start_with_payments(&s2,&dir,true);
          assert!(a.call(3,"open_wallet",json!({"wallet_path":"wallet"}))["result"].is_object());
          assert!(a.call(4,"unlock_wallet",json!({"password":"test-password"}))["error"].is_null());
          let setup=a.call(5,"begin_totp_setup",json!({"password":"test-password"}));
          secret=totp_rs::Secret::Encoded(setup["result"]["secret_base32"].as_str().unwrap().to_string()).to_bytes().unwrap();
          let totp=electrumsv_mc_lib::security::totp::TotpInstance::from_secret_bytes(&secret,"ElectrumSV-Mc","wallet").unwrap();
          assert!(a.call(6,"confirm_totp_setup",json!({"password":"test-password","code":totp.generate_current().unwrap()}))["error"].is_null());
          let generated=a.call(7,"generate_totp_recovery_codes",json!({"password":"test-password","code":totp.generate_current().unwrap()}));
          old_code=generated["result"][0].as_str().unwrap().to_string();
          assert!(a.call(8,"close_wallet",json!({}))["error"].is_null()); }
        let before=fingerprint(&wallet).await;
        { let mut a=Agent::start_with_payments(current,&dir,true);
          assert!(a.call(9,"open_wallet",json!({"wallet_path":"wallet"}))["result"].is_object());
          assert!(a.call(10,"close_wallet",json!({}))["error"].is_null()); }
        assert_eq!(fingerprint(&wallet).await,before,"read must not change wallet data or recovery hashes");
        let prior=root.join(format!("prior{version}"));std::fs::create_dir(&prior).unwrap();std::fs::copy(&wallet,prior.join("wallet.sqlite")).unwrap();
        { let mut a=Agent::start_with_payments(&s2,&prior,true);
          assert!(a.call(11,"open_wallet",json!({"wallet_path":"wallet"}))["result"].is_object());
          assert!(a.call(12,"recover_totp",json!({"password":"test-password","recovery_code":old_code}))["error"].is_null());
          assert!(a.call(13,"recover_totp",json!({"password":"test-password","recovery_code":old_code}))["error"].is_object());
          assert!(a.call(14,"close_wallet",json!({}))["error"].is_null()); }
        let new_code;
        { let mut a=Agent::start_with_payments(current,&dir,true);
          assert!(a.call(15,"open_wallet",json!({"wallet_path":"wallet"}))["result"].is_object());
          let totp=electrumsv_mc_lib::security::totp::TotpInstance::from_secret_bytes(&secret,"ElectrumSV-Mc","wallet").unwrap();
          assert!(a.call(16,"unlock_wallet",json!({"password":"test-password","totp_code":totp.generate_current().unwrap()}))["error"].is_null());
          let generated=a.call(17,"generate_totp_recovery_codes",json!({"password":"test-password","code":totp.generate_current().unwrap()}));
          let codes=generated["result"].as_array().unwrap();assert_eq!(codes.len(),10);
          for code in codes { let value=code.as_str().unwrap();let pieces:Vec<&str>=value.split('-').collect();assert_eq!(pieces.len(),8);assert!(pieces.iter().all(|p|p.len()==4 && p.bytes().all(|c|b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(&c)))); }
          new_code=codes[0].as_str().unwrap().to_string();
          assert!(a.call(18,"close_wallet",json!({}))["error"].is_null()); }
        let newer=root.join(format!("new{version}"));std::fs::create_dir(&newer).unwrap();std::fs::copy(&wallet,newer.join("wallet.sqlite")).unwrap();
        { let mut a=Agent::start_with_payments(&s2,&newer,true);
          assert!(a.call(19,"open_wallet",json!({"wallet_path":"wallet"}))["result"].is_object());
          assert!(a.call(190,"recover_totp",json!({"password":"test-password","recovery_code":old_code}))["error"].is_object());
          assert!(a.call(20,"recover_totp",json!({"password":"test-password","recovery_code":new_code}))["error"].is_null());
          assert!(a.call(21,"recover_totp",json!({"password":"test-password","recovery_code":new_code}))["error"].is_object());
          assert!(a.call(22,"close_wallet",json!({}))["error"].is_null()); }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[ignore = "requires explicit S1 and S2 preserved binaries"]
async fn explicit_migration_preserves_legacy_recovery_and_signed_reservation() {
    use bsv::script::templates::{p2pkh::P2PKH, ScriptTemplateLock};
    use bsv::transaction::{transaction::Transaction, transaction_input::TransactionInput, transaction_output::TransactionOutput};
    use electrumsv_mc_lib::{core::address, db::{connection, repositories}, security::totp::TotpInstance};
    let old=PathBuf::from(std::env::var_os("WALLET_COMPAT_OLD_BINARY").expect("set WALLET_COMPAT_OLD_BINARY"));
    let s2=PathBuf::from(std::env::var_os("WALLET_COMPAT_S2_BINARY").expect("set WALLET_COMPAT_S2_BINARY"));
    assert_eq!(digest_path(&old),OLD_SHA);
    assert_eq!(digest_path(&s2),"23d1d4b4ba257ee5ef69b542a5dd37407227ca26f70d2f5f8aa92a3d9e0c8f0e");
    let current=Path::new(env!("CARGO_BIN_EXE_electrumsv-mc"));
    let root=std::env::temp_dir().join(format!("wallet-migration-e2e-{}-{}",std::process::id(),chrono::Utc::now().timestamp_nanos_opt().unwrap()));
    let dir=root.join("wallet");std::fs::create_dir_all(&dir).unwrap();
    let receive;
    { let mut a=Agent::start_with_payments(&old,&dir,true);
      assert!(a.call(1,"create_wallet",json!({"name":"legacy","password":"test-password","mnemonic":WORDS,"passphrase":"synthetic-passphrase"}))["result"].is_object());
      receive=a.call(2,"get_receive_address",json!({}))["result"].clone();
      assert!(a.call(3,"close_wallet",json!({}))["error"].is_null()); }
    let wallet=dir.join("legacy.sqlite");
    {
        let pool=connection::open_wallet_db(wallet.to_str().unwrap()).await.unwrap();
        let script=P2PKH::from_address(receive["address"].as_str().unwrap()).unwrap().lock().unwrap();
        let mut funding=Transaction::new();
        funding.inputs.push(TransactionInput { source_txid:Some(hex::encode((0u8..32).collect::<Vec<_>>())),source_output_index:1,..Default::default() });
        funding.outputs.push(TransactionOutput { satoshis:Some(100_000),locking_script:script.clone(),change:false });
        let hash=address::hex_str_to_hash(&funding.id().unwrap()).unwrap();
        repositories::upsert_transaction(&pool,&hash,Some(10),Some(&hex::decode(funding.to_hex().unwrap()).unwrap())).await.unwrap();
        repositories::upsert_transaction_output(&pool,&hash,0,100_000,receive["keyinstance_id"].as_i64().unwrap(),0,Some(&hex::encode(script.to_binary()))).await.unwrap();
        pool.close().await;
    }
    let secret;let recovery;let plan_id;
    { let mut a=Agent::start_with_payments(&s2,&dir,true);
      assert!(a.call(4,"open_wallet",json!({"wallet_path":"legacy"}))["result"].is_object());
      assert!(a.call(5,"unlock_wallet",json!({"password":"test-password"}))["error"].is_null());
      let setup=a.call(6,"begin_totp_setup",json!({"password":"test-password"}));
      secret=totp_rs::Secret::Encoded(setup["result"]["secret_base32"].as_str().unwrap().to_string()).to_bytes().unwrap();
      let totp=TotpInstance::from_secret_bytes(&secret,"ElectrumSV-Mc","wallet").unwrap();
      assert!(a.call(7,"confirm_totp_setup",json!({"password":"test-password","code":totp.generate_current().unwrap()}))["error"].is_null());
      recovery=a.call(8,"generate_totp_recovery_codes",json!({"password":"test-password","code":totp.generate_current().unwrap()}))["result"][0].as_str().unwrap().to_string();
      let plan=a.call(9,"prepare_tx",json!({"outputs":[{"address":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","satoshis":10000}],"fee_rate":1}));
      plan_id=plan["result"]["plan_id"].as_str().unwrap().to_string();
      assert!(a.call(10,"sign_tx",json!({"plan_id":plan_id,"totp_code":totp.generate_current().unwrap()}))["result"].is_object());
      assert!(a.call(11,"close_wallet",json!({}))["error"].is_null()); }
    let before=fingerprint(&wallet).await;assert_eq!(before.1,33);
    async fn ledger(path:&Path)->(Vec<(String,String,String,Option<String>,Option<String>)>,Vec<(Vec<u8>,i64,String)>) {
        let options=sqlx::sqlite::SqliteConnectOptions::new().filename(path).read_only(true).immutable(true);
        let p=sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect_with(options).await.unwrap();
        let plans=sqlx::query_as("SELECT plan_id,state,plan_json,signed_raw,txid FROM SpendPlans ORDER BY plan_id").fetch_all(&p).await.unwrap();
        let reservations=sqlx::query_as("SELECT tx_hash,tx_index,plan_id FROM SpendReservations ORDER BY tx_hash,tx_index").fetch_all(&p).await.unwrap();
        p.close().await;(plans,reservations)
    }
    let ledger_before=ledger(&wallet).await;assert_eq!(ledger_before.0.len(),1);assert_eq!(ledger_before.1.len(),1);
    let backup=dir.join("migration-backup.sqlite");
    { let mut a=Agent::start_with_payments(current,&dir,true);
      assert!(a.call(12,"open_wallet",json!({"wallet_path":"legacy"}))["result"].is_object());
      assert_eq!(a.call(13,"get_wallet_status",json!({}))["result"]["wallet_format"],33);
      let totp=TotpInstance::from_secret_bytes(&secret,"ElectrumSV-Mc","wallet").unwrap();
      assert_eq!(a.call(130,"preview_migration",json!({"password":"test-password","unexpected":true}))["error"]["code"],-32602);
      let invalid_auth=a.call(131,"preview_migration",json!({"password":"wrong","totp_code":totp.generate_current().unwrap()}));
      assert_eq!(invalid_auth["error"]["data"]["outcome"],"not_committed");assert!(!backup.exists());
      assert!(a.call(14,"preview_migration",json!({"password":"test-password"}))["error"]["data"].is_object());
      let preview=a.call(15,"preview_migration",json!({"password":"test-password","totp_code":totp.generate_current().unwrap()}));
      assert_eq!(preview["result"]["from_version"],33);assert_eq!(preview["result"]["to_version"],34);
      assert_eq!(preview["result"]["policy"]["legacy_totp_enabled"],true);
      let token=preview["result"]["confirmation_token"].as_str().unwrap().to_string();
      writeln!(a.input,"{}",json!({"jsonrpc":"2.0","method":"migrate_wallet","params":{"password":"test-password","totp_code":totp.generate_current().unwrap(),"backup_path":backup,"confirmation_token":token}})).unwrap();a.input.flush().unwrap();
      assert_eq!(a.call(16,"get_wallet_status",json!({}))["result"]["wallet_format"],33);assert!(!backup.exists());
      let failed=a.call(17,"migrate_wallet",json!({"password":"test-password","totp_code":totp.generate_current().unwrap(),"backup_path":backup,"confirmation_token":"invalid"}));
      assert_eq!(failed["error"]["data"]["outcome"],"not_committed");assert!(!backup.exists());
      assert!(a.call(170,"close_wallet",json!({}))["error"].is_null());
      assert!(a.call(171,"open_wallet",json!({"wallet_path":"legacy"}))["result"].is_object());
      let stale=a.call(172,"migrate_wallet",json!({"password":"test-password","totp_code":totp.generate_current().unwrap(),"backup_path":backup,"confirmation_token":token}));
      assert_eq!(stale["error"]["data"]["outcome"],"not_committed");assert!(!backup.exists());
      let existing=dir.join("existing.sqlite");std::fs::write(&existing,b"sentinel").unwrap();
      let preview=a.call(173,"preview_migration",json!({"password":"test-password","totp_code":totp.generate_current().unwrap()}));
      let collision=a.call(174,"migrate_wallet",json!({"password":"test-password","totp_code":totp.generate_current().unwrap(),"backup_path":existing,"confirmation_token":preview["result"]["confirmation_token"]}));
      assert_eq!(collision["error"]["data"]["outcome"],"not_committed");assert_eq!(std::fs::read(&existing).unwrap(),b"sentinel");
      let preview=a.call(18,"preview_migration",json!({"password":"test-password","totp_code":totp.generate_current().unwrap()}));
      let token=preview["result"]["confirmation_token"].as_str().unwrap().to_string();
      let result=a.call(19,"migrate_wallet",json!({"password":"test-password","totp_code":totp.generate_current().unwrap(),"backup_path":backup,"confirmation_token":token}));
      assert_eq!(result["result"]["from_version"],33);assert_eq!(result["result"]["to_version"],34);assert_eq!(result["result"]["reopen_required"],true);
      assert_eq!(a.call(20,"get_wallet_status",json!({}))["result"]["is_open"],false);
      assert!(a.call(21,"open_wallet",json!({"wallet_path":"legacy"}))["result"].is_object());
      assert!(a.call(22,"unlock_wallet",json!({"password":"test-password","totp_code":totp.generate_current().unwrap()}))["error"].is_null());
      assert_eq!(a.call(23,"get_spend_plan_status",json!({"plan_id":plan_id}))["result"]["state"],"SIGNED");
      assert!(a.call(24,"close_wallet",json!({}))["error"].is_null()); }
    assert_eq!(fingerprint(&wallet).await.1,34);assert_eq!(fingerprint(&backup).await,before);assert_eq!(ledger(&wallet).await,ledger_before);
    { let mut a=Agent::start_with_payments(&old,&dir,true);let totp=TotpInstance::from_secret_bytes(&secret,"ElectrumSV-Mc","wallet").unwrap();
      assert!(a.call(240,"open_wallet",json!({"wallet_path":"migration-backup"}))["result"].is_object());
      assert!(a.call(241,"unlock_wallet",json!({"password":"test-password","totp_code":totp.generate_current().unwrap()}))["error"].is_null());
      assert!(a.call(242,"close_wallet",json!({}))["error"].is_null()); }
    { let mut a=Agent::start(&old,&dir);assert!(a.call(25,"open_wallet",json!({"wallet_path":"legacy"}))["error"].is_object()); }
    { let mut a=Agent::start_with_payments(&s2,&dir,true);let totp=TotpInstance::from_secret_bytes(&secret,"ElectrumSV-Mc","wallet").unwrap();
      assert!(a.call(26,"open_wallet",json!({"wallet_path":"legacy"}))["result"].is_object());
      assert!(a.call(27,"unlock_wallet",json!({"password":"test-password","totp_code":totp.generate_current().unwrap()}))["error"].is_null());
      assert!(a.call(28,"close_wallet",json!({}))["error"].is_null()); }
    let recovery_dir=root.join("recovery");std::fs::create_dir(&recovery_dir).unwrap();std::fs::copy(&wallet,recovery_dir.join("copy.sqlite")).unwrap();
    { let mut a=Agent::start_with_payments(&s2,&recovery_dir,true);assert!(a.call(29,"open_wallet",json!({"wallet_path":"copy"}))["result"].is_object());
      assert!(a.call(30,"recover_totp",json!({"password":"test-password","recovery_code":recovery}))["error"].is_null());
      assert!(a.call(31,"recover_totp",json!({"password":"test-password","recovery_code":recovery}))["error"].is_object());
      assert!(a.call(32,"close_wallet",json!({}))["error"].is_null()); }
    std::fs::remove_dir_all(root).unwrap();
}
