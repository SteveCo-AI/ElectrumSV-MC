//! Explicit compatibility test requiring two separately supplied historical binaries.
use bsv::compat::bip32::ExtendedKey;
use electrumsv_mc_lib::{core::address::pubkey_to_p2pkh_address, services::wallet_service, state::AppState};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::{BufRead, BufReader, Write}, path::{Path,PathBuf}, process::{Child,ChildStdin,Command,Stdio}, sync::mpsc::{self,Receiver}, time::Duration};
const WORDS:&str="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const LEGACY_XPUB:&str="xpub6DBt8NsjkcZmMGvJpA27bzaM244citSghpHVJwfs1WYGcLbZK5xcEgT65tf8CWnzvc9wQeiphXK9gSGgjoxtTA8Yhq1K5PiFrcoJjRo9TBn";
struct Agent { child:Child, input:ChildStdin, output:Receiver<std::io::Result<String>> }
impl Agent {
 fn start(binary:&Path,dir:&Path)->Self { let mut child=Command::new(binary).args(["--agent","--data-dir"]).arg(dir).arg("--enable-wallet-maintenance").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();let input=child.stdin.take().unwrap();let stdout=child.stdout.take().unwrap();let(tx,output)=mpsc::channel();std::thread::spawn(move||for line in BufReader::new(stdout).lines(){if tx.send(line).is_err(){break}});Self{child,input,output} }
 fn call(&mut self,id:u32,method:&str,params:Value)->Value { writeln!(self.input,"{}",json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).unwrap();self.input.flush().unwrap();let line=self.output.recv_timeout(Duration::from_secs(40)).unwrap_or_else(|_|panic!("RPC timeout: {method}")).unwrap();let v:Value=serde_json::from_str(&line).unwrap();assert_eq!(v["id"],id);v }
}
impl Drop for Agent { fn drop(&mut self){let _=self.child.kill();let _=self.child.wait();} }
fn binary(var:&str,expected:&str)->PathBuf { let path=PathBuf::from(std::env::var_os(var).unwrap_or_else(||panic!("{var} must specify the historical binary")));let actual=hex::encode(Sha256::digest(std::fs::read(&path).unwrap()));assert_eq!(actual,expected,"historical artifact hash");path }
async fn assert_identity(dir:&Path,expected_receive:&str,password:&str,expected_version:u32) {
 let mut state=AppState::new();state.data_dir=dir.to_string_lossy().into();
 wallet_service::open_wallet(&state,"wallet").await.unwrap();wallet_service::unlock_wallet_authorized(&state,password,None).await.unwrap();
 {let guard=state.active_wallet.lock().unwrap();let wallet=guard.as_ref().unwrap();assert_eq!(wallet.keystore_data.xpub,LEGACY_XPUB);let key=ExtendedKey::from_string(wallet.decrypted_xprv.as_ref().unwrap()).unwrap().derive("0/0").unwrap();assert_eq!(pubkey_to_p2pkh_address(&key.public_key().unwrap()),expected_receive);}
 let version=wallet_service::get_wallet_status(&state);assert_eq!(version.wallet_format,Some(expected_version));wallet_service::close_wallet(&state).await.unwrap();
}
#[tokio::test]
#[ignore = "requires separately supplied pinned historical binaries"]
async fn old_unicode_wallets_survive_reopen_rotation_and_migration() {
 let old33=binary("WALLET_COMPAT_OLD_BINARY","45659e194a4b6836981f48ac7d47c99bc3304d054e6c156f722dd64a8d3ed121");
 let old34=binary("WALLET_COMPAT_S2_BINARY","23d1d4b4ba257ee5ef69b542a5dd37407227ca26f70d2f5f8aa92a3d9e0c8f0e");
 let current=Path::new(env!("CARGO_BIN_EXE_electrumsv-mc"));
 let root=std::env::temp_dir().join(format!("wallet-historical-unicode-{}-{}",std::process::id(),chrono::Utc::now().timestamp_nanos_opt().unwrap()));std::fs::create_dir_all(&root).unwrap();
 for (version,old) in [(33,&old33),(34,&old34)] { let dir=root.join(version.to_string());std::fs::create_dir(&dir).unwrap();
  let address; { let mut a=Agent::start(old,&dir);let created=a.call(1,"create_wallet",json!({"name":"wallet","password":"old-password","mnemonic":WORDS,"passphrase":" café "}));assert!(created["result"].is_object());let receive=a.call(2,"get_receive_address",json!({}));address=receive["result"]["address"].as_str().unwrap().to_owned();assert!(a.call(3,"close_wallet",json!({}))["error"].is_null()); }
  assert_identity(&dir,&address,"old-password",version).await;
  {let mut a=Agent::start(current,&dir);assert!(a.call(4,"open_wallet",json!({"wallet_path":"wallet"}))["result"].is_object());assert!(a.call(5,"unlock_wallet",json!({"password":"old-password"}))["error"].is_null());assert!(a.call(6,"change_password",json!({"old_password":"old-password","new_password":"new-password"}))["error"].is_null());assert!(a.call(7,"close_wallet",json!({}))["error"].is_null());}
  assert_identity(&dir,&address,"new-password",version).await;
  if version==33 { let mut a=Agent::start(current,&dir);assert!(a.call(8,"open_wallet",json!({"wallet_path":"wallet"}))["result"].is_object());let preview=a.call(9,"preview_migration",json!({"password":"new-password"}));let token=preview["result"]["confirmation_token"].as_str().unwrap();let result=a.call(10,"migrate_wallet",json!({"password":"new-password","backup_path":dir.join("backup.sqlite"),"confirmation_token":token}));assert_eq!(result["result"]["to_version"],34);drop(a);assert_identity(&dir,&address,"new-password",34).await; }
 }
 std::fs::remove_dir_all(root).unwrap();
}
