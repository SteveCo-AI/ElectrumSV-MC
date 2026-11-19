use crate::{
    db::connection,
    services::{account_service, wallet_service},
    state::AppState,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, Read, Write},
    path::Path,
};

const MAX_REQUEST: u64 = 65536;

#[derive(Clone, Copy, Default)]
pub struct Capabilities {
    pub payments: bool,
    pub network: bool,
    pub broadcast: bool,
    pub wallet_maintenance: bool,
}

impl Capabilities {
    pub fn validate(self) -> Result<(), &'static str> {
        if self.broadcast && !(self.payments && self.network) {
            return Err("--allow-broadcast requires --enable-payments and --allow-network");
        }
        Ok(())
    }
}

/// A lock is held until the process exits, including if it crashes.
pub fn lock_data_dir(path: &Path) -> Result<(File, String), String> {
    std::fs::create_dir_all(path).map_err(|e| format!("data directory: {e}"))?;
    let path = path
        .canonicalize()
        .map_err(|e| format!("data directory: {e}"))?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path.join(".electrumsv-mc.lock"))
        .map_err(|e| format!("data directory lock: {e}"))?;
    lock.try_lock()
        .map_err(|e| format!("data directory is already in use or cannot be locked: {e}"))?;
    Ok((lock, path.to_string_lossy().into_owned()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    name: String,
    password: String,
    mnemonic: Option<String>,
    passphrase: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    wallet_path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Unlock {
    password: String,
    totp_code: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    account_id: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressScan {
    account_id: i64,
    wallet_instance_token: String,
    end_index_exclusive: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    account_id: Option<i64>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Connect {
    host: String,
    port: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    outputs: Vec<crate::core::transaction::PaymentOutput>,
    fee_rate: u64,
    op_return_data: Option<String>,
    strategy: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sign {
    plan_id: String,
    totp_code: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    plan_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Broadcast {
    plan_id: String,
    expected_txid: String,
    #[serde(default)]
    retry_unknown: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Password {
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupWallet {
    backup_path: String,
    password: String,
    totp_code: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePassword {
    old_password: String,
    new_password: String,
    totp_code: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationPreviewRequest { password: String, totp_code: Option<String> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationRequest { password: String, totp_code: Option<String>, backup_path: String, confirmation_token: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupConfirm { password: String, code: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery { password: String, recovery_code: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TotpCode {
    code: String,
}

fn migration_rpc_error(e: crate::services::wallet_migration::MigrationError) -> (i64, String, Option<Value>) {
    match serde_json::to_value(e) {
        Ok(data) => (-32000, "migration failed".into(), Some(data)),
        Err(_) => (-32603, "Internal error".into(), None),
    }
}

async fn dispatch_migration(state: &AppState, caps: Capabilities, method: &str, params: Value) -> Result<Value, (i64, String, Option<Value>)> {
    if !caps.wallet_maintenance { return Err((-32000, "wallet maintenance capability disabled".into(), None)); }
    if method == "preview_migration" {
        let p: MigrationPreviewRequest=serde_json::from_value(params).map_err(|_| (-32602,"Invalid params".into(),None))?;
        let result=crate::services::wallet_migration::preview_migration(state,&p.password,p.totp_code.as_deref()).await
            .map_err(migration_rpc_error)?;
        serde_json::to_value(result).map_err(|_| (-32603,"Internal error".into(),None))
    } else {
        let p: MigrationRequest=serde_json::from_value(params).map_err(|_| (-32602,"Invalid params".into(),None))?;
        let result=crate::services::wallet_migration::migrate_wallet(state,&p.password,p.totp_code.as_deref(),&p.backup_path,&p.confirmation_token).await
            .map_err(migration_rpc_error)?;
        serde_json::to_value(result).map_err(|_| (-32603,"Internal error".into(),None))
    }
}

async fn dispatch(state: &AppState, caps: Capabilities, method: &str, params: Value) -> Result<Value, (i64, String)> {
    dispatch_inner(state, caps, method, params, #[cfg(test)] None).await
}

async fn dispatch_inner(
    state: &AppState, caps: Capabilities, method: &str, params: Value,
    #[cfg(test)] test_roots: Option<rustls::RootCertStore>,
) -> Result<Value, (i64, String)> {
    fn parse<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, (i64, String)> {
        serde_json::from_value(v).map_err(|_| (-32602, "Invalid params".into()))
    }
    fn output<T: serde::Serialize>(v: Result<T, String>) -> Result<Value, (i64, String)> {
        v.map_err(|e| (-32000, e))
            .and_then(|v| serde_json::to_value(v).map_err(|_| (-32603, "Internal error".into())))
    }
    if matches!(
        method,
        "list_wallets"
            | "close_wallet"
            | "get_wallet_status"
            | "get_capabilities"
            | "disconnect_server"
            | "list_spend_plans"
            | "is_totp_enabled"
            | "cancel_totp_setup"
    ) && params != json!({})
    {
        return Err((-32602, "Invalid params".into()));
    }
    if !params.is_object() {
        return Err((-32602, "Invalid params".into()));
    }
    if matches!(
        method,
        "prepare_tx"
            | "sign_tx"
            | "get_spend_plan_status"
            | "list_spend_plans"
            | "cancel_spend_plan"
            | "enable_totp"
            | "is_totp_enabled"
            | "verify_totp"
            | "begin_totp_setup" | "confirm_totp_setup" | "cancel_totp_setup"
    ) && !caps.payments
    {
        return Err((-32000, "payments capability disabled".into()));
    }
    if matches!(
        method,
        "connect_server" | "disconnect_server" | "sync_wallet" | "scan_address_range"
    ) && !caps.network
    {
        return Err((-32000, "network capability disabled".into()));
    }
    if method == "broadcast_plan" && !caps.broadcast {
        return Err((-32000, "broadcast capability disabled".into()));
    }
    if matches!(method, "backup_wallet" | "change_password" | "recover_totp" | "disable_totp" | "generate_totp_recovery_codes") && !caps.wallet_maintenance {
        return Err((-32000, "wallet maintenance capability disabled".into()));
    }
    match method {
        "get_capabilities" => {
            Ok(json!({"payments":caps.payments,"network":caps.network,"broadcast":caps.broadcast,"wallet_maintenance":caps.wallet_maintenance}))
        }
        "backup_wallet" => {
            let p: BackupWallet = parse(params)?;
            output(crate::commands::extra::backup_wallet_authorized(state, p.backup_path, p.password, p.totp_code).await)
        }
        "change_password" => {
            let p: ChangePassword = parse(params)?;
            output(crate::commands::wallet::change_password_authorized(state, &p.old_password, &p.new_password, p.totp_code.as_deref()).await)
        }
        "begin_totp_setup" => { let p: Password = parse(params)?; output(crate::commands::wallet::begin_totp_setup_inner(state, &p.password).await) }
        "confirm_totp_setup" => { let p: SetupConfirm = parse(params)?; output(crate::commands::wallet::confirm_totp_setup_inner(state, &p.password, &p.code).await) }
        "cancel_totp_setup" => output(crate::commands::wallet::cancel_totp_setup_inner(state).await),
        "recover_totp" => { let p: Recovery = parse(params)?; output(crate::commands::wallet::recover_totp_inner(state, &p.password, &p.recovery_code).await) }
        "disable_totp" => { let p: SetupConfirm = parse(params)?; output(crate::commands::wallet::disable_totp_inner(state, p.password, p.code).await) }
        "generate_totp_recovery_codes" => { let p: SetupConfirm = parse(params)?; output(crate::commands::wallet::generate_totp_recovery_codes_inner(state, p.password, p.code).await) }
        "enable_totp" => {
            let p: Password = parse(params)?;
            output(crate::commands::wallet::enable_totp_inner(state, p.password).await)
        }
        "is_totp_enabled" => output(crate::commands::wallet::is_totp_enabled_inner(state).await),
        "verify_totp" => {
            let p: TotpCode = parse(params)?;
            output(crate::commands::wallet::verify_totp_inner(state, p.code).await)
        }
        "connect_server" => {
            let p: Connect = parse(params)?;
            if p.host.is_empty() || p.port == 0 {
                return Err((-32602, "Invalid params".into()));
            }
            if state.network.lock().unwrap().connected {
                return Err((-32000, "already connected".into()));
            }
            let server = crate::network::server_list::ServerEntry::new(&p.host, p.port);
            #[cfg(test)]
            let result = if let Some(roots) = test_roots {
                crate::commands::network::connect_explicit_server_with_test_roots(state, server, roots).await
            } else {
                crate::commands::network::connect_explicit_server(state, server).await
            };
            #[cfg(not(test))]
            let result = crate::commands::network::connect_explicit_server(state, server).await;
            output(result.map(|client| client.server_host()))
        }
        "disconnect_server" => {
            output(crate::commands::network::disconnect_server_inner(state).await)
        }
        "sync_wallet" => {
            let p: Account = parse(params)?;
            output(crate::commands::network::sync_wallet_inner(state, p.account_id).await)
        }
        "scan_address_range" => {
            let p: AddressScan = parse(params)?;
            if !(1..=1000).contains(&p.end_index_exclusive) || p.wallet_instance_token.is_empty() {
                return Err((-32602, "Invalid params".into()));
            }
            output(crate::commands::network::scan_address_range_inner(state, p.account_id, &p.wallet_instance_token, p.end_index_exclusive).await)
        }
        "prepare_tx" => {
            let p: Prepare = parse(params)?;
            output(
                crate::services::transaction_service::prepare_tx(
                    state,
                    p.outputs,
                    Some(p.fee_rate),
                    p.op_return_data,
                    p.strategy,
                )
                .await,
            )
        }
        "sign_tx" => {
            let p: Sign = parse(params)?;
            output(
                crate::services::transaction_service::sign_tx(state, p.plan_id, p.totp_code).await,
            )
        }
        "get_spend_plan_status" => {
            let p: Plan = parse(params)?;
            output(
                crate::services::transaction_service::get_spend_plan_status(state, &p.plan_id)
                    .await,
            )
        }
        "list_spend_plans" => {
            output(crate::services::transaction_service::list_spend_plans(state).await)
        }
        "cancel_spend_plan" => {
            let p: Plan = parse(params)?;
            output(crate::services::transaction_service::cancel_spend_plan(state, &p.plan_id).await)
        }
        "broadcast_plan" => {
            let p: Broadcast = parse(params)?;
            output(
                crate::services::transaction_service::broadcast_plan(
                    state,
                    &p.plan_id,
                    &p.expected_txid,
                    p.retry_unknown,
                )
                .await,
            )
        }
        "list_wallets" => {
            output(connection::list_wallet_files(&state.data_dir).map_err(|e| e.to_string()))
        }
        "create_wallet" => {
            let p: Create = parse(params)?;
            output(
                wallet_service::create_wallet(
                    state,
                    &p.name,
                    &p.password,
                    p.mnemonic.as_deref(),
                    p.passphrase.as_deref(),
                )
                .await
                .map_err(|e| e.to_string()),
            )
        }
        "open_wallet" => {
            let p: Open = parse(params)?;
            output(
                wallet_service::open_wallet(state, &p.wallet_path)
                    .await
                    .map_err(|e| e.to_string()),
            )
        }
        "unlock_wallet" => {
            let p: Unlock = parse(params)?;
            output(
                wallet_service::unlock_wallet_authorized(
                    state,
                    &p.password,
                    p.totp_code.as_deref(),
                )
                .await,
            )
        }
        "close_wallet" => output(
            wallet_service::close_wallet(state)
                .await
                .map_err(|e| e.to_string()),
        ),
        "get_wallet_status" => output(Ok(wallet_service::get_wallet_status(state))),
        "get_history" => {
            let p: History = parse(params)?;
            if p.limit.is_some_and(|limit| !(1..=500).contains(&limit)) || p.offset.is_some_and(|offset| offset < 0) {
                return Err((-32602, "Invalid params".into()));
            }
            output(crate::commands::account::get_history_inner(state, p.account_id, p.limit, p.offset).await)
        }
        "get_balance" => {
            let p: Account = parse(params)?;
            output(account_service::get_balance(state, p.account_id).await)
        }
        "get_receive_address" => {
            let p: Account = parse(params)?;
            output(account_service::get_receive_address(state, p.account_id).await)
        }
        _ => Err((-32601, "Method not found".into())),
    }
}

pub fn run(data_dir: String, caps: Capabilities) -> Result<(), String> {
    caps.validate().map_err(str::to_string)?;
    let (_lock, data_dir) = lock_data_dir(Path::new(&data_dir))?;
    let mut state = AppState::new();
    state.data_dir = data_dir;
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut out = io::stdout().lock();
    loop {
        let mut line = Vec::new();
        let n = (&mut input)
            .take(MAX_REQUEST + 1)
            .read_until(b'\n', &mut line)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        if n as u64 > MAX_REQUEST {
            return Err("request exceeds maximum size".into());
        }
        let parsed: Result<Value, _> = serde_json::from_slice(&line);
        let response = match parsed {
            Err(_) => Some(
                json!({"jsonrpc":"2.0", "id":null, "error":{"code":-32700,"message":"Parse error"}}),
            ),
            Ok(req) => {
                let obj = req.as_object();
                let id = obj.and_then(|o| o.get("id")).cloned();
                let valid_id = id
                    .as_ref()
                    .map_or(true, |v| v.is_null() || v.is_string() || v.is_number());
                let method = obj.and_then(|o| o.get("method")).and_then(Value::as_str);
                let valid = obj.and_then(|o| o.get("jsonrpc")) == Some(&json!("2.0"))
                    && method.is_some()
                    && valid_id;
                if !valid {
                    Some(
                        json!({"jsonrpc":"2.0", "id":null, "error":{"code":-32600,"message":"Invalid Request"}}),
                    )
                } else {
                    let params = obj
                        .and_then(|o| o.get("params"))
                        .cloned()
                        .unwrap_or(json!({}));
                    if id.is_none()
                        && !matches!(
                            method.unwrap(),
                            "list_wallets"
                                | "get_wallet_status"
                                | "get_capabilities"
                                | "is_totp_enabled"
                                | "verify_totp"
                        )
                    {
                        continue;
                    }
                    if matches!(method.unwrap(), "preview_migration" | "migrate_wallet") {
                        let result=runtime.block_on(dispatch_migration(&state,caps,method.unwrap(),params));
                        id.map(|id| match result {
                            Ok(value)=>json!({"jsonrpc":"2.0","id":id,"result":value}),
                            Err((code,message,Some(data)))=>json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message,"data":data}}),
                            Err((code,message,None))=>json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}),
                        })
                    } else {
                        let result = runtime.block_on(dispatch(&state, caps, method.unwrap(), params));
                        id.map(|id| match result {
                            Ok(value) => json!({"jsonrpc":"2.0","id":id,"result":value}),
                            Err((code, message)) => json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
                        })
                    }
                }
            }
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut out, &response).map_err(|e| e.to_string())?;
            writeln!(out).map_err(|e| e.to_string())?;
            out.flush().map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod payment_dispatch_tests {
    use super::*;
    use crate::db::repositories;
    use crate::security::totp::TotpInstance;

    #[test]
    fn migration_unknown_outcome_remains_structured_in_rpc_error() {
        let error = crate::services::wallet_migration::MigrationError {
            phase: "commit", outcome: "unknown", reopen_required: true,
            backup_path: Some("backup.sqlite".into()), backup_outcome: "published",
            message: "commit outcome uncertain",
        };
        let (code, _, data) = migration_rpc_error(error);
        let data = data.unwrap();
        assert_eq!(code, -32000);
        assert_eq!(data["outcome"], "unknown");
        assert_eq!(data["reopen_required"], true);
        assert_eq!(data["backup_outcome"], "published");
        assert_eq!(data["backup_path"], "backup.sqlite");
    }

    #[test]
    fn invalid_capabilities_are_rejected_before_directory_creation() {
        let directory = std::env::temp_dir().join(format!(
            "wallet-invalid-cap-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        assert!(run(
            directory.to_str().unwrap().into(),
            Capabilities {
                payments: false,
                network: true,
                broadcast: true,
                ..Default::default()
            }
        )
        .is_err());
        assert!(!directory.exists());
    }
    use bsv::compat::bip32::ExtendedKey;
    use bsv::script::templates::{p2pkh::P2PKH, ScriptTemplateLock};
    use bsv::transaction::{
        transaction::Transaction, transaction_input::TransactionInput,
        transaction_output::TransactionOutput,
    };

    #[tokio::test]
    async fn payment_dispatch_prepares_and_signs_without_network() {
        let directory = std::env::temp_dir().join(format!(
            "wallet-agent-pay-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let mut state = AppState::new();
        state.data_dir = directory.to_str().unwrap().into();
        let caps = Capabilities {
            payments: true,
            network: false,
            broadcast: false,
            ..Default::default()
        };
        let created = dispatch(&state, caps, "create_wallet", json!({"name":"synthetic","password":"test-password","mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"})).await.unwrap();
        assert_eq!(created["is_new_mnemonic"], false);
        let (pool, account, xprv) = {
            let guard = state.active_wallet.lock().unwrap();
            let active = guard.as_ref().unwrap();
            (
                active.db_pool.clone(),
                active.account_id,
                active.decrypted_xprv.clone().unwrap(),
            )
        };
        let account_key = ExtendedKey::from_string(&xprv).unwrap();
        let address = crate::core::address::pubkey_to_p2pkh_address(
            &account_key.derive("0/0").unwrap().public_key().unwrap(),
        );
        let script = P2PKH::from_address(&address).unwrap().lock().unwrap();
        let master = repositories::get_first_master_key(&pool)
            .await
            .unwrap()
            .unwrap();
        let key = repositories::insert_keyinstance(
            &pool,
            account,
            Some(master.masterkey_id),
            repositories::derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            repositories::script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();
        let mut funding = Transaction::new();
        funding.inputs.push(TransactionInput {
            source_txid: Some(hex::encode((0u8..32).collect::<Vec<_>>())),
            source_output_index: 1,
            ..Default::default()
        });
        funding.outputs.push(TransactionOutput {
            satoshis: Some(100_000),
            locking_script: script.clone(),
            change: false,
        });
        let id = funding.id().unwrap();
        let hash = crate::core::address::hex_str_to_hash(&id).unwrap();
        let raw = hex::decode(funding.to_hex().unwrap()).unwrap();
        repositories::upsert_transaction(&pool, &hash, Some(10), Some(&raw))
            .await
            .unwrap();
        repositories::upsert_transaction_output(
            &pool,
            &hash,
            0,
            100_000,
            key,
            0,
            Some(&hex::encode(script.to_binary())),
        )
        .await
        .unwrap();
        drop(pool);
        let setup = dispatch(
            &state,
            caps,
            "begin_totp_setup",
            json!({"password":"test-password"}),
        )
        .await
        .unwrap();
        let secret = totp_rs::Secret::Encoded(setup["secret_base32"].as_str().unwrap().to_string())
            .to_bytes()
            .unwrap();
        let code = TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "synthetic")
            .unwrap()
            .generate_current()
            .unwrap();
        dispatch(&state, caps, "confirm_totp_setup", json!({"password":"test-password", "code":code})).await.unwrap();
        let plan = dispatch(&state, caps, "prepare_tx", json!({"outputs":[{"address":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","satoshis":10000}], "fee_rate":1})).await.unwrap();
        let plan_id = plan["plan_id"].as_str().unwrap();
        assert!(dispatch(
            &state,
            caps,
            "sign_tx",
            json!({"plan_id":plan_id,"totp_code":"invalid"})
        )
        .await
        .is_err());
        assert_eq!(
            dispatch(
                &state,
                caps,
                "get_spend_plan_status",
                json!({"plan_id":plan_id})
            )
            .await
            .unwrap()["state"],
            "PREPARED"
        );
        let signed = dispatch(
            &state,
            caps,
            "sign_tx",
            json!({"plan_id":plan_id,"totp_code":code}),
        )
        .await
        .unwrap();
        assert!(signed["txid"].is_string());
        let tx = Transaction::from_hex(signed["signed_tx_hex"].as_str().unwrap()).unwrap();
        assert_eq!(tx.inputs[0].source_txid.as_deref(), Some(id.as_str()));
        let mut spend = bsv::script::spend::Spend::new(bsv::script::spend::SpendParams {
            locking_script: script,
            unlocking_script: tx.inputs[0].unlocking_script.clone().unwrap(),
            source_txid: id,
            source_output_index: 0,
            source_satoshis: 100_000,
            transaction_version: tx.version,
            transaction_lock_time: tx.lock_time,
            transaction_sequence: tx.inputs[0].sequence,
            other_inputs: vec![],
            other_outputs: tx.outputs.clone(),
            input_index: 0,
        });
        assert!(spend.validate().unwrap());
        let net = state.network.lock().unwrap();
        assert!(!net.connected && net.client.is_none() && net.woc_client.is_none());
        drop(net);
        assert!(dispatch(
            &state,
            caps,
            "broadcast_plan",
            json!({"plan_id":plan_id,"expected_txid":signed["txid"]})
        )
        .await
        .is_err());
        wallet_service::close_wallet(&state).await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(test)]
#[path = "agent_tls_test.rs"]
pub(crate) mod agent_tls_test;
