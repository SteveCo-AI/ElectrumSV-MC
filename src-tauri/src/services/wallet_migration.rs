//! Read-only inventory for a future explicit legacy migration.
//! Callers hold the wallet operation guard and supply their own SQLite transaction.
use crate::{core::{keystore, mnemonic}, security::encryption};
use bsv::compat::bip32::ExtendedKey;
use serde::Deserialize;
use sqlx::{Connection, Sqlite, SqliteConnection, Transaction};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InventoryError { UnsupportedSchema, UnsupportedRecords, InvalidSecrets, InvalidPolicy, Database }

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyScope { Unspecified, Login, Transaction }

/// Secret-bearing inventory: deliberately not Debug, Serialize or Clone.
pub(crate) struct LegacyInventory {
    pub masterkey_id: i64,
    pub account_id: i64,
    pub key_count: usize,
    pub xpub: String,
    pub derivation: String,
    pub xprv: Zeroizing<String>,
    pub mnemonic: Zeroizing<String>,
    pub passphrase: Zeroizing<String>,
    pub totp_secret: Option<Zeroizing<Vec<u8>>>,
    pub recovery_hashes: Vec<String>,
    pub scope: LegacyScope,
    pub totp_record_scope: Option<LegacyScope>,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct PolicySummary {
    pub legacy_totp_enabled: bool,
    pub legacy_wallet_scope: &'static str,
    pub legacy_record_scope: Option<&'static str>,
    pub target_policy_id: &'static str,
    pub newly_require_totp: &'static [&'static str],
}
impl LegacyScope {
    fn label(self) -> &'static str { match self { Self::Unspecified => "unspecified", Self::Login => "login", Self::Transaction => "tx" } }
}
impl LegacyInventory {
    pub fn policy_summary(&self) -> PolicySummary {
        PolicySummary {
            legacy_totp_enabled: self.totp_secret.is_some(),
            legacy_wallet_scope: self.scope.label(),
            legacy_record_scope: self.totp_record_scope.map(LegacyScope::label),
            target_policy_id: if self.totp_secret.is_some() { "totp-reauth-backup-change-delete-v1" } else { "totp-off-sign-unavailable-v1" },
            newly_require_totp: if self.totp_secret.is_some() { &["backup", "change_password", "delete_wallet"] } else { &[] },
        }
    }
    /// Compares sensitive inventory in memory without formatting or exposing it.
    pub fn equivalent_secrets(&self, other: &Self) -> bool {
        self.xpub == other.xpub && self.derivation == other.derivation
            && *self.xprv == *other.xprv && *self.mnemonic == *other.mnemonic
            && *self.passphrase == *other.passphrase && self.totp_secret.as_deref() == other.totp_secret.as_deref()
            && self.recovery_hashes == other.recovery_hashes && self.scope == other.scope
            && self.totp_record_scope == other.totp_record_scope
    }
    /// Password verification happens in inspect_legacy; this checks the separate TOTP challenge.
    pub fn verify_totp(&self, code: &str) -> Result<bool, InventoryError> {
        let Some(secret) = &self.totp_secret else { return Ok(false) };
        if code.len()!=6 || !code.bytes().all(|b| b.is_ascii_digit()) { return Ok(false); }
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(secret, "ElectrumSV-Mc", "wallet").map_err(|_| InventoryError::InvalidPolicy)?;
        totp.verify_current(code).map_err(|_| InventoryError::InvalidPolicy)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyKeystore { xpub: String, xprv: String, seed_type: String, derivation: String, seed: String, passphrase: Option<String> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPath { subpath: [u32; 2] }

async fn verify_schema(tx: &mut Transaction<'_, Sqlite>) -> Result<(), InventoryError> {
    let mut expected = SqliteConnection::connect("sqlite::memory:").await.map_err(|_| InventoryError::Database)?;
    for sql in [
        include_str!("../../migrations/0022_create_database.sql"), include_str!("../../migrations/0023_add_wallet_events.sql"),
        include_str!("../../migrations/0024_account_transactions.sql"), include_str!("../../migrations/0025_invoices.sql"),
        include_str!("../../migrations/0026_txo_coinbase_flag.sql"), include_str!("../../migrations/0027_totp_secrets.sql"),
        include_str!("../../migrations/0028_totp_recovery_codes.sql"), include_str!("../../migrations/0029_contacts.sql"),
        include_str!("../../migrations/0030_multisig_configs.sql"), include_str!("../../migrations/0031_txo_script_pubkey.sql"),
        include_str!("../../migrations/0032_transaction_delta_known.sql"), include_str!("../../migrations/0033_spend_reservations.sql"),
    ] { sqlx::query(sql).execute(&mut expected).await.map_err(|_| InventoryError::Database)?; }
    let q = "SELECT type,name,COALESCE(sql,'') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name";
    let actual: Vec<(String,String,String)> = sqlx::query_as(q).fetch_all(&mut **tx).await.map_err(|_| InventoryError::Database)?;
    let reference: Vec<(String,String,String)> = sqlx::query_as(q).fetch_all(&mut expected).await.map_err(|_| InventoryError::Database)?;
    if actual != reference { return Err(InventoryError::UnsupportedSchema); }
    Ok(())
}

pub(crate) async fn inspect_legacy(tx: &mut Transaction<'_, Sqlite>, password: &str) -> Result<LegacyInventory, InventoryError> {
    verify_schema(tx).await?;
    let version: Option<(String,)> = sqlx::query_as("SELECT value FROM WalletData WHERE key='migration'").fetch_optional(&mut **tx).await.map_err(|_| InventoryError::Database)?;
    if version.as_ref().map(|x| x.0.as_str()) != Some("33") { return Err(InventoryError::UnsupportedSchema); }
    let unknown: (i64,) = sqlx::query_as("SELECT count(*) FROM WalletData WHERE key LIKE 'crypto-%' OR (key LIKE 'totp_%' AND key NOT IN ('totp_scope','totp_recovery_codes'))").fetch_one(&mut **tx).await.map_err(|_| InventoryError::Database)?;
    if unknown.0 != 0 { return Err(InventoryError::UnsupportedRecords); }
    let masters: Vec<(i64,Option<i64>,i32,Vec<u8>)> = sqlx::query_as("SELECT masterkey_id,parent_masterkey_id,derivation_type,derivation_data FROM MasterKeys LIMIT 2").fetch_all(&mut **tx).await.map_err(|_| InventoryError::Database)?;
    let accounts: Vec<(i64,Option<i64>,i32)> = sqlx::query_as("SELECT account_id,default_masterkey_id,default_script_type FROM Accounts LIMIT 2").fetch_all(&mut **tx).await.map_err(|_| InventoryError::Database)?;
    let multisig: (i64,) = sqlx::query_as("SELECT count(*) FROM MultisigConfigs").fetch_one(&mut **tx).await.map_err(|_| InventoryError::Database)?;
    if masters.len()!=1 || accounts.len()!=1 || masters[0].1.is_some() || masters[0].2!=3 || masters[0].3.len()>140_000 || accounts[0].1!=Some(masters[0].0) || accounts[0].2!=2 || multisig.0!=0 { return Err(InventoryError::UnsupportedRecords); }
    let key_counts: (i64,i64) = sqlx::query_as("SELECT count(*),COALESCE(sum(CASE WHEN account_id != ? OR masterkey_id IS NULL OR masterkey_id != ? OR derivation_type != 3 OR script_type != 2 OR length(derivation_data) > 256 THEN 1 ELSE 0 END),0) FROM KeyInstances").bind(accounts[0].0).bind(masters[0].0).fetch_one(&mut **tx).await.map_err(|_| InventoryError::Database)?;
    if key_counts.0>100_000 || key_counts.1!=0 { return Err(InventoryError::UnsupportedRecords); }
    let paths: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT derivation_data FROM KeyInstances").fetch_all(&mut **tx).await.map_err(|_| InventoryError::Database)?;
    let mut unique = std::collections::HashSet::new();
    for (bytes,) in &paths {
        let path: KeyPath = serde_json::from_slice(bytes).map_err(|_| InventoryError::UnsupportedRecords)?;
        if path.subpath[0]>1 || path.subpath[1]>=1<<31 || !unique.insert(path.subpath) { return Err(InventoryError::UnsupportedRecords); }
    }
    let ks: LegacyKeystore = serde_json::from_slice(&masters[0].3).map_err(|_| InventoryError::UnsupportedRecords)?;
    if ks.seed_type!="bip39" || ks.derivation!=keystore::DERIVATION_PATH || password.is_empty() || ks.seed.is_empty() { return Err(InventoryError::UnsupportedRecords); }
    let xprv = Zeroizing::new(encryption::pw_decode(&ks.xprv,password).map_err(|_| InventoryError::InvalidSecrets)?);
    let words = Zeroizing::new(encryption::pw_decode(&ks.seed,password).map_err(|_| InventoryError::InvalidSecrets)?);
    let passphrase = Zeroizing::new(match ks.passphrase { Some(p) => encryption::pw_decode(&p,password).map_err(|_| InventoryError::InvalidSecrets)?, None => String::new() });
    let bip39 = bsv::compat::bip39::Mnemonic::from_string(&words, bsv::compat::bip39::Language::English).map_err(|_| InventoryError::UnsupportedRecords)?;
    if !bip39.check() { return Err(InventoryError::UnsupportedRecords); }
    let seed = Zeroizing::new(mnemonic::mnemonic_to_seed(&words,&passphrase).map_err(|_| InventoryError::InvalidSecrets)?);
    let master = ExtendedKey::from_seed(&seed).map_err(|_| InventoryError::InvalidSecrets)?;
    let derived = master.derive(&ks.derivation).map_err(|_| InventoryError::InvalidSecrets)?;
    if !derived.is_private() || derived.to_base58()!=*xprv || derived.to_public().map_err(|_| InventoryError::InvalidSecrets)?.to_base58()!=ks.xpub { return Err(InventoryError::InvalidSecrets); }
    let rows: Vec<(i64,Vec<u8>,Vec<u8>,String)> = sqlx::query_as("SELECT id,secret_encrypted,CAST(nonce AS BLOB),scope FROM TotpSecrets LIMIT 2").fetch_all(&mut **tx).await.map_err(|_| InventoryError::Database)?;
    let totp_rows: Vec<_> = rows.into_iter().map(|(id, secret, nonce, scope)| (id, Zeroizing::new(secret), nonce, scope)).collect();
    let table_codes: (i64,) = sqlx::query_as("SELECT count(*) FROM TotpRecoveryCodes").fetch_one(&mut **tx).await.map_err(|_| InventoryError::Database)?;
    if table_codes.0 != 0 || totp_rows.len()>1 || totp_rows.iter().any(|r| r.0!=1 || r.1.len()!=20 || !r.2.is_empty() || (r.3!="login" && r.3!="tx")) { return Err(InventoryError::InvalidPolicy); }
    let stored: Option<(String,)> = sqlx::query_as("SELECT value FROM WalletData WHERE key='totp_recovery_codes'").fetch_optional(&mut **tx).await.map_err(|_| InventoryError::Database)?;
    let hashes: Vec<String> = match stored { Some((v,)) if v.len()<=1000 => serde_json::from_str(&v).map_err(|_| InventoryError::InvalidPolicy)?, Some(_) => return Err(InventoryError::InvalidPolicy), None => Vec::new() };
    let unique_hashes: std::collections::HashSet<&str> = hashes.iter().map(String::as_str).collect();
    if hashes.len()>10 || unique_hashes.len()!=hashes.len() || hashes.iter().any(|h| h.len()!=64 || !h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) || (totp_rows.is_empty() && !hashes.is_empty()) { return Err(InventoryError::InvalidPolicy); }
    let scope: Option<(String,)> = sqlx::query_as("SELECT value FROM WalletData WHERE key='totp_scope'").fetch_optional(&mut **tx).await.map_err(|_| InventoryError::Database)?;
    let scope = match scope.as_ref().map(|v| v.0.as_str()) { None => LegacyScope::Unspecified, Some("login") => LegacyScope::Login, Some("tx") => LegacyScope::Transaction, _ => return Err(InventoryError::InvalidPolicy) };
    let totp_record_scope = totp_rows.first().map(|r| if r.3 == "login" { LegacyScope::Login } else { LegacyScope::Transaction });
    let totp_secret = totp_rows.into_iter().next().map(|r| r.1);
    Ok(LegacyInventory { masterkey_id: masters[0].0, account_id: accounts[0].0, key_count: paths.len(), xpub: ks.xpub, derivation: ks.derivation, xprv, mnemonic: words, passphrase, totp_secret, recovery_hashes: hashes, scope, totp_record_scope })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db::repositories, services::wallet_service, state::AppState};
    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    fn state() -> AppState {
        let mut state = AppState::new();
        state.data_dir = std::env::temp_dir().join(format!("wallet-migration-inventory-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap())).to_string_lossy().into();
        std::fs::create_dir_all(&state.data_dir).unwrap(); state
    }
    async fn fixture(state: &AppState) -> sqlx::SqlitePool {
        wallet_service::create_legacy_fixture(state, "legacy", "pw", WORDS, Some("TREZOR")).await.unwrap();
        state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone()
    }
    #[tokio::test]
    async fn legacy_inventory_preserves_bip39_totp_recovery_and_database() {
        let state = state(); let pool = fixture(&state).await;
        let account = state.active_wallet.lock().unwrap().as_ref().unwrap().account_id;
        let master = repositories::get_first_master_key(&pool).await.unwrap().unwrap();
        repositories::insert_keyinstance(&pool, account, Some(master.masterkey_id), 3, br#"{"subpath":[0,2]}"#, 2, 0, None).await.unwrap();
        repositories::store_totp_secret(&pool, &[8;20]).await.unwrap();
        let hashes = vec![crate::security::totp::hash_recovery_code("ABCD-EFGH")];
        repositories::store_recovery_codes(&pool, &hashes).await.unwrap();
        repositories::set_wallet_data(&pool, "totp_scope", "login").await.unwrap();
        repositories::set_wallet_data(&pool, "currency", "USD").await.unwrap();
        let before = repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data;
        let _guard = state.wallet_operation.lock().await;
        let mut tx = pool.begin().await.unwrap();
        assert!(matches!(inspect_legacy(&mut tx,"wrong").await, Err(InventoryError::InvalidSecrets)));
        let found = inspect_legacy(&mut tx,"pw").await.unwrap();
        assert_eq!(found.key_count,1); assert_eq!(&*found.mnemonic,WORDS); assert_eq!(&*found.passphrase,"TREZOR");
        assert_eq!(found.masterkey_id,master.masterkey_id); assert_eq!(found.account_id,account);
        assert_eq!(found.recovery_hashes, hashes); assert_eq!(&**found.totp_secret.as_ref().unwrap(), &[8;20]);
        assert!(found.scope == LegacyScope::Login);
        assert!(found.totp_record_scope == Some(LegacyScope::Login));
        assert_eq!(found.policy_summary().newly_require_totp, &["backup", "change_password", "delete_wallet"]);
        tx.rollback().await.unwrap(); drop(_guard);
        assert_eq!(repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data,before);
        assert_eq!(repositories::get_wallet_data(&pool,"currency").await.unwrap().as_deref(),Some("USD"));
        wallet_service::close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(state.data_dir).unwrap();
    }
    #[tokio::test]
    async fn scope_inventory_covers_known_values_and_rejects_unknown() {
        let state = state(); let pool = fixture(&state).await;
        repositories::store_totp_secret(&pool, &[8;20]).await.unwrap();
        let _guard = state.wallet_operation.lock().await; let mut tx = pool.begin().await.unwrap();
        for record in ["login", "tx"] {
            sqlx::query("UPDATE TotpSecrets SET scope=?").bind(record).execute(&mut *tx).await.unwrap();
            for configured in [None, Some("login"), Some("tx")] {
                sqlx::query("DELETE FROM WalletData WHERE key='totp_scope'").execute(&mut *tx).await.unwrap();
                if let Some(value) = configured { sqlx::query("INSERT INTO WalletData VALUES('totp_scope',?,0,0)").bind(value).execute(&mut *tx).await.unwrap(); }
                let found = inspect_legacy(&mut tx, "pw").await.unwrap(); let summary = found.policy_summary();
                assert_eq!(summary.legacy_record_scope, Some(record));
                assert_eq!(summary.legacy_wallet_scope, configured.unwrap_or("unspecified"));
                assert_eq!(summary.target_policy_id, "totp-reauth-backup-change-delete-v1");
            }
        }
        sqlx::query("UPDATE WalletData SET value='LOGIN' WHERE key='totp_scope'").execute(&mut *tx).await.unwrap();
        assert!(matches!(inspect_legacy(&mut tx,"pw").await, Err(InventoryError::InvalidPolicy)));
        sqlx::query("DELETE FROM WalletData WHERE key='totp_scope'").execute(&mut *tx).await.unwrap();
        sqlx::query("UPDATE TotpSecrets SET scope='other'").execute(&mut *tx).await.unwrap();
        assert!(matches!(inspect_legacy(&mut tx,"pw").await, Err(InventoryError::InvalidPolicy)));
        tx.rollback().await.unwrap(); drop(_guard); wallet_service::close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(state.data_dir).unwrap();
    }
    #[tokio::test]
    async fn rejects_multiple_records_unknown_schema_and_duplicate_hashes() {
        let state = state(); let pool = fixture(&state).await;
        let _guard = state.wallet_operation.lock().await; let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TABLE UnexpectedSecret(value BLOB)").execute(&mut *tx).await.unwrap();
        assert!(matches!(inspect_legacy(&mut tx,"pw").await, Err(InventoryError::UnsupportedSchema)));
        sqlx::query("DROP TABLE UnexpectedSecret").execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO MasterKeys(parent_masterkey_id,derivation_type,derivation_data,date_created,date_updated) SELECT NULL,derivation_type,derivation_data,0,0 FROM MasterKeys LIMIT 1").execute(&mut *tx).await.unwrap();
        assert!(matches!(inspect_legacy(&mut tx,"pw").await, Err(InventoryError::UnsupportedRecords)));
        sqlx::query("DELETE FROM MasterKeys WHERE masterkey_id != 1").execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO Accounts(default_masterkey_id,default_script_type,account_name,date_created,date_updated) VALUES(1,2,'other',0,0)").execute(&mut *tx).await.unwrap();
        assert!(matches!(inspect_legacy(&mut tx,"pw").await, Err(InventoryError::UnsupportedRecords)));
        sqlx::query("DELETE FROM Accounts WHERE account_id != 1").execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO TotpSecrets(id,secret_encrypted,nonce,scope,date_created,date_updated) VALUES(1,?,'','login',0,0)").bind(vec![8u8;20]).execute(&mut *tx).await.unwrap();
        let hash = "a".repeat(64);
        sqlx::query("INSERT INTO WalletData VALUES('totp_recovery_codes',?,0,0)").bind(serde_json::json!([hash, hash]).to_string()).execute(&mut *tx).await.unwrap();
        assert!(matches!(inspect_legacy(&mut tx,"pw").await, Err(InventoryError::InvalidPolicy)));
        tx.rollback().await.unwrap(); drop(_guard); wallet_service::close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(state.data_dir).unwrap();
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn verified_backup_independently_authenticates_same_secret_and_totp() {
        let state = state(); let pool = fixture(&state).await;
        let secret = [8u8;20]; repositories::store_totp_secret(&pool, &secret).await.unwrap();
        let hashes = vec![crate::security::totp::hash_recovery_code("ABCD-EFGH")];
        repositories::store_recovery_codes(&pool, &hashes).await.unwrap();
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").unwrap();
        let code = totp.generate_current().unwrap();
        let guard = state.wallet_operation.lock().await;
        let path = std::path::Path::new(&state.data_dir).join("verified-backup.sqlite");
        let backup = crate::commands::extra::backup_snapshot_locked(&state, &guard, path.to_str().unwrap()).await.unwrap();
        let mut source_tx = backup.begin_verified_source(&state, &guard).await.unwrap();
        let mut snapshot_tx = backup.readonly_pool().begin().await.unwrap();
        assert!(matches!(inspect_legacy(&mut source_tx,"wrong").await, Err(InventoryError::InvalidSecrets)));
        assert!(matches!(inspect_legacy(&mut snapshot_tx,"wrong").await, Err(InventoryError::InvalidSecrets)));
        let original = inspect_legacy(&mut source_tx,"pw").await.unwrap();
        let restored = inspect_legacy(&mut snapshot_tx,"pw").await.unwrap();
        assert!(original.equivalent_secrets(&restored));
        assert!(original.verify_totp(&code).unwrap() && restored.verify_totp(&code).unwrap());
        assert!(!original.verify_totp("invalid").unwrap() && !restored.verify_totp("invalid").unwrap());
        assert_eq!(restored.recovery_hashes, hashes);
        source_tx.rollback().await.unwrap(); snapshot_tx.rollback().await.unwrap(); drop(backup); drop(guard);
        wallet_service::close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(state.data_dir).unwrap();
    }
    #[tokio::test]
    #[ignore = "requires pinned historical S1 agent artifact"]
    async fn inventories_real_s1_45659e_fixture() {
        use std::io::Read;
        use tokio::io::AsyncWriteExt;
        use sha2::{Digest, Sha256};
        let binary = "/tmp/wallet-s1-compat/electrumsv-mc-45659e";
        let mut file = std::fs::File::open(binary).unwrap(); let mut hasher = Sha256::new(); let mut buf = [0u8; 65536];
        loop { let n = file.read(&mut buf).unwrap(); if n == 0 { break; } hasher.update(&buf[..n]); }
        assert_eq!(hex::encode(hasher.finalize()), "45659e194a4b6836981f48ac7d47c99bc3304d054e6c156f722dd64a8d3ed121");
        let state = state();
        let mut child = tokio::process::Command::new(binary).args(["--agent", "--data-dir", &state.data_dir])
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).kill_on_drop(true).spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let request = format!("{}\n", serde_json::json!({"jsonrpc":"2.0","id":1,"method":"create_wallet","params":{"name":"legacy","password":"pw","mnemonic":WORDS,"passphrase":"TREZOR"}}));
        input.write_all(request.as_bytes()).await.unwrap();
        drop(input);
        let output = tokio::time::timeout(std::time::Duration::from_secs(30), child.wait_with_output()).await.unwrap().unwrap(); assert!(output.status.success());
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap(); assert!(response["result"].is_object());
        let path = std::path::Path::new(&state.data_dir).join("legacy.sqlite");
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(path).read_only(true)).await.unwrap();
        let mut tx = pool.begin().await.unwrap(); let found = inspect_legacy(&mut tx, "pw").await.unwrap();
        assert_eq!(&*found.mnemonic, WORDS); assert_eq!(&*found.passphrase, "TREZOR"); assert_eq!(found.key_count, 0);
        tx.rollback().await.unwrap(); pool.close().await; std::fs::remove_dir_all(state.data_dir).unwrap();
    }
    #[tokio::test]
    async fn rejects_unknown_keys_corrupt_secrets_and_inconsistent_recovery() {
        let state = state(); let pool = fixture(&state).await;
        let master = repositories::get_first_master_key(&pool).await.unwrap().unwrap();
        let _guard = state.wallet_operation.lock().await;
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("UPDATE MasterKeys SET derivation_data=?").bind(br#"{"xpub":"x","xprv":"y","seed_type":"bip39","derivation":"m/44'/0'/0'","seed":"z","unknown":1}"#.as_slice()).execute(&mut *tx).await.unwrap();
        assert!(matches!(inspect_legacy(&mut tx,"pw").await, Err(InventoryError::UnsupportedRecords)));
        sqlx::query("UPDATE MasterKeys SET derivation_data=?").bind(&master.derivation_data).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO KeyInstances(account_id,masterkey_id,derivation_type,derivation_data,script_type,flags,date_created,date_updated) VALUES(1,1,3,?,999,0,0,0)").bind(br#"{"subpath":[0,0]}"#.as_slice()).execute(&mut *tx).await.unwrap();
        assert!(matches!(inspect_legacy(&mut tx,"pw").await, Err(InventoryError::UnsupportedRecords)));
        sqlx::query("DELETE FROM KeyInstances").execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO TotpRecoveryCodes(code_hash,used,date_created) VALUES('unhandled',0,0)").execute(&mut *tx).await.unwrap();
        assert!(matches!(inspect_legacy(&mut tx,"pw").await, Err(InventoryError::InvalidPolicy)));
        sqlx::query("DELETE FROM TotpRecoveryCodes").execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO WalletData(key,value,date_created,date_updated) VALUES('totp_recovery_codes',?,0,0)").bind(format!("[\"{}\"]", "a".repeat(64))).execute(&mut *tx).await.unwrap();
        assert!(matches!(inspect_legacy(&mut tx,"pw").await, Err(InventoryError::InvalidPolicy)));
        tx.rollback().await.unwrap(); drop(_guard);
        assert_eq!(repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data, master.derivation_data);
        wallet_service::close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(state.data_dir).unwrap();
    }
    #[tokio::test]
    async fn rejects_seed_passphrase_xpub_and_keypath_tampering() {
        let state = state(); let pool = fixture(&state).await;
        let master = repositories::get_first_master_key(&pool).await.unwrap().unwrap();
        let original: serde_json::Value = serde_json::from_slice(&master.derivation_data).unwrap();
        let _guard = state.wallet_operation.lock().await; let mut tx = pool.begin().await.unwrap();
        for (field, value, expected) in [
            ("seed", encryption::pw_encode("legal winner thank year wave sausage worth useful legal winner thank yellow", "pw"), InventoryError::InvalidSecrets),
            ("passphrase", encryption::pw_encode("different", "pw"), InventoryError::InvalidSecrets),
            ("xpub", "invalid".into(), InventoryError::InvalidSecrets),
            ("derivation", "m/44'/0'/1'".into(), InventoryError::UnsupportedRecords),
        ] {
            let mut altered = original.clone(); altered[field] = serde_json::json!(value);
            sqlx::query("UPDATE MasterKeys SET derivation_data=?").bind(serde_json::to_vec(&altered).unwrap()).execute(&mut *tx).await.unwrap();
            assert!(matches!(inspect_legacy(&mut tx, "pw").await, Err(e) if e == expected));
        }
        sqlx::query("UPDATE MasterKeys SET derivation_data=?").bind(&master.derivation_data).execute(&mut *tx).await.unwrap();
        for path in [br#"{"subpath":[2,0]}"#.as_slice(), br#"{"subpath":[0,2147483648]}"#.as_slice(), br#"{"subpath":[0,0],"extra":1}"#.as_slice()] {
            sqlx::query("INSERT INTO KeyInstances(account_id,masterkey_id,derivation_type,derivation_data,script_type,flags,date_created,date_updated) VALUES(1,1,3,?,2,0,0,0)").bind(path).execute(&mut *tx).await.unwrap();
            assert!(matches!(inspect_legacy(&mut tx,"pw").await, Err(InventoryError::UnsupportedRecords)));
            sqlx::query("DELETE FROM KeyInstances").execute(&mut *tx).await.unwrap();
        }
        tx.rollback().await.unwrap(); drop(_guard);
        assert_eq!(repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data, master.derivation_data);
        wallet_service::close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(state.data_dir).unwrap();
    }
}

#[derive(serde::Serialize)]
pub(crate) struct MigrationPreview {
    pub from_version: u32, pub to_version: u32, pub policy: PolicySummary,
    pub confirmation_token: String, pub expires_in_seconds: u64,
}
#[derive(serde::Serialize)]
pub(crate) struct MigrationSuccess { pub backup_path: String, pub from_version: u32, pub to_version: u32, pub reopen_required: bool }
#[derive(Debug, serde::Serialize)]
pub(crate) struct MigrationError {
    pub phase: &'static str, pub outcome: &'static str, pub reopen_required: bool,
    pub backup_path: Option<String>, pub backup_outcome: &'static str, pub message: &'static str,
}
fn failure(phase: &'static str, message: &'static str) -> MigrationError {
    MigrationError { phase, outcome: "not_committed", reopen_required: false, backup_path: None, backup_outcome: "not_created", message }
}
struct Confirmation {
    instance: std::sync::Weak<()>, digest: [u8;32], policy: PolicySummary, expires: std::time::Instant,
}
fn confirmations() -> &'static std::sync::Mutex<std::collections::HashMap<String, Confirmation>> {
    static STORE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, Confirmation>>> = std::sync::OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}
fn check_challenge(inventory: &LegacyInventory, code: Option<&str>) -> Result<(), MigrationError> {
    if inventory.totp_secret.is_some() {
        if !inventory.verify_totp(code.ok_or_else(|| failure("authentication", "TOTP code required"))?).map_err(|_| failure("authentication", "authentication failed"))? {
            return Err(failure("authentication", "authentication failed"));
        }
    }
    Ok(())
}
fn active_legacy(state: &crate::state::AppState) -> Result<(std::sync::Arc<()>, sqlx::SqlitePool), MigrationError> {
    let guard = state.active_wallet.lock().map_err(|_| failure("wallet", "wallet state unavailable"))?;
    let active = guard.as_ref().ok_or_else(|| failure("wallet", "no wallet is open"))?;
    if active.secure_wallet.is_some() { return Err(failure("wallet", "wallet is not legacy format")); }
    Ok((active.instance_id.clone(), active.db_pool.clone()))
}
fn inventory_error(_: InventoryError) -> MigrationError { failure("inventory", "legacy wallet inventory or authentication failed") }

#[cfg(target_os = "linux")]
pub(crate) async fn preview_migration(state: &crate::state::AppState, password: &str, totp_code: Option<&str>) -> Result<MigrationPreview, MigrationError> {
    use rand::RngCore;
    let _operation = state.wallet_operation.lock().await;
    let (instance, pool) = active_legacy(state)?;
    let mut tx = pool.begin().await.map_err(|_| failure("inventory", "wallet read failed"))?;
    let inventory = inspect_legacy(&mut tx, password).await.map_err(inventory_error)?;
    check_challenge(&inventory, totp_code)?;
    let digest = crate::commands::extra::verified_backup::migration_snapshot_digest(&mut tx).await.map_err(|_| failure("inventory", "wallet snapshot failed"))?;
    tx.rollback().await.map_err(|_| failure("inventory", "wallet read failed"))?;
    let policy = inventory.policy_summary();
    let mut random = [0u8;32]; rand::rngs::OsRng.try_fill_bytes(&mut random).map_err(|_| failure("preview", "random generation failed"))?;
    let token = hex::encode(random);
    let mut store = confirmations().lock().map_err(|_| failure("preview", "confirmation unavailable"))?;
    store.retain(|_, v| v.expires > std::time::Instant::now() && v.instance.strong_count() != 0);
    store.retain(|_, v| !v.instance.ptr_eq(&std::sync::Arc::downgrade(&instance)));
    if store.len() >= 32 { return Err(failure("preview", "confirmation capacity reached")); }
    store.insert(token.clone(), Confirmation { instance: std::sync::Arc::downgrade(&instance), digest, policy: policy.clone(), expires: std::time::Instant::now()+std::time::Duration::from_secs(300) });
    Ok(MigrationPreview { from_version: 33, to_version: 34, policy, confirmation_token: token, expires_in_seconds: 300 })
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn preview_migration(_: &crate::state::AppState, _: &str, _: Option<&str>) -> Result<MigrationPreview, MigrationError> {
    Err(failure("preview", "secure migration is not supported on this platform"))
}

/// Cleanup survives cancellation of the migration future and releases the wallet lock only after pool close.
struct Retirement { trigger: Option<tokio::sync::oneshot::Sender<()>>, done: Option<tokio::task::JoinHandle<Result<(), ()>>> }
impl Retirement {
    fn new(wallet: crate::state::ActiveWallet) -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let done = tokio::spawn(async move { let _ = rx.await; wallet.db_pool.close().await; wallet.wallet_lock.unlock().map_err(|_| ()) });
        Self { trigger: Some(tx), done: Some(done) }
    }
    async fn finish(&mut self) -> Result<(), ()> {
        if let Some(tx) = self.trigger.take() { let _ = tx.send(()); }
        self.done.take().ok_or(())?.await.map_err(|_| ())?
    }
}
impl Drop for Retirement { fn drop(&mut self) { if let Some(tx) = self.trigger.take() { let _ = tx.send(()); } } }

#[cfg(target_os = "linux")]
pub(crate) async fn migrate_wallet(state: &crate::state::AppState, password: &str, totp_code: Option<&str>, backup_path: &str, confirmation_token: &str) -> Result<MigrationSuccess, MigrationError> {
    use rand::RngCore;
    let operation = state.wallet_operation.lock().await;
    let (instance, pool) = active_legacy(state)?;
    let confirmation = confirmations().lock().map_err(|_| failure("confirmation", "confirmation unavailable"))?.remove(confirmation_token).ok_or_else(|| failure("confirmation", "confirmation expired or invalid"))?;
    if confirmation.expires <= std::time::Instant::now() || !confirmation.instance.ptr_eq(&std::sync::Arc::downgrade(&instance)) { return Err(failure("confirmation", "confirmation expired or invalid")); }
    let mut initial = pool.begin().await.map_err(|_| failure("authentication", "wallet read failed"))?;
    let original = inspect_legacy(&mut initial, password).await.map_err(inventory_error)?;
    check_challenge(&original, totp_code)?;
    let digest = crate::commands::extra::verified_backup::migration_snapshot_digest(&mut initial).await.map_err(|_| failure("confirmation", "wallet snapshot failed"))?;
    if digest != confirmation.digest || original.policy_summary() != confirmation.policy { return Err(failure("confirmation", "wallet changed; preview again")); }
    initial.rollback().await.map_err(|_| failure("authentication", "wallet read failed"))?;
    let mut wallet_id = [0u8;16]; rand::rngs::OsRng.try_fill_bytes(&mut wallet_id).map_err(|_| failure("encryption", "random generation failed"))?;
    let context = crate::security::envelope::WalletContext { wallet_id, xpub: original.xpub.clone(), derivation: original.derivation.clone() };
    let bundle = crate::security::wallet_bundle::WalletBundle { version:1, xprv:(*original.xprv).clone(), mnemonic:(*original.mnemonic).clone(), passphrase:(*original.passphrase).clone(), totp:original.totp_secret.as_ref().map(|s| crate::security::wallet_bundle::TotpPolicy { secret:s.to_vec(), recovery_hashes:original.recovery_hashes.clone() }) };
    let envelope = crate::security::wallet_bundle::seal(password,&context,&bundle).await.map_err(|_| failure("encryption", "wallet encryption failed"))?;
    let record = crate::services::wallet_security::StoredWallet::encode(&context,&envelope).map_err(|_| failure("encryption", "wallet encoding failed"))?;
    let backup = match crate::commands::extra::backup_snapshot_locked(state,&operation,backup_path).await {
        Ok(v) => v,
        Err(_) => { let mut e = failure("backup", "backup creation failed; inspect destination before retry"); e.backup_outcome="unknown"; e.backup_path=Some(backup_path.into()); return Err(e); }
    };
    let published = |mut e: MigrationError| { e.backup_outcome="published"; e.backup_path=Some(backup_path.into()); e };
    let mut final_tx = backup.begin_verified_source(state,&operation).await.map_err(|_| published(failure("comparison", "backup and wallet differ")))?;
    let mut snap_tx = backup.readonly_pool().begin().await.map_err(|_| published(failure("backup", "backup read failed")))?;
    let restored = inspect_legacy(&mut snap_tx,password).await.map_err(|e| published(inventory_error(e)))?;
    check_challenge(&restored,totp_code).map_err(&published)?;
    let final_inventory = inspect_legacy(&mut final_tx,password).await.map_err(|e| published(inventory_error(e)))?;
    check_challenge(&final_inventory,totp_code).map_err(&published)?;
    let digest = crate::commands::extra::verified_backup::migration_snapshot_digest(&mut final_tx).await.map_err(|_| published(failure("comparison", "wallet snapshot failed")))?;
    if digest != confirmation.digest || final_inventory.policy_summary() != confirmation.policy || !original.equivalent_secrets(&restored) || !original.equivalent_secrets(&final_inventory) {
        return Err(published(failure("comparison", "wallet changed; preview again")));
    }
    snap_tx.rollback().await.map_err(|_| published(failure("backup", "backup read failed")))?;
    let old: (Vec<u8>,) = sqlx::query_as("SELECT derivation_data FROM MasterKeys WHERE masterkey_id=?").bind(final_inventory.masterkey_id).fetch_one(&mut *final_tx).await.map_err(|_| published(failure("write", "wallet update failed")))?;
    let now = chrono::Utc::now().timestamp();
    #[cfg(test)]
    let fail_write = state.active_wallet.lock().unwrap().as_ref().is_some_and(|a| a.migration_write_fail);
    #[cfg(test)]
    if fail_write { sqlx::query("PRAGMA query_only=ON").execute(&mut *final_tx).await.map_err(|_| published(failure("write", "wallet update failed")))?; }
    let updated = sqlx::query("UPDATE MasterKeys SET derivation_data=?,date_updated=? WHERE masterkey_id=? AND derivation_data=?").bind(record).bind(now).bind(final_inventory.masterkey_id).bind(old.0).execute(&mut *final_tx).await;
    #[cfg(test)]
    if fail_write { sqlx::query("PRAGMA query_only=OFF").execute(&mut *final_tx).await.map_err(|_| published(failure("write", "wallet update failed")))?; }
    let updated = updated.map_err(|_| published(failure("write", "wallet update failed")))?;
    if updated.rows_affected()!=1 { return Err(published(failure("write", "wallet changed"))); }
    sqlx::query("DELETE FROM TotpSecrets WHERE id=1").execute(&mut *final_tx).await.map_err(|_| published(failure("write", "wallet update failed")))?;
    sqlx::query("DELETE FROM WalletData WHERE key='totp_recovery_codes'").execute(&mut *final_tx).await.map_err(|_| published(failure("write", "wallet update failed")))?;
    // The legacy password token is CBC-derived and must not remain as a weak verifier.
    sqlx::query("DELETE FROM WalletData WHERE key='password-token'").execute(&mut *final_tx).await.map_err(|_| published(failure("write", "wallet update failed")))?;
    sqlx::query("INSERT INTO WalletData(key,value,date_created,date_updated) VALUES('crypto-format','wallet-envelope-v1',?,?)").bind(now).bind(now).execute(&mut *final_tx).await.map_err(|_| published(failure("write", "wallet update failed")))?;
    let changed = sqlx::query("UPDATE WalletData SET value='34',date_updated=? WHERE key='migration' AND value='33'").bind(now).execute(&mut *final_tx).await.map_err(|_| published(failure("write", "wallet update failed")))?;
    if changed.rows_affected()!=1 { return Err(published(failure("write", "wallet changed"))); }
    let mut active = {
        let mut active = state.active_wallet.lock().map_err(|_| published(failure("commit", "wallet state unavailable")))?;
        if !active.as_ref().is_some_and(|a| std::sync::Arc::ptr_eq(&a.instance_id,&instance)) { return Err(published(failure("commit", "wallet changed"))); }
        active.take().ok_or_else(|| published(failure("commit", "wallet changed")))?
    };
    use zeroize::Zeroize;
    if let Some(xprv) = &mut active.decrypted_xprv { xprv.zeroize(); }
    active.decrypted_xprv = None;
    active.legacy_pending_totp = None;
    active.secure_wallet = None;
    #[cfg(test)]
    let mut barrier = active.commit_barrier.take();
    let mut retirement = Retirement::new(active);
    #[cfg(test)]
    if barrier.as_ref().is_some_and(|b| !b.after_commit) {
        let b = barrier.take().unwrap(); let _ = b.started.send(()); let _ = b.resume.await;
    }
    if final_tx.commit().await.is_err() {
        let _ = retirement.finish().await;
        let mut e = published(failure("commit", "commit outcome unknown; reopen wallet")); e.outcome="unknown"; e.reopen_required=true; return Err(e);
    }
    #[cfg(test)]
    if let Some(b) = barrier.take() { let _ = b.started.send(()); let _ = b.resume.await; }
    if retirement.finish().await.is_err() {
        let mut e = published(failure("cleanup", "wallet committed; reopen after lock release")); e.outcome="unknown"; e.reopen_required=true; return Err(e);
    }
    Ok(MigrationSuccess { backup_path:backup_path.into(), from_version:33, to_version:34, reopen_required:true })
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn migrate_wallet(_: &crate::state::AppState, _: &str, _: Option<&str>, _: &str, _: &str) -> Result<MigrationSuccess, MigrationError> {
    Err(failure("preview", "secure migration is not supported on this platform"))
}

#[cfg(all(test, target_os = "linux"))]
mod migration_execution_tests {
    use super::*;
    use crate::{db::repositories, services::wallet_service, state::AppState};
    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    fn state() -> AppState {
        let mut state = AppState::new();
        state.data_dir = std::env::temp_dir().join(format!("wallet-migration-exec-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap())).to_string_lossy().into();
        std::fs::create_dir_all(&state.data_dir).unwrap(); state
    }
    async fn fixture(state: &AppState) -> (sqlx::SqlitePool, crate::security::totp::TotpInstance) {
        wallet_service::create_legacy_fixture(state, "legacy", "pw", WORDS, Some("TREZOR")).await.unwrap();
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        let secret = [9u8;20]; repositories::store_totp_secret(&pool, &secret).await.unwrap();
        repositories::store_recovery_codes(&pool, &[crate::security::totp::hash_recovery_code("ABCD-EFGH")]).await.unwrap();
        repositories::set_wallet_data(&pool, "currency", "USD").await.unwrap();
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(&secret, "ElectrumSV-Mc", "wallet").unwrap();
        (pool, totp)
    }
    #[tokio::test]
    async fn explicit_migration_preserves_secret_recovery_plans_and_verified_backup() {
        let state = state(); let (pool, totp) = fixture(&state).await;
        sqlx::query("INSERT INTO SpendPlans(plan_id,account_id,state,plan_json,fee_rate,expires_at,date_updated) VALUES('synthetic',1,'SIGNED','{}',1,0,0)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO SpendReservations(tx_hash,tx_index,plan_id) VALUES(?,0,'synthetic')").bind(vec![5u8;32]).execute(&pool).await.unwrap();
        assert!(preview_migration(&state,"pw",None).await.is_err());
        let preview = preview_migration(&state,"pw",Some(&totp.generate_current().unwrap())).await.unwrap_or_else(|_| panic!("preview failed"));
        let backup = std::path::Path::new(&state.data_dir).join("backup.sqlite");
        let result = migrate_wallet(&state,"pw",Some(&totp.generate_current().unwrap()),backup.to_str().unwrap(),&preview.confirmation_token).await.unwrap_or_else(|_| panic!("migration failed"));
        assert!(result.reopen_required); assert!(!wallet_service::get_wallet_status(&state).is_open);
        assert!(migrate_wallet(&state,"pw",Some(&totp.generate_current().unwrap()),backup.to_str().unwrap(),&preview.confirmation_token).await.is_err());
        wallet_service::open_wallet(&state,"legacy").await.unwrap();
        assert!(wallet_service::unlock_wallet_authorized(&state,"pw",None).await.is_err());
        wallet_service::unlock_wallet_authorized(&state,"pw",Some(&totp.generate_current().unwrap())).await.unwrap();
        let new_pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        assert_eq!(repositories::get_wallet_data(&new_pool,"migration").await.unwrap().as_deref(),Some("34"));
        assert_eq!(repositories::get_wallet_data(&new_pool,"currency").await.unwrap().as_deref(),Some("USD"));
        assert!(repositories::get_wallet_data(&new_pool,"password-token").await.unwrap().is_none());
        assert!(repositories::get_wallet_data(&new_pool,"totp_recovery_codes").await.unwrap().is_none());
        let remaining: (i64,) = sqlx::query_as("SELECT count(*) FROM SpendReservations WHERE plan_id='synthetic'").fetch_one(&new_pool).await.unwrap(); assert_eq!(remaining.0,1);
        wallet_service::close_wallet(&state).await.unwrap(); wallet_service::open_wallet(&state,"backup").await.unwrap();
        let backup_pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        assert_eq!(repositories::get_wallet_data(&backup_pool,"migration").await.unwrap().as_deref(),Some("33"));
        assert_eq!(repositories::load_recovery_codes(&backup_pool).await.unwrap(),vec![crate::security::totp::hash_recovery_code("ABCD-EFGH")]);
        wallet_service::unlock_wallet_authorized(&state,"pw",Some(&totp.generate_current().unwrap())).await.unwrap();
        wallet_service::close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(state.data_dir).unwrap();
    }
    #[tokio::test]
    async fn stale_preview_and_write_failure_leave_original_and_published_backup() {
        let state = state(); let (pool, totp) = fixture(&state).await;
        let preview = preview_migration(&state,"pw",Some(&totp.generate_current().unwrap())).await.unwrap_or_else(|_| panic!("preview failed"));
        repositories::set_wallet_data(&pool,"currency","EUR").await.unwrap();
        let path = std::path::Path::new(&state.data_dir).join("stale.sqlite");
        let err = migrate_wallet(&state,"pw",Some(&totp.generate_current().unwrap()),path.to_str().unwrap(),&preview.confirmation_token).await.err().unwrap();
        assert_eq!(err.outcome,"not_committed"); assert!(!path.exists());
        assert!(migrate_wallet(&state,"pw",Some(&totp.generate_current().unwrap()),path.to_str().unwrap(),&preview.confirmation_token).await.is_err());
        let preview = preview_migration(&state,"pw",Some(&totp.generate_current().unwrap())).await.unwrap_or_else(|_| panic!("preview failed"));
        state.active_wallet.lock().unwrap().as_mut().unwrap().migration_write_fail = true;
        let before = repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data;
        let backup = std::path::Path::new(&state.data_dir).join("writefail.sqlite");
        let error = migrate_wallet(&state,"pw",Some(&totp.generate_current().unwrap()),backup.to_str().unwrap(),&preview.confirmation_token).await.err().unwrap();
        assert_eq!(error.phase,"write"); assert_eq!(error.outcome,"not_committed"); assert_eq!(error.backup_outcome,"published"); assert!(backup.exists());
        assert_eq!(repositories::get_first_master_key(&pool).await.unwrap().unwrap().derivation_data,before);
        assert_eq!(repositories::get_wallet_data(&pool,"migration").await.unwrap().as_deref(), Some("33"));
        assert_eq!(repositories::get_wallet_data(&pool,"currency").await.unwrap().as_deref(), Some("EUR"));
        assert!(wallet_service::get_wallet_status(&state).is_open);
        wallet_service::close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(state.data_dir).unwrap();
    }
    #[tokio::test]
    async fn cancellation_around_commit_closes_old_pool_before_wallet_lock_release() {
        for after_commit in [false, true] {
            let state = std::sync::Arc::new(state()); let (pool, totp) = fixture(&state).await;
            let preview = preview_migration(&state,"pw",Some(&totp.generate_current().unwrap())).await.unwrap_or_else(|_| panic!("preview failed"));
            let held = pool.acquire().await.unwrap();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel(); let (_resume_tx, resume_rx) = tokio::sync::oneshot::channel();
            state.active_wallet.lock().unwrap().as_mut().unwrap().commit_barrier = Some(crate::state::TestCommitBarrier { after_commit, started: started_tx, resume: resume_rx });
            let backup = std::path::Path::new(&state.data_dir).join("cancel-backup.sqlite").to_string_lossy().to_string();
            let worker = state.clone(); let code = totp.generate_current().unwrap();
            let task = tokio::spawn(async move { migrate_wallet(&worker,"pw",Some(&code),&backup,&preview.confirmation_token).await });
            tokio::time::timeout(std::time::Duration::from_secs(90),started_rx).await.unwrap().unwrap();
            assert!(!wallet_service::get_wallet_status(&state).is_open);
            task.abort(); let _ = task.await;
            assert!(wallet_service::open_wallet(&state,"legacy").await.is_err(), "lock must remain held while old connection is checked out");
            drop(held);
            tokio::time::timeout(std::time::Duration::from_secs(15), async {
                loop {
                    if wallet_service::open_wallet(&state,"legacy").await.is_ok() { break; }
                    tokio::task::yield_now().await;
                }
            }).await.expect("cleanup must release wallet lock");
            assert!(pool.is_closed());
            let current = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
            assert_eq!(repositories::get_wallet_data(&current,"migration").await.unwrap().as_deref(),Some(if after_commit { "34" } else { "33" }));
            wallet_service::unlock_wallet_authorized(&state,"pw",Some(&totp.generate_current().unwrap())).await.unwrap();
            wallet_service::close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(&state.data_dir).unwrap();
        }
    }

    // Spawned only by the parent regression; the production binary has no fault switch.
    #[tokio::test]
    #[ignore = "subprocess crash-test harness"]
    async fn crash_child_harness() {
        use std::io::Write;
        let path = std::env::var("ELECTRUMSV_MIGRATION_CRASH_DIR").expect("test-only child directory");
        let after_commit = std::env::var("ELECTRUMSV_MIGRATION_CRASH_PHASE").unwrap() == "after";
        let mut s = AppState::new(); s.data_dir = path; let state = std::sync::Arc::new(s);
        let (pool, totp) = fixture(&state).await;
        sqlx::query("INSERT INTO SpendPlans(plan_id,account_id,state,plan_json,fee_rate,expires_at,date_updated) VALUES('crash-plan',1,'SIGNED','{}',1,0,0)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO SpendReservations(tx_hash,tx_index,plan_id) VALUES(?,0,'crash-plan')").bind(vec![6u8;32]).execute(&pool).await.unwrap();
        let preview = preview_migration(&state,"pw",Some(&totp.generate_current().unwrap())).await.unwrap_or_else(|_| panic!("preview failed"));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel(); let (_resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        state.active_wallet.lock().unwrap().as_mut().unwrap().commit_barrier = Some(crate::state::TestCommitBarrier { after_commit, started: started_tx, resume: resume_rx });
        let backup = std::path::Path::new(&state.data_dir).join("backup.sqlite").to_string_lossy().to_string();
        let worker = state.clone(); let code = totp.generate_current().unwrap();
        let task = tokio::spawn(async move { migrate_wallet(&worker,"pw",Some(&code),&backup,&preview.confirmation_token).await });
        tokio::time::timeout(std::time::Duration::from_secs(90), started_rx).await.unwrap().unwrap();
        println!("MIGRATION_TEST_READY"); std::io::stdout().flush().unwrap();
        let _ = task.await;
    }

    #[tokio::test]
    async fn killed_process_recovers_at_both_commit_boundaries() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        for after_commit in [false, true] {
            let state = state();
            let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "services::wallet_migration::migration_execution_tests::crash_child_harness", "--nocapture"])
                .env("ELECTRUMSV_MIGRATION_CRASH_DIR", &state.data_dir)
                .env("ELECTRUMSV_MIGRATION_CRASH_PHASE", if after_commit { "after" } else { "before" })
                .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).kill_on_drop(true).spawn().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            tokio::time::timeout(std::time::Duration::from_secs(120), async {
                loop { let mut line = String::new(); assert!(output.read_line(&mut line).await.unwrap() > 0, "child exited before barrier"); if line.contains("MIGRATION_TEST_READY") { break; } }
            }).await.expect("child did not reach commit barrier");
            child.kill().await.unwrap(); let status = child.wait().await.unwrap(); assert!(!status.success());
            wallet_service::open_wallet(&state,"legacy").await.unwrap();
            let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
            assert_eq!(repositories::get_wallet_data(&pool,"migration").await.unwrap().as_deref(),Some(if after_commit { "34" } else { "33" }));
            let count: (i64,) = sqlx::query_as("SELECT count(*) FROM SpendReservations WHERE plan_id='crash-plan'").fetch_one(&pool).await.unwrap(); assert_eq!(count.0,1);
            let totp = crate::security::totp::TotpInstance::from_secret_bytes(&[9u8;20],"ElectrumSV-Mc","wallet").unwrap();
            wallet_service::unlock_wallet_authorized(&state,"pw",Some(&totp.generate_current().unwrap())).await.unwrap();
            crate::commands::wallet::recover_totp_inner(&state,"pw","ABCD-EFGH").await.unwrap();
            assert!(crate::commands::wallet::recover_totp_inner(&state,"pw","ABCD-EFGH").await.is_err());
            wallet_service::close_wallet(&state).await.unwrap(); wallet_service::open_wallet(&state,"backup").await.unwrap();
            let backup = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
            assert_eq!(repositories::get_wallet_data(&backup,"migration").await.unwrap().as_deref(),Some("33"));
            assert_eq!(repositories::load_recovery_codes(&backup).await.unwrap(),vec![crate::security::totp::hash_recovery_code("ABCD-EFGH")]);
            wallet_service::unlock_wallet_authorized(&state,"pw",Some(&totp.generate_current().unwrap())).await.unwrap();
            wallet_service::close_wallet(&state).await.unwrap(); std::fs::remove_dir_all(state.data_dir).unwrap();
        }
    }
}
