// commands/restore.rs — Legacy ElectrumSV seed migration Tauri commands
//
// Provides:
// - restore_legacy_wallet: decode legacy seed, validate, create new BIP32 wallet
// - sweep_legacy_to_new: scan legacy addresses for UTXOs, build & broadcast sweep tx
//
// Reference: SPECIFICATION-LEGACY-MIGRATION.md

use crate::core::legacy_keystore;
use crate::core::transaction::{PaymentOutput, SelectedUtxo, TxBuilder};
use crate::network::backend::NetworkBackend;
use crate::services::wallet_service;
use crate::state::AppState;
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use bsv::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
use bsv::script::templates::p2pkh::P2PKH;
use bsv::script::templates::ScriptTemplateLock;
use sha2::{Digest, Sha256};
use tauri::State;

/// Standard Electrum gap limit for address scanning.
const GAP_LIMIT: u32 = 20;

/// Safety cap to prevent infinite scanning loops.
const MAX_SCAN_ADDRESSES: u32 = 10_000;

/// Result of restoring a legacy wallet.
#[derive(Debug, serde::Serialize)]
pub struct LegacyRestoreResult {
    pub new_mnemonic: String,
    pub wallet_path: String,
    pub old_addresses_scanned: u32,
    pub migration_status: String,
}

/// Result of sweeping legacy UTXOs to the new wallet.
#[derive(Debug, serde::Serialize)]
pub struct SweepResult {
    pub addresses_scanned: u32,
    pub utxos_found: u32,
    pub total_sats: u64,
    pub txid: Option<String>,
    pub new_addresses: Vec<String>,
    pub sweep_amount: Option<u64>,
    pub message: String,
}

/// Legacy migration remains disabled until imported keys are spendable.
#[tauri::command]
pub async fn restore_legacy_wallet(state: State<'_, AppState>, seed_words: String, password: String, wallet_name: String) -> Result<LegacyRestoreResult, String> {
    let _ = (state, seed_words, password, wallet_name);
    Err("Legacy migration is not yet safe. Keep the original seed and use a compatible wallet for recovery.".into())
}

/// Scan legacy addresses for UTXOs and sweep them to the new wallet.
#[tauri::command]
pub async fn sweep_legacy_to_new(
    state: State<'_, AppState>, seed_words: String, new_wallet_path: String, password: String,
) -> Result<SweepResult, String> {
    let _ = (state, seed_words, new_wallet_path, password);
    Err("Legacy sweep is disabled until safe signing and broadcast are verified. Keep your original seed.".into())
}

/// Get a receive address from the currently open (unlocked) wallet.
async fn get_new_wallet_receive_address(state: &AppState) -> Result<String, String> {
    let (xprv_str, _account_id) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        let xprv = active
            .decrypted_xprv
            .as_ref()
            .ok_or("wallet is locked — cannot derive address")?;
        (xprv.clone(), active.account_id)
    };

    let account_key = bsv::compat::bip32::ExtendedKey::from_string(&xprv_str)
        .map_err(|e| format!("failed to parse xprv: {}", e))?;
    let child = account_key
        .derive("0/0")
        .map_err(|e| format!("failed to derive 0/0: {}", e))?;
    let pubkey = child
        .public_key()
        .map_err(|e| format!("failed to get public key: {}", e))?;
    let address = crate::core::address::pubkey_to_p2pkh_address(&pubkey);
    Ok(address)
}