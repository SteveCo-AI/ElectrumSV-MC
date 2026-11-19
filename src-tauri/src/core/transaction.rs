// core/transaction.rs — Transaction building, coin selection, and fee estimation
//
// Provides:
// - TxBuilder: constructs unsigned BSV transactions from UTXOs and outputs
// - CoinSelector: selects UTXOs for spending (largest-first strategy)
// - FeeEstimator: estimates transaction fees in satoshis
// - TxPlan: a serializable unsigned transaction plan with metadata
//
// Uses bsv-sdk Transaction, TransactionInput, TransactionOutput, and P2PKH
// script templates for construction. Signing is handled by the Signer trait
// in core/signer.rs.

use crate::core::coinchooser;
use crate::db::repositories::{TransactionOutputRow, UtxoInfo};
use bsv::script::inscriptions::op_return_data;
use bsv::script::templates::p2pkh::P2PKH;
use bsv::script::templates::ScriptTemplateLock;
use bsv::transaction::transaction::Transaction;
use bsv::transaction::transaction_input::TransactionInput;
use bsv::transaction::transaction_output::TransactionOutput;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Check wire lengths before the SDK allocates vectors from untrusted varints.
pub(crate) fn validate_transaction_wire(bytes: &[u8]) -> Result<(), String> {
    fn take(bytes: &[u8], pos: &mut usize, n: usize) -> Result<(), String> {
        *pos = pos.checked_add(n).filter(|end| *end <= bytes.len()).ok_or("truncated transaction")?;
        Ok(())
    }
    fn compact(bytes: &[u8], pos: &mut usize) -> Result<usize, String> {
        let first = *bytes.get(*pos).ok_or("truncated varint")?;
        take(bytes, pos, 1)?;
        let size = match first { 0..=252 => return Ok(first as usize), 253 => 2, 254 => 4, _ => 8 };
        let start = *pos;
        take(bytes, pos, size)?;
        let mut value = 0u64;
        for (i, byte) in bytes[start..*pos].iter().enumerate() { value |= (*byte as u64) << (8 * i); }
        usize::try_from(value).map_err(|_| "varint overflow".into())
    }
    let mut pos = 0;
    take(bytes, &mut pos, 4)?;
    let inputs = compact(bytes, &mut pos)?;
    if inputs > bytes.len() / 41 { return Err("invalid input count".into()); }
    for _ in 0..inputs {
        take(bytes, &mut pos, 36)?;
        let len = compact(bytes, &mut pos)?;
        take(bytes, &mut pos, len)?;
        take(bytes, &mut pos, 4)?;
    }
    let outputs = compact(bytes, &mut pos)?;
    if outputs > bytes.len() / 9 { return Err("invalid output count".into()); }
    for _ in 0..outputs {
        take(bytes, &mut pos, 8)?;
        let len = compact(bytes, &mut pos)?;
        take(bytes, &mut pos, len)?;
    }
    take(bytes, &mut pos, 4)?;
    if pos != bytes.len() { return Err("trailing transaction data".into()); }
    Ok(())
}


/// Transaction building errors.
#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("insufficient funds: needed {needed} sat, available {available} sat")]
    InsufficientFunds { needed: u64, available: u64 },
    #[error("no UTXOs available")]
    NoUtxos,
    #[error("invalid output: {0}")]
    InvalidOutput(String),
    #[error("BSV SDK error: {0}")]
    BsvSdk(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<bsv::transaction::error::TransactionError> for TransactionError {
    fn from(e: bsv::transaction::error::TransactionError) -> Self {
        TransactionError::BsvSdk(e.to_string())
    }
}

impl From<bsv::script::error::ScriptError> for TransactionError {
    fn from(e: bsv::script::error::ScriptError) -> Self {
        TransactionError::BsvSdk(e.to_string())
    }
}

/// A payment output specification (address + amount in satoshis).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentOutput {
    /// BSV P2PKH address (e.g. "1A1zP1eP5...")
    pub address: String,
    /// Amount in satoshis
    pub satoshis: u64,
}

/// A UTXO selected for spending (simplified for TX building).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedUtxo {
    /// Display hex txid (reversed byte order)
    pub tx_hash_hex: String,
    /// Output index
    pub tx_index: u32,
    /// Value in satoshis
    pub satoshis: u64,
    /// KeyInstance ID that owns this UTXO
    pub keyinstance_id: i64,
    /// Derivation subpath for the key that owns this UTXO (e.g. [0, 3])
    pub subpath: [u32; 2],
}

impl SelectedUtxo {
    /// Create from a UtxoInfo (from DB) + subpath.
    pub fn from_utxo_info(info: &UtxoInfo, subpath: [u32; 2]) -> Self {
        SelectedUtxo {
            tx_hash_hex: info.tx_hash_hex.clone(),
            tx_index: info.tx_index as u32,
            satoshis: info.value as u64,
            keyinstance_id: info.keyinstance_id,
            subpath,
        }
    }

    /// Create from a TransactionOutputRow (from DB) + subpath.
    pub fn from_output_row(row: &TransactionOutputRow, subpath: [u32; 2]) -> Self {
        SelectedUtxo {
            tx_hash_hex: crate::core::address::hash_to_hex_str(&row.tx_hash),
            tx_index: row.tx_index as u32,
            satoshis: row.value as u64,
            keyinstance_id: row.keyinstance_id,
            subpath,
        }
    }
}

/// Result of coin selection.
#[derive(Debug, Clone)]
pub struct CoinSelectionResult {
    /// Selected UTXOs to spend
    pub selected: Vec<SelectedUtxo>,
    /// Total input value in satoshis
    pub total_input: u64,
    /// Total output value in satoshis (payments + change)
    pub total_output: u64,
    /// Fee in satoshis
    pub fee: u64,
    /// Change amount in satoshis (0 if no change output)
    pub change: u64,
}

/// Coin selector — largest-first strategy.
///
/// Selects UTXOs starting from the largest until the target amount + fee is covered.
/// This is a simple, deterministic strategy that minimizes the number of inputs.
pub struct CoinSelector;

impl CoinSelector {
    /// Select UTXOs to cover `target_amount + fee`.
    ///
    /// `available_utxos` is sorted descending by value before selection.
    /// Returns `InsufficientFunds` if the UTXOs cannot cover the target.
    pub fn select(
        available_utxos: &[SelectedUtxo],
        target_amount: u64,
        fee: u64,
    ) -> Result<CoinSelectionResult, TransactionError> {
        if available_utxos.is_empty() {
            return Err(TransactionError::NoUtxos);
        }

        let needed = target_amount
            .checked_add(fee)
            .ok_or_else(|| TransactionError::InvalidOutput("overflow in target + fee".into()))?;

        // Sort descending by satoshis (largest first)
        let mut sorted: Vec<&SelectedUtxo> = available_utxos.iter().collect();
        sorted.sort_by(|a, b| b.satoshis.cmp(&a.satoshis));

        let mut selected = Vec::new();
        let mut accumulated = 0u64;

        for utxo in &sorted {
            selected.push((*utxo).clone());
            accumulated = accumulated.checked_add(utxo.satoshis).ok_or_else(|| {
                TransactionError::InvalidOutput("overflow in accumulation".into())
            })?;
            if accumulated >= needed {
                break;
            }
        }

        if accumulated < needed {
            return Err(TransactionError::InsufficientFunds {
                needed,
                available: accumulated,
            });
        }

        let change = accumulated - needed;
        let total_input = accumulated;
        let total_output = target_amount + change;
        let actual_fee = fee;

        Ok(CoinSelectionResult {
            selected,
            total_input,
            total_output,
            fee: actual_fee,
            change,
        })
    }
}

/// Conservative fee estimates based on serialized transaction size.
pub struct FeeEstimator;

fn compact_size_len(n: usize) -> u64 {
    if n < 253 { 1 } else if n <= 0xffff { 3 } else if n <= 0xffff_ffff { 5 } else { 9 }
}

/// Interpret hexadecimal input (optional 0x prefix) or otherwise use UTF-8 bytes.
pub fn decode_op_return(input: &str) -> Vec<u8> {
    let candidate = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")).unwrap_or(input);
    hex::decode(candidate).unwrap_or_else(|_| input.as_bytes().to_vec())
}

impl FeeEstimator {
    /// Local default in satoshis per byte.
    pub const DEFAULT_FEE_RATE: u64 = 1;

    /// Estimate a transaction with P2PKH outputs, without OP_RETURN data.
    /// A maximal compressed P2PKH input is 149 bytes: 32 hash + 4 index + 1 script
    /// length + 108 scriptSig + 4 sequence. The scriptSig is 1 push + up to 72 DER
    /// signature bytes + 1 hash type + 1 push + 33 public-key bytes.
    pub fn estimate_fee(num_inputs: usize, num_outputs: usize, fee_rate: u64) -> u64 {
        Self::estimate_fee_with_data(num_inputs, num_outputs, None, fee_rate)
    }

    /// `p2pkh_outputs` excludes the optional data output; CompactSize lengths are included.
    pub fn estimate_fee_with_data(num_inputs: usize, p2pkh_outputs: usize, data: Option<&[u8]>, fee_rate: u64) -> u64 {
        let output_count = p2pkh_outputs.saturating_add(usize::from(data.is_some()));
        let mut size = 8u64.saturating_add(compact_size_len(num_inputs)).saturating_add(compact_size_len(output_count))
            .saturating_add(149u64.saturating_mul(num_inputs as u64))
            .saturating_add(34u64.saturating_mul(p2pkh_outputs as u64));
        if let Some(data) = data {
            let script_len = op_return_data(data).to_binary().len();
            size = size.saturating_add(8).saturating_add(compact_size_len(script_len)).saturating_add(script_len as u64);
        }
        size.saturating_mul(fee_rate)
    }

    pub fn estimate_fee_default(num_inputs: usize, num_outputs: usize) -> u64 {
        Self::estimate_fee(num_inputs, num_outputs, Self::DEFAULT_FEE_RATE)
    }
}

/// A transaction plan — unsigned TX with metadata for AUD-007 binding.
///
/// The plan is:
/// 1. Created by `prepare_tx` (unsigned)
/// 2. Signed by `sign_tx` (requires TOTP verification)
/// 3. Broadcast by `broadcast_tx` (validates txid via AUD-006)
///
/// The plan is bound to a specific wallet by `wallet_path` to prevent
/// cross-wallet replay attacks (AUD-007).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPlan {
    /// The unsigned transaction in hex format
    pub unsigned_tx_hex: String,
    /// Payment outputs
    pub outputs: Vec<PaymentOutput>,
    /// Selected UTXOs (inputs)
    pub inputs: Vec<SelectedUtxo>,
    /// Fee in satoshis
    pub fee: u64,
    /// Change amount in satoshis
    pub change: u64,
    /// Change address (if change > 0)
    pub change_address: Option<String>,
    /// Total input value in satoshis
    pub total_input: u64,
    /// Total output value in satoshis
    pub total_output: u64,
    /// Wallet path binding (AUD-007: plan can only be signed by this wallet)
    pub wallet_path: String,
    /// Account ID
    pub account_id: i64,
    /// Creation timestamp (Unix epoch)
    pub created_at: i64,
    /// Expiration timestamp (Unix epoch) — plan expires after this time
    pub expires_at: i64,
    /// Whether this plan has been signed
    pub signed: bool,
    /// Signed transaction hex (None until signed)
    pub signed_tx_hex: Option<String>,
    /// Transaction ID (None until signed)
    pub txid: Option<String>,
    /// OP_RETURN data embedded in the transaction (None if no OP_RETURN output)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_return: Option<Vec<u8>>,
}

/// Check that persisted preview metadata describes the unsigned transaction.
pub fn validate_plan_consistency(plan: &TxPlan) -> Result<(), TransactionError> {
    let fail = || TransactionError::InvalidOutput("transaction does not match plan preview".into());
    let raw = hex::decode(&plan.unsigned_tx_hex).map_err(|_| fail())?;
    validate_transaction_wire(&raw).map_err(|_| fail())?;
    let tx = Transaction::from_hex(&plan.unsigned_tx_hex)?;
    if tx.to_hex()? != plan.unsigned_tx_hex || tx.version != 1 || tx.lock_time != 0 || tx.inputs.len() != plan.inputs.len() || tx.inputs.is_empty() {
        return Err(fail());
    }
    let mut seen = std::collections::HashSet::new();
    for (input, prev) in tx.inputs.iter().zip(&plan.inputs) {
        if !input.source_txid.as_deref().is_some_and(|id| id.eq_ignore_ascii_case(&prev.tx_hash_hex)) || input.source_output_index != prev.tx_index || input.sequence != u32::MAX ||
           input.unlocking_script.as_ref().is_some_and(|script| !script.to_binary().is_empty()) ||
           !seen.insert((prev.tx_hash_hex.to_ascii_lowercase(), prev.tx_index)) { return Err(fail()); }
    }
    let inputs = plan.inputs.iter().try_fold(0u64, |sum, input| sum.checked_add(input.satoshis)).ok_or_else(fail)?;
    if inputs != plan.total_input { return Err(fail()); }
    let expected_count = plan.outputs.len() + usize::from(plan.op_return.is_some()) + usize::from(plan.change > 0);
    if tx.outputs.len() != expected_count { return Err(fail()); }
    for (actual, preview) in tx.outputs.iter().zip(&plan.outputs) {
        crate::network::backend::scripthash_from_address(&preview.address).map_err(|_| fail())?;
        let script = P2PKH::from_address(&preview.address)?.lock()?;
        if actual.satoshis != Some(preview.satoshis) || actual.locking_script.to_binary() != script.to_binary() { return Err(fail()); }
    }
    let mut index = plan.outputs.len();
    if let Some(data) = &plan.op_return {
        let actual = &tx.outputs[index];
        if actual.satoshis != Some(0) || actual.locking_script.to_binary() != op_return_data(data).to_binary() { return Err(fail()); }
        index += 1;
    }
    if plan.change > 0 {
        let address = plan.change_address.as_deref().ok_or_else(fail)?;
        crate::network::backend::scripthash_from_address(address).map_err(|_| fail())?;
        let script = P2PKH::from_address(address)?.lock()?;
        if tx.outputs[index].satoshis != Some(plan.change) || tx.outputs[index].locking_script.to_binary() != script.to_binary() { return Err(fail()); }
    }
    let outputs = tx.outputs.iter().try_fold(0u64, |sum, output| sum.checked_add(output.satoshis?)).ok_or_else(fail)?;
    if outputs != plan.total_output || inputs.checked_sub(outputs) != Some(plan.fee) { return Err(fail()); }
    Ok(())
}

/// Convert a `SelectedUtxo` into a `coinchooser::Coin` for use by the
/// advanced coin-selection strategies.
fn utxo_to_coin(utxo: &SelectedUtxo) -> coinchooser::Coin {
    coinchooser::Coin::new(
        utxo.tx_hash_hex.clone(),
        utxo.tx_index,
        utxo.satoshis,
        utxo.keyinstance_id,
    )
}

/// Transaction builder — constructs unsigned transactions.
pub struct TxBuilder;

impl TxBuilder {
    /// Build an unsigned transaction from selected UTXOs and payment outputs.
    ///
    /// `change_address`: P2PKH address for change output (if any change remains).
    /// `strategy`: optional coin-selection strategy. `None` keeps the default
    ///   largest-first `CoinSelector`. `Some(strategy)` delegates selection to
    ///   the `CoinChooser` module (BranchAndBound / RandomSubset / Privacy).
    /// Returns an unsigned Transaction and the CoinSelectionResult.
    pub fn build_unsigned(
        utxos: &[SelectedUtxo],
        outputs: &[PaymentOutput],
        change_address: Option<&str>,
        fee_rate: u64,
        op_return: Option<&[u8]>,
        strategy: Option<coinchooser::Strategy>,
    ) -> Result<(Transaction, CoinSelectionResult), TransactionError> {
        // Calculate total payment amount
        let total_payment = outputs.iter().try_fold(0u64, |sum, output| sum.checked_add(output.satoshis))
            .ok_or_else(|| TransactionError::InvalidOutput("payment amount overflow".into()))?;

        if total_payment == 0 {
            return Err(TransactionError::InvalidOutput(
                "total payment is zero".into(),
            ));
        }

        let estimate = |inputs, reserve_change: bool| {
            let p2pkh_outputs = outputs.len() + usize::from(reserve_change && change_address.is_some());
            FeeEstimator::estimate_fee_with_data(inputs, p2pkh_outputs, op_return, fee_rate)
        };

        let select = |reserve_change: bool| -> Result<CoinSelectionResult, TransactionError> {
        Ok(match strategy {
            None => {
                let mut fee = estimate(1, reserve_change);
                let mut attempts = 0usize;
                loop {
                    attempts += 1;
                    if attempts > 128 { return Err(TransactionError::InvalidOutput("fee calculation did not converge".into())); }
                    let result = CoinSelector::select(utxos, total_payment, fee)?;
                    let actual_fee = estimate(result.selected.len(), reserve_change);
                    if actual_fee == fee { break result; }
                    fee = actual_fee;
                }
            }
            Some(strategy) => {
                let coins: Vec<coinchooser::Coin> = utxos.iter().map(utxo_to_coin).collect();
                let chooser = coinchooser::CoinChooser::new(strategy, fee_rate);
                let mut lookup = std::collections::HashMap::new();
                for u in utxos {
                    if lookup.insert((u.tx_hash_hex.clone(), u.tx_index), u).is_some() {
                        return Err(TransactionError::InvalidOutput("duplicate UTXO".into()));
                    }
                }
                let mut target = total_payment;
                let mut attempts = 0usize;
                loop {
                    attempts += 1;
                    if attempts > 128 { return Err(TransactionError::InvalidOutput("fee calculation did not converge".into())); }
                    let result = chooser.select(&coins, target).map_err(|e| match e {
                        coinchooser::CoinChooserError::InsufficientFunds { needed, available } => TransactionError::InsufficientFunds { needed, available },
                        coinchooser::CoinChooserError::NoCoins => TransactionError::NoUtxos,
                        other => TransactionError::InvalidOutput(other.to_string()),
                    })?;
                    let mut selected = Vec::with_capacity(result.coins.len());
                    for c in &result.coins {
                        let utxo = lookup.get(&(c.tx_hash_hex.clone(), c.tx_index)).ok_or_else(|| TransactionError::InvalidOutput("coin selection returned an unknown UTXO".into()))?;
                        selected.push((*utxo).clone());
                    }
                    let actual_fee = estimate(selected.len(), reserve_change);
                    let needed = total_payment.checked_add(actual_fee).ok_or_else(|| TransactionError::InvalidOutput("fee overflow".into()))?;
                    if result.total_input >= needed {
                        let change = result.total_input - needed;
                        break CoinSelectionResult { selected, total_input: result.total_input, total_output: total_payment + change, fee: actual_fee, change };
                    }
                    target = target.checked_add(needed - result.total_input).ok_or_else(|| TransactionError::InvalidOutput("fee overflow".into()))?;
                }
            }
        })
        };
        let selection = match select(change_address.is_some()) {
            Ok(selection) => selection,
            Err(original @ TransactionError::InsufficientFunds { .. }) if change_address.is_some() => {
                let mut without_change = match select(false) { Ok(result) => result, Err(_) => return Err(original) };
                let change_cost = estimate(without_change.selected.len(), true).saturating_sub(estimate(without_change.selected.len(), false));
                if without_change.change >= change_cost { return Err(original); }
                without_change.fee = without_change.fee.checked_add(without_change.change).ok_or_else(|| TransactionError::InvalidOutput("fee overflow".into()))?;
                without_change.change = 0;
                without_change.total_output = total_payment;
                without_change
            }
            Err(error) => return Err(error),
        };

        if selection.change > 0 && change_address.is_none() {
            return Err(TransactionError::InvalidOutput("change address required".into()));
        }
        for output in outputs {
            crate::network::backend::scripthash_from_address(&output.address)
                .map_err(|e| TransactionError::InvalidOutput(e.to_string()))?;
        }
        if let Some(addr) = change_address {
            crate::network::backend::scripthash_from_address(addr)
                .map_err(|e| TransactionError::InvalidOutput(e.to_string()))?;
        }
        // Build the transaction
        let mut tx = Transaction::new();

        // Add inputs (unsigned — no unlocking script)
        for utxo in &selection.selected {
            let input = TransactionInput {
                source_txid: Some(utxo.tx_hash_hex.clone()),
                source_output_index: utxo.tx_index,
                sequence: 0xFFFFFFFF,
                ..Default::default()
            };
            tx.add_input(input);
        }

        // Add payment outputs
        for output in outputs {
            let p2pkh = P2PKH::from_address(&output.address)?;
            let lock_script = p2pkh.lock()?;
            tx.add_output(TransactionOutput {
                satoshis: Some(output.satoshis),
                locking_script: lock_script,
                change: false,
            });
        }

        // Add OP_RETURN output if provided (0 satoshis, unspendable)
        if let Some(data) = op_return {
            let op_return_script = op_return_data(data);
            tx.add_output(TransactionOutput {
                satoshis: Some(0),
                locking_script: op_return_script,
                change: false,
            });
        }

        // Add change output if change > 0 and change address provided
        if selection.change > 0 {
            if let Some(addr) = change_address {
                let p2pkh = P2PKH::from_address(addr)?;
                let lock_script = p2pkh.lock()?;
                tx.add_output(TransactionOutput {
                    satoshis: Some(selection.change),
                    locking_script: lock_script,
                    change: true,
                });
            }
        }

        Ok((tx, selection))
    }

    /// Create a TxPlan from the built transaction.
    pub fn create_plan(
        tx: Transaction,
        outputs: Vec<PaymentOutput>,
        selection: CoinSelectionResult,
        change_address: Option<String>,
        wallet_path: String,
        account_id: i64,
        ttl_seconds: i64,
        op_return: Option<Vec<u8>>,
    ) -> Result<TxPlan, TransactionError> {
        let now = chrono::Utc::now().timestamp();
        let unsigned_tx_hex = tx.to_hex()?;

        Ok(TxPlan {
            unsigned_tx_hex,
            outputs,
            inputs: selection.selected.clone(),
            fee: selection.fee,
            change: selection.change,
            change_address,
            total_input: selection.total_input,
            total_output: selection.total_output,
            wallet_path,
            account_id,
            created_at: now,
            expires_at: now + ttl_seconds,
            signed: false,
            signed_tx_hex: None,
            txid: None,
            op_return,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known address for private key = 1: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    const TEST_ADDRESS_A: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    // Known address for private key = ff: 1CCCCZ8Z4m5jvFp2F2Kp6wQ4q2N6vL8mZ (example)
    const TEST_ADDRESS_B: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // genesis address

    fn make_utxos() -> Vec<SelectedUtxo> {
        vec![
            SelectedUtxo {
                tx_hash_hex: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                    .to_string(),
                tx_index: 0,
                satoshis: 100_000,
                keyinstance_id: 1,
                subpath: [0, 0],
            },
            SelectedUtxo {
                tx_hash_hex: "b477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58459"
                    .to_string(),
                tx_index: 1,
                satoshis: 50_000,
                keyinstance_id: 2,
                subpath: [0, 1],
            },
            SelectedUtxo {
                tx_hash_hex: "c477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe5845a"
                    .to_string(),
                tx_index: 0,
                satoshis: 25_000,
                keyinstance_id: 3,
                subpath: [1, 0],
            },
        ]
    }

    // --- CoinSelector tests ---

    #[test]
    fn test_coin_selector_largest_first() {
        let utxos = make_utxos();
        let result = CoinSelector::select(&utxos, 80_000, 500).unwrap();

        // Should select the 100k UTXO first (largest)
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected[0].satoshis, 100_000);
        assert_eq!(result.total_input, 100_000);
    }

    #[test]
    fn test_coin_selector_needs_multiple() {
        let utxos = make_utxos();
        // Need 140k + 500 fee = 140500 — the 100k alone is not enough
        let result = CoinSelector::select(&utxos, 140_000, 500).unwrap();

        assert_eq!(result.selected.len(), 2);
        assert_eq!(result.selected[0].satoshis, 100_000);
        assert_eq!(result.selected[1].satoshis, 50_000);
        assert_eq!(result.total_input, 150_000);
        assert_eq!(result.change, 150_000 - 140_500);
    }

    #[test]
    fn test_coin_selector_insufficient() {
        let utxos = make_utxos();
        // Total available = 175000, need 200000
        let result = CoinSelector::select(&utxos, 200_000, 500);
        assert!(result.is_err());
        match result.unwrap_err() {
            TransactionError::InsufficientFunds { needed, available } => {
                assert_eq!(needed, 200_500);
                assert_eq!(available, 175_000);
            }
            _ => panic!("expected InsufficientFunds"),
        }
    }

    #[test]
    fn test_coin_selector_empty_utxos() {
        let result = CoinSelector::select(&[], 1000, 100);
        assert!(matches!(result.unwrap_err(), TransactionError::NoUtxos));
    }

    #[test]
    fn test_coin_selector_exact_amount() {
        let utxos = make_utxos();
        // 100k UTXO, need 99500 + 500 fee = 100000 exactly
        let result = CoinSelector::select(&utxos, 99_500, 500).unwrap();
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.change, 0);
    }

    // --- FeeEstimator tests ---

    #[test]
    fn test_fee_estimator_1_in_2_out() {
        let fee = FeeEstimator::estimate_fee(1, 2, 1);
        // 10 + 149 + 68 = 227
        assert_eq!(fee, 227);
    }

    #[test]
    fn test_fee_estimator_3_in_2_out() {
        let fee = FeeEstimator::estimate_fee(3, 2, 1);
        // 10 + 149*3 + 68 = 525
        assert_eq!(fee, 525);
    }

    #[test]
    fn test_fee_estimator_custom_rate() {
        let fee = FeeEstimator::estimate_fee(1, 1, 2);
        // (10 + 149 + 34) * 2 = 386
        assert_eq!(fee, 386);
    }

    #[test]
    fn fee_estimator_accounts_for_compact_size_boundaries() {
        assert_eq!(FeeEstimator::estimate_fee(253, 1, 1) - FeeEstimator::estimate_fee(252, 1, 1), 151);
        assert_eq!(FeeEstimator::estimate_fee(1, 253, 1) - FeeEstimator::estimate_fee(1, 252, 1), 36);
    }

    #[test]
    fn op_return_compact_size_fee_covers_full_serialization() {
        let utxos = vec![SelectedUtxo { tx_hash_hex: "01".repeat(32), tx_index: 0, satoshis: 100_000, keyinstance_id: 1, subpath: [0,0] }];
        let outputs = vec![PaymentOutput { address: TEST_ADDRESS_B.into(), satoshis: 10_000 }];
        for len in [251, 252, 253, 65535, 65536] {
            let data = vec![7u8; len];
            let (tx, selection) = TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, Some(&data), None).unwrap();
            let unsigned_size = tx.to_hex().unwrap().len() / 2;
            assert!(selection.fee >= (unsigned_size + 108) as u64);
        }
    }

    #[test]
    fn tightly_funded_payment_can_omit_unaffordable_change() {
        let utxos = vec![SelectedUtxo { tx_hash_hex: "01".repeat(32), tx_index: 0, satoshis: 1000, keyinstance_id: 1, subpath: [0,0] }];
        let outputs = vec![PaymentOutput { address: TEST_ADDRESS_B.into(), satoshis: 790 }];
        for strategy in [None, Some(coinchooser::Strategy::BranchAndBound), Some(coinchooser::Strategy::RandomSubset), Some(coinchooser::Strategy::Privacy)] {
            let (_, selection) = TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, strategy).unwrap();
            assert_eq!(selection.change, 0);
            assert_eq!(selection.fee, 210);
        }
    }

    #[test]
    fn all_strategies_select_enough_for_outputs_and_data() {
        let utxos = vec![
            SelectedUtxo { tx_hash_hex: "01".repeat(32), tx_index: 0, satoshis: 1000, keyinstance_id: 1, subpath: [0,0] },
            SelectedUtxo { tx_hash_hex: "02".repeat(32), tx_index: 0, satoshis: 1000, keyinstance_id: 2, subpath: [0,1] },
        ];
        let outputs = vec![PaymentOutput { address: TEST_ADDRESS_B.into(), satoshis: 800 }];
        for strategy in [None, Some(coinchooser::Strategy::BranchAndBound), Some(coinchooser::Strategy::RandomSubset), Some(coinchooser::Strategy::Privacy)] {
            let (tx, selection) = TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, Some(b"test data"), strategy).unwrap();
            assert_eq!(selection.selected.len(), 2);
            let unsigned = tx.to_hex().unwrap().len() / 2;
            // Maximum P2PKH unlocking script is 108 bytes, absent from the unsigned inputs.
            assert!(selection.fee >= (unsigned + 108 * selection.selected.len()) as u64);
        }
    }

    // --- TxBuilder tests ---

    #[test]
    fn plan_consistency_rejects_recipient_and_preview_changes() {
        let outputs = vec![PaymentOutput { address: TEST_ADDRESS_B.into(), satoshis: 50_000 }];
        let (tx, selection) = TxBuilder::build_unsigned(&make_utxos(), &outputs, Some(TEST_ADDRESS_A), 1, Some(b"message"), None).unwrap();
        let plan = TxBuilder::create_plan(tx, outputs, selection, Some(TEST_ADDRESS_A.into()), "wallet".into(), 1, 300, Some(b"message".to_vec())).unwrap();
        validate_plan_consistency(&plan).unwrap();
        let mut changed = plan.clone();
        let mut tx = Transaction::from_hex(&changed.unsigned_tx_hex).unwrap();
        tx.outputs[0].locking_script = P2PKH::from_address(TEST_ADDRESS_A).unwrap().lock().unwrap();
        changed.unsigned_tx_hex = tx.to_hex().unwrap();
        assert!(validate_plan_consistency(&changed).is_err());
        let mut changed = plan.clone(); changed.fee += 1;
        assert!(validate_plan_consistency(&changed).is_err());
        let mut changed = plan.clone(); changed.change += 1;
        assert!(validate_plan_consistency(&changed).is_err());
        let mut changed = plan.clone(); changed.total_input += 1;
        assert!(validate_plan_consistency(&changed).is_err());
        let mut changed = plan.clone(); changed.op_return = Some(b"different".to_vec());
        assert!(validate_plan_consistency(&changed).is_err());
    }

    #[test]
    fn test_build_unsigned_single_input() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let (tx, selection) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None).unwrap();

        // Should select 1 input (100k covers 50k + fee + change)
        assert_eq!(selection.selected.len(), 1);
        assert_eq!(tx.inputs.len(), 1);
        // 2 outputs: payment + change
        assert_eq!(tx.outputs.len(), 2);
        // First output is the payment
        assert_eq!(tx.outputs[0].satoshis, Some(50_000));
        assert!(!tx.outputs[0].change);
        // Second output is change
        assert!(tx.outputs[1].change);
    }

    #[test]
    fn test_build_unsigned_no_change() {
        let utxos = make_utxos();
        // Send exact amount that leaves no change after fee
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 99_773, // 100000 - 227 fee (1 input, 2 outputs)
        }];

        let (tx, selection) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None).unwrap();

        assert_eq!(selection.change, 0);
        // Only 1 output (payment), no change
        assert_eq!(tx.outputs.len(), 1);
    }

    #[test]
    fn test_build_unsigned_no_change_address() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let result = TxBuilder::build_unsigned(&utxos, &outputs, None, 1, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_unsigned_multiple_outputs() {
        let utxos = make_utxos();
        let outputs = vec![
            PaymentOutput {
                address: TEST_ADDRESS_B.to_string(),
                satoshis: 30_000,
            },
            PaymentOutput {
                address: TEST_ADDRESS_A.to_string(),
                satoshis: 40_000,
            },
        ];

        let (tx, selection) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None).unwrap();

        // 3 outputs: 2 payments + change
        assert_eq!(tx.outputs.len(), 3);
        assert_eq!(tx.outputs[0].satoshis, Some(30_000));
        assert_eq!(tx.outputs[1].satoshis, Some(40_000));
        assert!(tx.outputs[2].change);
    }

    #[test]
    fn test_build_unsigned_zero_payment() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 0,
        }];

        let result = TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_unsigned_serializes_to_hex() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let (tx, _) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None).unwrap();

        let hex = tx.to_hex().unwrap();
        assert!(!hex.is_empty());
        assert!(hex.len() % 2 == 0); // valid hex
    }

    // --- TxPlan tests ---

    #[test]
    fn test_create_plan_fields() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let (tx, selection) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None).unwrap();

        let plan = TxBuilder::create_plan(
            tx,
            outputs.clone(),
            selection,
            Some(TEST_ADDRESS_A.to_string()),
            "/path/to/wallet.sqlite".to_string(),
            1,
            300, // 5 minute TTL
            None,
        )
        .unwrap();

        assert!(!plan.unsigned_tx_hex.is_empty());
        assert_eq!(plan.outputs.len(), 1);
        assert_eq!(plan.inputs.len(), 1);
        assert_eq!(plan.wallet_path, "/path/to/wallet.sqlite");
        assert_eq!(plan.account_id, 1);
        assert!(!plan.signed);
        assert!(plan.signed_tx_hex.is_none());
        assert!(plan.txid.is_none());
        assert!(plan.expires_at > plan.created_at);
        assert_eq!(plan.expires_at - plan.created_at, 300);
    }

    #[test]
    fn test_plan_serialization_roundtrip() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let (tx, selection) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None).unwrap();

        let plan = TxBuilder::create_plan(
            tx,
            outputs,
            selection,
            Some(TEST_ADDRESS_A.to_string()),
            "/wallet.sqlite".to_string(),
            1,
            300,
            None,
        )
        .unwrap();

        let json = serde_json::to_string(&plan).unwrap();
        let restored: TxPlan = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.wallet_path, plan.wallet_path);
        assert_eq!(restored.fee, plan.fee);
        assert_eq!(restored.inputs.len(), plan.inputs.len());
        assert_eq!(restored.unsigned_tx_hex, plan.unsigned_tx_hex);
    }

    // --- CoinChooser strategy tests ---

    /// TxBuilder with strategy=None must produce the same largest-first selection
    /// as before (backward compatible). Existing tests already cover this; here we
    /// explicitly verify the strategy parameter wiring.
    #[test]
    fn test_build_unsigned_strategy_none_uses_largest_first() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let (tx, selection) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None)
                .unwrap();

        // Largest-first picks the 100k UTXO first → exactly 1 input.
        assert_eq!(selection.selected.len(), 1);
        assert_eq!(selection.selected[0].satoshis, 100_000);
        assert_eq!(tx.inputs.len(), 1);
    }

    /// TxBuilder with Strategy::Privacy must build a valid transaction that
    /// covers the payment + fee from the available UTXOs.
    #[test]
    fn test_build_unsigned_strategy_privacy() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let (tx, selection) = TxBuilder::build_unsigned(
            &utxos,
            &outputs,
            Some(TEST_ADDRESS_A),
            1,
            None,
            Some(crate::core::coinchooser::Strategy::Privacy),
        )
        .unwrap();

        // Selection must cover payment + fee.
        let expected_fee =
            FeeEstimator::estimate_fee(selection.selected.len(), 2, 1);
        assert!(
            selection.total_input >= 50_000 + expected_fee,
            "total_input {} must cover payment + fee {}",
            selection.total_input,
            50_000 + expected_fee
        );
        assert_eq!(tx.inputs.len(), selection.selected.len());
        // At least 1 payment output + 1 change output.
        assert!(tx.outputs.len() >= 1);
        // Fee must match the FeeEstimator formula.
        assert_eq!(selection.fee, expected_fee);
        // Change = total_input - payment - fee.
        assert_eq!(
            selection.change,
            selection.total_input - 50_000 - expected_fee
        );
    }
}
