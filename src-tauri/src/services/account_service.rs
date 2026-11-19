use crate::commands::account::{
    get_active_wallet_data, AccountError, BalanceInfo, ReceiveAddressResult,
};
use crate::core::address;
use crate::db::repositories;
use crate::state::AppState;
use bsv::compat::bip32::ExtendedKey;

pub async fn get_balance(state: &AppState, account_id: Option<i64>) -> Result<BalanceInfo, String> {
    log::info!("get_balance — account_id: {:?}", account_id);
    let _operation = state.wallet_operation.lock().await;

    let (pool, default_account_id, _) =
        get_active_wallet_data(&state).map_err(|e| e.to_string())?;
    let acct_id = account_id.unwrap_or(default_account_id);
    crate::services::transaction_service::expire_prepared(&pool, chrono::Utc::now().timestamp()).await?;

    let (confirmed, unconfirmed, total) = repositories::get_balance_for_account(&pool, acct_id)
        .await
        .map_err(|e| e.to_string())?;

    let (reserved, available): (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(CASE WHEN r.plan_id IS NOT NULL THEN o.value ELSE 0 END),0), COALESCE(SUM(CASE WHEN r.plan_id IS NULL AND (o.flags & ?) = 0 AND k.derivation_type = ? AND o.script_pubkey IS NOT NULL AND o.script_pubkey <> '' AND t.tx_data IS NOT NULL THEN o.value ELSE 0 END),0) FROM TransactionOutputs o JOIN KeyInstances k ON k.keyinstance_id=o.keyinstance_id JOIN Transactions t ON t.tx_hash=o.tx_hash LEFT JOIN SpendReservations r ON r.tx_hash=o.tx_hash AND r.tx_index=o.tx_index WHERE k.account_id=? AND (o.flags & ?) = 0")
        .bind(repositories::txo_flags::IS_COINBASE).bind(repositories::derivation_type::BIP32).bind(acct_id).bind(repositories::txo_flags::IS_SPENT)
        .fetch_one(&pool).await.map_err(|e| e.to_string())?;
    Ok(BalanceInfo { confirmed, unconfirmed, total, reserved, available })
}

pub async fn get_receive_address(
    state: &AppState,
    account_id: Option<i64>,
) -> Result<ReceiveAddressResult, String> {
    let _operation = state.wallet_operation.lock().await;
    log::info!("get_receive_address — account_id: {:?}", account_id);

    let (pool, default_account_id, xprv_opt) =
        get_active_wallet_data(&state).map_err(|e| e.to_string())?;

    let xprv_str = xprv_opt.ok_or(AccountError::WalletLocked.to_string())?;
    let acct_id = account_id.unwrap_or(default_account_id);
    if acct_id != default_account_id {
        return Err("only the active account supports address derivation".into());
    }

    // Parse the xprv
    let account_key = ExtendedKey::from_string(&xprv_str)
        .map_err(|e| AccountError::InvalidXprv(e.to_string()).to_string())?;

    // Get the next receiving index
    let next_index = repositories::next_keyinstance_index(&pool, acct_id, 0)
        .await
        .map_err(|e| e.to_string())?;

    // Derive the receiving key at 0/next_index
    let derivation_path = format!("0/{}", next_index);
    let child_key = account_key
        .derive(&derivation_path)
        .map_err(|e| AccountError::DerivationFailed(e.to_string()).to_string())?;

    // Get the public key
    let pubkey = child_key
        .public_key()
        .map_err(|e| AccountError::DerivationFailed(e.to_string()).to_string())?;

    // Generate the P2PKH address
    let address_str = address::pubkey_to_p2pkh_address(&pubkey);

    // Store the KeyInstance in the database
    let derivation_data = serde_json::json!({
        "subpath": [0, next_index]
    })
    .to_string()
    .into_bytes();

    // Get the masterkey_id from the first master key
    let mk_row = repositories::get_first_master_key(&pool)
        .await
        .map_err(|e| e.to_string())?;
    let masterkey_id = mk_row.map(|mk| mk.masterkey_id);

    let keyinstance_id = repositories::insert_keyinstance(
        &pool,
        acct_id,
        masterkey_id,
        repositories::derivation_type::BIP32,
        &derivation_data,
        repositories::script_type::P2PKH,
        0, // flags = 0 (no special flags)
        None,
    )
    .await
    .map_err(|e| e.to_string())?;

    log::info!(
        "Generated receive address {} at 0/{} (keyinstance {})",
        address_str,
        next_index,
        keyinstance_id
    );

    Ok(ReceiveAddressResult {
        address: address_str,
        keyinstance_id,
        derivation_index: next_index,
    })
}
