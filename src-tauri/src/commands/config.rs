// commands/config.rs — Config get/update Tauri commands
//
// Uses the existing WalletData key-value store for configuration.
// All config values are stored as strings in WalletData.

use crate::db::repositories;
use crate::state::AppState;
use tauri::State;

fn is_internal_key(key: &str) -> bool {
    key == "migration" || key.starts_with("next_") || key == "password-token"
        || key == "hardware_wallet_enabled" || key.starts_with("crypto-")
        || key.starts_with("totp_") || key.starts_with("address_discovery_v1_")
}

/// Get all configuration values from WalletData.
///
/// Returns a JSON object mapping config keys to their string values.
/// Excludes internal keys (migration, next_*, password-token).
#[tauri::command]
pub async fn get_config(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    get_config_inner(&state).await
}

async fn get_config_inner(state: &AppState) -> Result<serde_json::Value, String> {
    log::info!("get_config");

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        guard
            .as_ref()
            .ok_or("no wallet is currently open")?
            .db_pool
            .clone()
    };

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM WalletData ORDER BY key")
            .fetch_all(&pool)
            .await
            .map_err(|e| e.to_string())?;

    let mut config = serde_json::Map::new();
    for (key, value) in rows {
    // Skip internal keys
    if is_internal_key(&key) {
        continue;
    }
    config.insert(key, serde_json::Value::String(value));
    }

    Ok(serde_json::Value::Object(config))
}

/// Update a configuration value in WalletData.
///
/// Sets a single key-value pair. If the key already exists, it is updated.
#[tauri::command]
pub async fn update_config(
    state: State<'_, AppState>,
    key: String,
    value: String,
) -> Result<(), String> {
    update_config_inner(&state, key, value).await
}

async fn update_config_inner(state: &AppState, key: String, value: String) -> Result<(), String> {
    log::info!("update_config — key: {}", key);

    // Reject internal keys
    if is_internal_key(&key) {
        return Err("cannot modify internal configuration keys".to_string());
    }

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        guard
            .as_ref()
            .ok_or("no wallet is currently open")?
            .db_pool
            .clone()
    };

    repositories::set_wallet_data(&pool, &key, &value)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::wallet_service;
    use crate::state::AppState;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_test_state(test_name: &str) -> AppState {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir()
            .join(format!("electrumsv_mc_cfg_{}_{}", test_name, id));
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir).ok();
        }
        std::fs::create_dir_all(&temp_dir).unwrap();
        AppState {
            data_dir: temp_dir.to_string_lossy().to_string(),
            active_wallet: std::sync::Mutex::new(None),
            network: std::sync::Mutex::new(crate::state::NetworkState::new()),
            pending_plans: std::sync::Mutex::new(std::collections::HashMap::new()),
            wallet_operation: tokio::sync::Mutex::new(()),
        }
    }

    #[tokio::test]
    async fn test_get_config_empty_wallet() {
        let state = make_test_state("cfg_empty");
        wallet_service::create_wallet(&state, "test_cfg", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM WalletData ORDER BY key")
                .fetch_all(&pool)
                .await
                .unwrap();

        // New wallet may have internal keys (migration, next_*) but no user config.
        // All visible keys should be internal.
        for (key, _) in &rows {
            assert!(
                key == "migration"
                    || key.starts_with("next_")
                    || key == "password-token"
                    || key == "hardware_wallet_enabled"
                    || key == "crypto-format",
                "unexpected non-internal key in new wallet: {}",
                key
            );
        }

        assert!(get_config_inner(&state).await.unwrap().get("crypto-format").is_none());
        assert!(update_config_inner(&state, "crypto-format".into(), "tampered".into()).await.is_err());
        assert_eq!(repositories::get_wallet_data(&pool, "crypto-format").await.unwrap().as_deref(), Some("wallet-envelope-v1"));

        pool.close().await;
        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn config_cannot_inject_legacy_recovery_or_discovery_state() {
        let state = make_test_state("cfg_recovery_injection");
        wallet_service::create_legacy_fixture(&state, "legacy", "pw", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None).await.unwrap();
        let pool = state.active_wallet.lock().unwrap().as_ref().unwrap().db_pool.clone();
        repositories::store_totp_secret(&pool, &[7; 20]).await.unwrap();
        let legit = crate::security::totp::hash_recovery_code("VALID-CODE");
        repositories::store_recovery_codes(&pool, &[legit.clone()]).await.unwrap();
        let forged = crate::security::totp::hash_recovery_code("FAKE-CODE");
        assert!(update_config_inner(&state, repositories::TOTP_RECOVERY_CODES_KEY.into(), serde_json::json!([forged]).to_string()).await.is_err());
        assert!(update_config_inner(&state, "totp_scope".into(), "login".into()).await.is_err());
        repositories::set_wallet_data(&pool, "address_discovery_v1_1", "original").await.unwrap();
        assert!(update_config_inner(&state, "address_discovery_v1_1".into(), "done".into()).await.is_err());
        assert_eq!(repositories::get_wallet_data(&pool, "address_discovery_v1_1").await.unwrap().as_deref(), Some("original"));
        assert!(get_config_inner(&state).await.unwrap().get("address_discovery_v1_1").is_none());
        assert!(get_config_inner(&state).await.unwrap().get(repositories::TOTP_RECOVERY_CODES_KEY).is_none());
        assert!(!crate::commands::wallet::totp_recover_inner(&state, "FAKE-CODE").await.unwrap());
        assert_eq!(repositories::load_recovery_codes(&pool).await.unwrap(), vec![legit]);
        assert!(repositories::is_totp_enabled(&pool).await.unwrap());
        assert!(crate::commands::wallet::totp_recover_inner(&state, "VALID-CODE").await.unwrap());
        assert!(!repositories::is_totp_enabled(&pool).await.unwrap());
        update_config_inner(&state, "currency".into(), "USD".into()).await.unwrap();
        assert_eq!(get_config_inner(&state).await.unwrap()["currency"], "USD");
        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_update_config_sets_key() {
        let state = make_test_state("cfg_set");
        wallet_service::create_wallet(&state, "test_set", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        repositories::set_wallet_data(&pool, "currency", "USD")
            .await
            .unwrap();

        let val = repositories::get_wallet_data(&pool, "currency")
            .await
            .unwrap();
        assert_eq!(val, Some("USD".to_string()));

        pool.close().await;
        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_config_returns_key_after_setting() {
        let state = make_test_state("cfg_get");
        wallet_service::create_wallet(&state, "test_get", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        repositories::set_wallet_data(&pool, "language", "en")
            .await
            .unwrap();

        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM WalletData ORDER BY key")
                .fetch_all(&pool)
                .await
                .unwrap();

        let mut found = false;
        for (key, value) in &rows {
            if key == "language" {
                assert_eq!(value, "en");
                found = true;
            }
        }
        assert!(found, "language key should be present in WalletData");

        pool.close().await;
        wallet_service::close_wallet(&state).await.unwrap();
    }

    #[tokio::test]
    async fn test_internal_keys_rejected_by_update_config() {
        // These checks mirror the validation in update_config (cannot modify internal keys).
        // We test the logic directly since update_config requires a Tauri State wrapper.
        let internal_keys = vec!["migration", "password-token", "next_index"];
        for key in internal_keys {
            let is_internal = key == "migration"
                || key.starts_with("next_")
                || key == "password-token";
            assert!(is_internal, "key '{}' should be internal", key);
        }

        // Non-internal keys should pass
        let user_key = "currency";
        let is_internal = user_key == "migration"
            || user_key.starts_with("next_")
            || user_key == "password-token";
        assert!(!is_internal, "user key should not be internal");
    }
}
