// network/backend.rs — NetworkBackend trait + shared types for ElectrumX/WhatsOnChain
//
// This module defines the common interface that both ElectrumX (TCP+TLS) and
// WhatsOnChain (REST) backends implement. It also defines the shared data types
// that flow through the network layer.
//
// AUDIT REQUIREMENTS:
// - AUD-006: broadcast_tx must return a validated txid, never None as success.
// - AUD-Fund #6: Server responses must be cryptographically validated.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Backend type enum
// ---------------------------------------------------------------------------

/// Which network backend is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    /// ElectrumX TCP+TLS protocol (primary).
    ElectrumX,
    /// WhatsOnChain REST API (fallback).
    WhatsOnChain,
}

impl fmt::Display for BackendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendType::ElectrumX => write!(f, "electrumx"),
            BackendType::WhatsOnChain => write!(f, "whatsonchain"),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared data types
// ---------------------------------------------------------------------------

/// Balance reported for a provider-specific query target.
///
/// Renamed from `BalanceInfo` to `BackendBalance` to avoid collision with
/// `commands::account::BalanceInfo` (the API-facing balance type with i64
/// fields). This struct uses u64 confirmed/total and i64 unconfirmed because
/// servers report raw satoshi amounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendBalance {
    /// Confirmed balance in satoshis.
    pub confirmed: u64,
    /// Unconfirmed balance in satoshis (mempool, can be negative).
    pub unconfirmed: i64,
    /// Total = confirmed + unconfirmed, clamped to >= 0 for display.
    pub total: u64,
}

impl BackendBalance {
    /// Reject positive overflow; negative totals are clamped to zero.
    pub fn new(confirmed: u64, unconfirmed: i64) -> Result<Self, NetworkError> {
        let total = if unconfirmed < 0 {
            confirmed.saturating_sub(unconfirmed.unsigned_abs())
        } else {
            confirmed.checked_add(unconfirmed as u64)
                .ok_or_else(|| NetworkError::Validation("balance total overflow".into()))?
        };
        Ok(Self {
            confirmed,
            unconfirmed,
            total,
        })
    }

    /// Returns true when the balance is zero and there is no unconfirmed activity.
    pub fn is_empty(&self) -> bool {
        self.confirmed == 0 && self.unconfirmed == 0
    }
}

impl Default for BackendBalance {
    fn default() -> Self {
        Self { confirmed: 0, unconfirmed: 0, total: 0 }
    }
}

/// A single history entry reported by a server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxHistoryEntry {
    /// Transaction hash in display (reversed) hex.
    pub tx_hash: String,
    /// Server-reported height, 0 or -1 for unconfirmed entries.
    pub height: i64,
    /// Whether the transaction has been independently verified; backend history alone is unverified.
    pub verified: bool,
}

/// An unspent transaction output from the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoEntry {
    /// Transaction hash in display (reversed) hex.
    pub tx_hash: String,
    /// Output index (vout).
    pub tx_pos: u32,
    /// Value in satoshis.
    pub value: u64,
    /// Block height if confirmed, 0 if unconfirmed.
    pub height: i64,
}

/// A block header (80 bytes, BSV format).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height in the chain.
    pub height: u64,
    /// Raw 80-byte header in hex.
    pub hex: String,
}

/// Merkle proof for SPV verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Transaction hash in display (reversed) hex.
    pub tx_hash: String,
    /// Block height containing the transaction.
    pub block_height: u64,
    /// Merkle branch: pairs of (hash, direction) where direction=true means the
    /// partner is on the right side.
    pub merkle_branch: Vec<(String, bool)>,
    pub position: Option<u64>,
    /// Merkle root from the block header (hex, internal byte order).
    pub root: String,
}

/// Result of broadcasting a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastResult {
    /// The validated transaction ID (64-char hex, display/reversed form).
    pub txid: String,
}

// ---------------------------------------------------------------------------
// Network error enum
// ---------------------------------------------------------------------------

/// Errors that can occur in the network layer.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// Connection refused, timeout, or DNS failure.
    #[error("connection error: {0}")]
    Connection(String),

    /// TLS handshake or certificate validation failure.
    /// AUD-Fund #6: Must never be bypassed.
    #[error("TLS error: {0}")]
    Tls(String),

    /// Server returned an error response.
    #[error("server error: {0}")]
    Server(String),

    /// JSON-RPC protocol error (malformed message, unexpected response).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Server response failed cryptographic validation.
    /// AUD-Fund #6: Invalid proof, wrong txid, bad header chain.
    #[error("validation error: {0}")]
    Validation(String),

    /// AUD-006: Broadcast returned None or empty — must be treated as failure.
    #[error("broadcast returned no txid")]
    BroadcastNoTxid,

    /// The requested data was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// All servers in the rotation have been exhausted.
    #[error("all servers failed")]
    AllServersFailed,

    /// No backend is currently connected.
    #[error("no backend connected")]
    NotConnected,

    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),

    /// Generic I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Generic JSON error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Scripthash helper
// ---------------------------------------------------------------------------

/// An ElectrumX script hash encoded as exactly 64 ASCII hexadecimal characters.
///
/// ```compile_fail
/// use electrumsv_mc_lib::network::backend::ScriptHash;
/// let _ = ScriptHash("00".repeat(32));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScriptHash(String);

impl TryFrom<&str> for ScriptHash {
    type Error = NetworkError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(NetworkError::Protocol("invalid scripthash".into()));
        }
        Ok(Self(value.to_owned()))
    }
}

impl ScriptHash {
    pub fn as_str(&self) -> &str { &self.0 }
}

/// A Base58Check mainnet P2PKH or P2SH address.
///
/// Other address forms formerly passed through to WhatsOnChain are rejected.
/// ```compile_fail
/// use electrumsv_mc_lib::network::backend::MainnetAddress;
/// let _ = MainnetAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_owned());
/// ```
/// ```no_run
/// use electrumsv_mc_lib::network::backend::{MainnetAddress, NetworkBackend, ScriptHash};
/// use electrumsv_mc_lib::network::{electrumx::ElectrumXClient, whatsonchain::WhatsOnChainClient};
/// async fn correct(electrum: &ElectrumXClient, woc: &WhatsOnChainClient) {
///     let hash = ScriptHash::try_from("00".repeat(32).as_str()).unwrap();
///     let address = MainnetAddress::try_from("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
///     let _ = electrum.get_history(&hash).await;
///     let _ = woc.get_history(&address).await;
/// }
/// ```
/// ```compile_fail
/// use electrumsv_mc_lib::network::backend::{MainnetAddress, NetworkBackend};
/// use electrumsv_mc_lib::network::electrumx::ElectrumXClient;
/// async fn wrong(client: &ElectrumXClient, address: &MainnetAddress) {
///     let _ = client.get_balance(address).await;
/// }
/// ```
/// ```compile_fail
/// use electrumsv_mc_lib::network::backend::{NetworkBackend, ScriptHash};
/// use electrumsv_mc_lib::network::whatsonchain::WhatsOnChainClient;
/// async fn wrong(client: &WhatsOnChainClient, hash: &ScriptHash) {
///     let _ = client.get_history(hash).await;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MainnetAddress(String);

impl TryFrom<&str> for MainnetAddress {
    type Error = NetworkError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        use sha2::{Digest, Sha256};
        if value.len() > 35 { return Err(NetworkError::Protocol("invalid mainnet address length".into())); }
        let decoded = bs58::decode(value).into_vec().map_err(|_| NetworkError::Protocol("invalid mainnet address".into()))?;
        if decoded.len() != 25 || !matches!(decoded[0], 0 | 5) {
            return Err(NetworkError::Protocol("expected a mainnet P2PKH or P2SH address".into()));
        }
        let checksum = Sha256::digest(Sha256::digest(&decoded[..21]));
        if decoded[21..] != checksum[..4] {
            return Err(NetworkError::Protocol("invalid address checksum".into()));
        }
        Ok(Self(value.to_owned()))
    }
}

impl MainnetAddress {
    pub fn as_str(&self) -> &str { &self.0 }
}

/// Compute the ElectrumX scripthash for a P2PKH address.
///
/// ElectrumX uses SHA256(script) in reverse byte order as the "scripthash".
/// For a P2PKH address, the script is: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
///
/// Returns the scripthash as a hex string (display/reversed form, matching ElectrumX protocol).
pub fn scripthash_from_address(addr: &str) -> Result<String, NetworkError> {
    use sha2::{Digest, Sha256};
    let decoded = bs58::decode(addr).into_vec().map_err(|e| NetworkError::Protocol(format!("invalid address: {e}")))?;
    if decoded.len() != 25 || decoded[0] != 0 {
        return Err(NetworkError::Protocol("expected a mainnet P2PKH address".into()));
    }
    let checksum = Sha256::digest(Sha256::digest(&decoded[..21]));
    if decoded[21..] != checksum[..4] {
        return Err(NetworkError::Protocol("invalid address checksum".into()));
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&decoded[1..21]);
    Ok(scripthash_from_pubkey_hash(&hash))
}

pub fn scripthash_from_pubkey_hash(pubkey_hash: &[u8; 20]) -> String {
    use sha2::{Digest, Sha256};
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(pubkey_hash);
    script.extend_from_slice(&[0x88, 0xac]);
    let mut hash = Sha256::digest(&script).to_vec();
    hash.reverse();
    hex::encode(hash)
}

pub fn scripthash_from_script(script_hex: &str) -> Result<String, NetworkError> {
    use sha2::{Digest, Sha256};
    let script = hex::decode(script_hex).map_err(|e| NetworkError::Protocol(format!("invalid script hex: {e}")))?;
    let mut hash = Sha256::digest(&script).to_vec();
    hash.reverse();
    Ok(hex::encode(hash))
}

// ---------------------------------------------------------------------------
// NetworkBackend trait
// ---------------------------------------------------------------------------

/// The common interface for all network backends (ElectrumX, WhatsOnChain).
///
/// Implementations must be async and Send, as they are called from Tauri commands.
///
/// AUDIT REQUIREMENTS:
/// - `broadcast_tx` MUST validate the returned txid (AUD-006).
/// - Server history, balances, and heights are unverified claims unless separately checked.
/// - TLS MUST use full certificate + hostname verification (no permissive verifier).
#[async_trait::async_trait]
pub trait NetworkBackend: Send + Sync {
    /// The provider-specific target for balance, history, and UTXO queries.
    type QueryTarget: Send + Sync;
    /// The backend type identifier.
    fn backend_type(&self) -> BackendType;

    /// Whether the backend is currently connected.
    fn is_connected(&self) -> bool;

    /// Get the current best block height (chain tip).
    async fn get_tip_height(&self) -> Result<u64, NetworkError>;

    /// Get the balance for this provider's query target.
    async fn get_balance(&self, target: &Self::QueryTarget) -> Result<BackendBalance, NetworkError>;

    /// Get the transaction history for this provider's query target.
    async fn get_history(&self, target: &Self::QueryTarget) -> Result<Vec<TxHistoryEntry>, NetworkError>;

    /// Get the unspent outputs for this provider's query target.
    async fn get_utxos(&self, target: &Self::QueryTarget) -> Result<Vec<UtxoEntry>, NetworkError>;

    /// Broadcast a raw transaction.
    ///
    /// AUD-006: The returned txid MUST be validated.
    /// - If the server returns None or empty, return `NetworkError::BroadcastNoTxid`.
    /// - The returned txid should match hash256(raw_tx) reversed.
    /// - On failure, the caller's transaction plan must remain retryable.
    async fn broadcast_tx(&self, raw_tx: &[u8]) -> Result<BroadcastResult, NetworkError>;

    /// Get block headers starting from `start_height` for `count` blocks.
    async fn get_block_headers(
        &self,
        start_height: u64,
        count: u64,
    ) -> Result<Vec<BlockHeader>, NetworkError>;

    /// Get the merkle proof for a transaction (SPV verification).
    async fn get_merkle_proof(
        &self,
        tx_hash: &str,
        block_height: u64,
    ) -> Result<MerkleProof, NetworkError>;

    /// Subscribe to scripthash updates, or return `Unsupported` when unavailable.
    /// Updates arrive via the notification channel.
    async fn subscribe_scripthash(&self, scripthash: &ScriptHash) -> Result<(), NetworkError>;

    /// Unsubscribe from status updates for a scripthash.
    async fn unsubscribe_scripthash(&self, scripthash: &ScriptHash) -> Result<(), NetworkError>;

    /// Ping the server to check liveness.
    async fn ping(&self) -> Result<(), NetworkError>;

    /// Gracefully disconnect from the server.
    async fn disconnect(&self) -> Result<(), NetworkError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_balance_overflow_reproduction() {
        assert!(matches!(BackendBalance::new(u64::MAX, 1), Err(NetworkError::Validation(_))));
        assert_eq!(BackendBalance::new(u64::MAX, 0).unwrap().total, u64::MAX);
        assert_eq!(BackendBalance::new(u64::MAX - 1, 1).unwrap().total, u64::MAX);
        assert_eq!(BackendBalance::new(0, i64::MIN).unwrap().total, 0);
        assert_eq!(BackendBalance::new(u64::MAX, i64::MIN).unwrap().total, i64::MAX as u64);
    }

    #[test]
    fn query_targets_validate_format_checksum_and_mainnet() {
        let lower = "ab".repeat(32);
        let upper = lower.to_ascii_uppercase();
        assert_eq!(ScriptHash::try_from(lower.as_str()).unwrap().as_str(), lower);
        assert_eq!(ScriptHash::try_from(upper.as_str()).unwrap().as_str(), upper);
        for value in ["", "0", &"0".repeat(63), &"0".repeat(65), &format!("{}g", "0".repeat(63)), &"é".repeat(32)] {
            assert!(ScriptHash::try_from(value).is_err());
        }
        for value in ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"] {
            assert_eq!(MainnetAddress::try_from(value).unwrap().as_str(), value);
        }
        for value in ["", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", "not_an_address"] {
            assert!(MainnetAddress::try_from(value).is_err());
        }
    }

    #[test]
    fn test_backend_type_display() {
        assert_eq!(BackendType::ElectrumX.to_string(), "electrumx");
        assert_eq!(BackendType::WhatsOnChain.to_string(), "whatsonchain");
    }

    #[test]
    fn test_backend_type_serde() {
        let json = serde_json::to_string(&BackendType::ElectrumX).unwrap();
        assert_eq!(json, "\"electrum_x\"");
        let bt: BackendType = serde_json::from_str("\"whats_on_chain\"").unwrap();
        assert_eq!(bt, BackendType::WhatsOnChain);
    }

    #[test]
    fn test_balance_info_new() {
        let b = BackendBalance::new(1000, 500).unwrap();
        assert_eq!(b.confirmed, 1000);
        assert_eq!(b.unconfirmed, 500);
        assert_eq!(b.total, 1500);
        assert!(!b.is_empty());
    }

    #[test]
    fn test_balance_info_negative_unconfirmed() {
        let b = BackendBalance::new(1000, -300).unwrap();
        assert_eq!(b.confirmed, 1000);
        assert_eq!(b.unconfirmed, -300);
        assert_eq!(b.total, 700);
    }

    #[test]
    fn test_balance_info_empty() {
        let b = BackendBalance::default();
        assert!(b.is_empty());
        assert_eq!(b.confirmed, 0);
        assert_eq!(b.total, 0);
    }

    #[test]
    fn test_balance_info_saturating_sub() {
        // If unconfirmed is more negative than confirmed, total clamps to 0
        let b = BackendBalance::new(100, -200).unwrap();
        assert_eq!(b.total, 0);
    }

    #[test]
    fn test_tx_history_entry() {
        let e = TxHistoryEntry {
            tx_hash: "abcdef1234567890".to_string(),
            height: 800000,
            verified: true,
        };
        assert_eq!(e.height, 800000);
        assert!(e.verified);
    }

    #[test]
    fn test_utxo_entry() {
        let u = UtxoEntry {
            tx_hash: "abcdef".to_string(),
            tx_pos: 0,
            value: 5000,
            height: 800000,
        };
        assert_eq!(u.value, 5000);
        assert_eq!(u.tx_pos, 0);
    }

    #[test]
    fn test_scripthash_from_known_address() {
        // Known: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (Bitcoin genesis address)
        // P2PKH script: 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac
        // hash160 = 62e907b15cbf27d5425399ebf6f0fb50ebb88f18
        let sh = scripthash_from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!(sh, "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161");
        assert!(scripthash_from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb").is_err());
        // Should be 64 hex chars
        assert_eq!(sh.len(), 64);
        // Verify it matches the known ElectrumX scripthash
        // script = 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac
        // hash256(script) reversed = 3b8a4c2a3b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
        // Actually just verify it's deterministic
        let sh2 = scripthash_from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!(sh, sh2);
    }

    #[test]
    fn test_scripthash_invalid_address() {
        let result = scripthash_from_address("invalid_address");
        assert!(result.is_err());
    }

    #[test]
    fn test_scripthash_from_script() {
        // P2PKH script for genesis address
        let script = "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac";
        let sh = scripthash_from_script(script).unwrap();
        assert_eq!(sh.len(), 64);

        // Should match scripthash_from_address for the same address
        let sh_addr = scripthash_from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!(sh, sh_addr);
    }

    #[test]
    fn test_scripthash_from_pubkey_hash() {
        // Known: hash160 = 62e907b15cbf27d5425399ebf6f0fb50ebb88f18
        // (from Bitcoin genesis address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa)
        let mut pubkey_hash = [0u8; 20];
        let hash_hex = "62e907b15cbf27d5425399ebf6f0fb50ebb88f18";
        let bytes = hex::decode(hash_hex).unwrap();
        pubkey_hash.copy_from_slice(&bytes);

        let sh = scripthash_from_pubkey_hash(&pubkey_hash);
        assert_eq!(sh.len(), 64);

        // Should match scripthash_from_address for the same address
        let sh_addr = scripthash_from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!(sh, sh_addr);
    }

    #[test]
    fn test_scripthash_invalid_script() {
        let result = scripthash_from_script("not_valid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_network_error_display() {
        let e = NetworkError::BroadcastNoTxid;
        assert!(e.to_string().contains("no txid"));

        let e = NetworkError::Connection("timeout".to_string());
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn test_block_header() {
        let h = BlockHeader {
            height: 800000,
            hex: "0000000000000000000123456789abcdef".to_string(),
        };
        assert_eq!(h.height, 800000);
    }

    #[test]
    fn test_merkle_proof() {
        let p = MerkleProof {
            tx_hash: "abcdef".to_string(),
            block_height: 800000,
            merkle_branch: vec![("deadbeef".to_string(), true)],
            position: Some(0),
            root: "cafebabe".to_string(),
        };
        assert_eq!(p.block_height, 800000);
        assert_eq!(p.merkle_branch.len(), 1);
    }
}
