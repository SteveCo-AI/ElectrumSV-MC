//! Authenticated secret payload for newly created wallets. Not a legacy migration.
use crate::{core::mnemonic, security::envelope::{self, WalletContext}};
use bsv::compat::bip32::ExtendedKey;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TotpPolicy {
    pub secret: Vec<u8>,
    pub recovery_hashes: Vec<String>,
}
impl Drop for TotpPolicy {
    fn drop(&mut self) { self.secret.zeroize(); self.recovery_hashes.zeroize(); }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WalletBundle {
    pub version: u32,
    pub xprv: String,
    pub mnemonic: String,
    pub passphrase: String,
    pub totp: Option<TotpPolicy>,
}
impl Drop for WalletBundle {
    fn drop(&mut self) { self.xprv.zeroize(); self.mnemonic.zeroize(); self.passphrase.zeroize(); }
}
impl WalletBundle {
    fn validate(&self, ctx: &WalletContext) -> Result<(), String> {
        if self.version != 1 { return Err("unsupported wallet bundle".into()); }
        let seed = Zeroizing::new(mnemonic::mnemonic_to_seed(&self.mnemonic, &self.passphrase).map_err(|_| "invalid wallet seed")?);
        let master = ExtendedKey::from_seed(&seed).map_err(|_| "invalid wallet seed")?;
        let key = master.derive(&ctx.derivation).map_err(|_| "invalid wallet derivation")?;
        if !key.is_private() || key.to_base58() != self.xprv || key.to_public().map_err(|_| "invalid wallet key")?.to_base58() != ctx.xpub {
            return Err("wallet key metadata mismatch".into());
        }
        if let Some(policy) = &self.totp {
            if policy.secret.len() != 20 || policy.recovery_hashes.len() > 10 || policy.recovery_hashes.iter().any(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit())) {
                return Err("invalid wallet TOTP policy".into());
            }
        }
        Ok(())
    }
}
pub(crate) async fn seal(password: &str, ctx: &WalletContext, bundle: &WalletBundle) -> Result<Vec<u8>, String> {
    bundle.validate(ctx)?;
    let bytes = Zeroizing::new(serde_json::to_vec(bundle).map_err(|_| "invalid wallet bundle")?);
    envelope::seal(password, ctx, &bytes).await.map_err(|_| "wallet encryption failed".into())
}
pub(crate) async fn open(password: &str, ctx: &WalletContext, data: &[u8]) -> Result<WalletBundle, String> {
    let bytes = envelope::open(password, ctx, data).await.map_err(|_| "wallet authentication failed")?;
    let bundle: WalletBundle = serde_json::from_slice(&bytes).map_err(|_| "invalid wallet bundle")?;
    bundle.validate(ctx)?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::keystore;
    #[tokio::test]
    async fn roundtrip_and_reject_mismatched_key_metadata() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic::mnemonic_to_seed(phrase, "passphrase").unwrap();
        let derived = keystore::derive_keys_from_seed(&seed).unwrap();
        let ctx = WalletContext { wallet_id: [1;16], xpub: derived.xpub, derivation: keystore::DERIVATION_PATH.into() };
        let bundle = WalletBundle { version: 1, xprv: derived.xprv, mnemonic: phrase.into(), passphrase: "passphrase".into(), totp: None };
        let encrypted = seal("password", &ctx, &bundle).await.unwrap();
        assert_eq!(open("password", &ctx, &encrypted).await.unwrap().xprv, bundle.xprv);
        assert!(open("wrong", &ctx, &encrypted).await.is_err());
        let mut corrupt = bundle.clone(); corrupt.passphrase = "other".into();
        assert!(seal("password", &ctx, &corrupt).await.is_err());
        let wrong_context = WalletContext { xpub: "wrong".into(), ..ctx };
        assert!(open("password", &wrong_context, &encrypted).await.is_err());
    }
}
