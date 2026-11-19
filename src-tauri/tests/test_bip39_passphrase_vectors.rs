use bsv::compat::bip32::ExtendedKey;
use electrumsv_mc_lib::{core::address::pubkey_to_p2pkh_address, services::{account_service, wallet_service::{self, Bip39RestoreMode}}, state::AppState};

// Public BIP39 test mnemonic; expected public values were independently derived using
// PBKDF2/NFKD and OpenSSL secp256k1, rather than this wallet's BSV SDK.
const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
struct Vector { passphrase: &'static str, xpub: &'static str, receive0: &'static str, receive1: &'static str, change0: &'static str }
const VECTORS: &[Vector] = &[
    Vector { passphrase: "", xpub: "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj", receive0: "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", receive1: "1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP", change0: "1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH" },
    Vector { passphrase: "TREZOR", xpub: "xpub6D3Cj1d8RgE6BRaEyYiRsJ8T17QA6Vq8F4P8f13BvDQTfgiBVT5iSdeSJ2QLSRijq2PMBXRSgduEUq11mYggQz6vUEe7Ga9e86urZjkrmeR", receive0: "1PEha8dk5Me5J1rZWpgqSt5F4BroTBLS5y", receive1: "1NWFrd38ng3DRt3oqAP1rAJZeDunek7E33", change0: "1MVkh45Zn9A7ZBga697r34DBiRFLXD4UKG" },
    Vector { passphrase: " café ", xpub: "xpub6CKy5JR1zBjsr9LoyGDgGkpF5C1UgANxti3Bxrk4YYoaXSCwAYzhDk9EEv6y3y1dj6dGk3eehGYBMFygj3C7N2NbzX6hDYNcdqrCUaXigcP", receive0: "1PrfmX8y9MnWyJeXLjkjcakkyfhPWsDC3q", receive1: "1CFFKvrNb2iMyeD5PyDj177ij5MyVHkNdh", change0: "1LX6d96bHFRPVRiQNn73ndx73jqYFkisem" },
    Vector { passphrase: " cafe\u{301} ", xpub: "xpub6CKy5JR1zBjsr9LoyGDgGkpF5C1UgANxti3Bxrk4YYoaXSCwAYzhDk9EEv6y3y1dj6dGk3eehGYBMFygj3C7N2NbzX6hDYNcdqrCUaXigcP", receive0: "1PrfmX8y9MnWyJeXLjkjcakkyfhPWsDC3q", receive1: "1CFFKvrNb2iMyeD5PyDj177ij5MyVHkNdh", change0: "1LX6d96bHFRPVRiQNn73ndx73jqYFkisem" },
    Vector { passphrase: "café", xpub: "xpub6DAb6DzoBBBCF4WVo9ugtRC5YiGzhot2YNwSUpNd8dCWz9sHcQqAkNmpUWgfz5ShnAGBojfrqCfP98HaLP8xj1C2B1NaLBtYZtmABcQWPFy", receive0: "181uaYvdKkcqKHwP77DGutmkXiJcET3qvx", receive1: "1PhKGL31kmyZZJbs36Q1hdnhDQUobFp9nr", change0: "1HA2zdJZEXs2i5jKrTbER1D2G15oyezbPE" },
];

#[tokio::test]
async fn public_bip39_passphrase_vectors_survive_wallet_reopen() {
    let root = std::env::temp_dir().join(format!("wallet-public-passphrase-{}-{}",std::process::id(),chrono::Utc::now().timestamp_nanos_opt().unwrap()));
    std::fs::create_dir_all(&root).unwrap();
    let mut state = AppState::new(); state.data_dir = root.to_string_lossy().into();
    for (index, vector) in VECTORS.iter().enumerate() {
        let name = format!("public-{index}");
        wallet_service::restore_bip39_wallet(&state, &name, "synthetic-password", MNEMONIC, vector.passphrase, Bip39RestoreMode::StandardBip39).await.unwrap();
        { let wallet = state.active_wallet.lock().unwrap(); assert_eq!(wallet.as_ref().unwrap().keystore_data.xpub, vector.xpub); }
        let first = account_service::get_receive_address(&state, None).await.unwrap();
        assert_eq!((first.derivation_index, first.address.as_str()), (0, vector.receive0));
        wallet_service::close_wallet(&state).await.unwrap();
        wallet_service::open_wallet(&state, &name).await.unwrap();
        wallet_service::unlock_wallet_authorized(&state, "synthetic-password", None).await.unwrap();
        { let wallet = state.active_wallet.lock().unwrap();
          let active = wallet.as_ref().unwrap(); assert_eq!(active.keystore_data.xpub, vector.xpub);
          // Change-address derivation is a private service helper; exercise SDK derivation against the external oracle.
          let key = ExtendedKey::from_string(active.decrypted_xprv.as_ref().unwrap()).unwrap().derive("1/0").unwrap();
          assert_eq!(pubkey_to_p2pkh_address(&key.public_key().unwrap()), vector.change0);
        }
        let second = account_service::get_receive_address(&state, None).await.unwrap();
        assert_eq!((second.derivation_index, second.address.as_str()), (1, vector.receive1));
        wallet_service::close_wallet(&state).await.unwrap();
    }
    assert!(serde_json::from_str::<Bip39RestoreMode>("\"unknown\"").is_err());
    assert!(wallet_service::restore_bip39_wallet(&state, "invalid", "synthetic-password", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", "", Bip39RestoreMode::StandardBip39).await.is_err());
    assert!(!root.join("invalid.sqlite").exists());
    wallet_service::restore_bip39_wallet(&state, "historical", "synthetic-password", MNEMONIC, " café ", Bip39RestoreMode::HistoricalMc).await.unwrap();
    { let wallet = state.active_wallet.lock().unwrap(); assert_eq!(wallet.as_ref().unwrap().keystore_data.xpub, "xpub6DBt8NsjkcZmMGvJpA27bzaM244citSghpHVJwfs1WYGcLbZK5xcEgT65tf8CWnzvc9wQeiphXK9gSGgjoxtTA8Yhq1K5PiFrcoJjRo9TBn"); }
    wallet_service::close_wallet(&state).await.unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
