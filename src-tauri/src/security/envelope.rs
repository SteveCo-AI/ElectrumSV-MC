//! Versioned authenticated encryption for one wallet secret bundle.
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const MAX_PAYLOAD: usize = 64 * 1024;
const MAX_JSON: usize = (MAX_PAYLOAD + 16) * 2 + 1024;
const DOMAIN: &[u8] = b"electrumsv-mc/wallet-secrets/v1";
const MEMORY: u32 = 65536;
const ITERATIONS: u32 = 3;
const LANES: u32 = 1;

/// Expected public wallet identity, supplied by the caller, never by the envelope.
#[derive(Clone)]
pub struct WalletContext {
    pub wallet_id: [u8; 16],
    pub xpub: String,
    pub derivation: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError { InvalidFormat, Authentication, EmptyPassword, Random, Runtime }

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    kdf: String,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    salt: String,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

fn context_valid(c: &WalletContext) -> bool {
    !c.xpub.is_empty() && c.xpub.len() <= 256 && !c.derivation.is_empty() && c.derivation.len() <= 256
}
fn append(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
fn aad(c: &WalletContext, salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in [DOMAIN, &1u32.to_be_bytes(), b"argon2id", &MEMORY.to_be_bytes(), &ITERATIONS.to_be_bytes(), &LANES.to_be_bytes(), salt, b"xchacha20poly1305", nonce, &c.wallet_id, c.xpub.as_bytes(), c.derivation.as_bytes()] {
        append(&mut out, part);
    }
    out
}
fn slots() -> &'static Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(2)))
}
async fn blocking_job<T: Send + 'static>(permit: tokio::sync::OwnedSemaphorePermit, job: impl FnOnce() -> Result<T, EnvelopeError> + Send + 'static) -> Result<T, EnvelopeError> {
    tokio::task::spawn_blocking(move || { let _permit = permit; job() })
        .await.map_err(|_| EnvelopeError::Runtime)?
}
fn derive(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
    let params = Params::new(MEMORY, ITERATIONS, LANES, Some(32)).map_err(|_| EnvelopeError::Runtime)?;
    let mut key = Zeroizing::new([0; 32]);
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); MEMORY as usize]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(password, salt, &mut *key, &mut *memory).map_err(|_| EnvelopeError::Runtime)?;
    Ok(key)
}
fn parse(data: &[u8]) -> Result<(Envelope, Vec<u8>, Vec<u8>, Vec<u8>), EnvelopeError> {
    if data.len() > MAX_JSON { return Err(EnvelopeError::InvalidFormat); }
    let e: Envelope = serde_json::from_slice(data).map_err(|_| EnvelopeError::InvalidFormat)?;
    if e.version != 1 || e.kdf != "argon2id" || e.memory_kib != MEMORY || e.iterations != ITERATIONS || e.lanes != LANES || e.cipher != "xchacha20poly1305" || e.salt.len() != 32 || e.nonce.len() != 48 || e.ciphertext.len() < 32 || e.ciphertext.len() > (MAX_PAYLOAD + 16) * 2 || e.ciphertext.len() % 2 != 0 {
        return Err(EnvelopeError::InvalidFormat);
    }
    let salt = hex::decode(&e.salt).map_err(|_| EnvelopeError::InvalidFormat)?;
    let nonce = hex::decode(&e.nonce).map_err(|_| EnvelopeError::InvalidFormat)?;
    let ciphertext = hex::decode(&e.ciphertext).map_err(|_| EnvelopeError::InvalidFormat)?;
    Ok((e, salt, nonce, ciphertext))
}

/// Encrypt a secret bundle. The owned blocking job retains its memory slot if cancelled.
pub async fn seal(password: &str, context: &WalletContext, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if password.is_empty() { return Err(EnvelopeError::EmptyPassword); }
    if password.len() > 4096 || plaintext.len() > MAX_PAYLOAD || !context_valid(context) { return Err(EnvelopeError::InvalidFormat); }
    let permit = slots().clone().acquire_owned().await.map_err(|_| EnvelopeError::Runtime)?;
    let password = Zeroizing::new(password.as_bytes().to_vec());
    let plaintext = Zeroizing::new(plaintext.to_vec());
    let context = context.clone();
    blocking_job(permit, move || {
        let mut salt = [0u8; 16]; let mut nonce = [0u8; 24];
        OsRng.try_fill_bytes(&mut salt).map_err(|_| EnvelopeError::Random)?;
        OsRng.try_fill_bytes(&mut nonce).map_err(|_| EnvelopeError::Random)?;
        let key = derive(&password, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| EnvelopeError::Runtime)?;
        let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &aad(&context, &salt, &nonce) }).map_err(|_| EnvelopeError::Runtime)?;
        let envelope = Envelope { version: 1, kdf: "argon2id".into(), memory_kib: MEMORY, iterations: ITERATIONS, lanes: LANES, salt: hex::encode(salt), cipher: "xchacha20poly1305".into(), nonce: hex::encode(nonce), ciphertext: hex::encode(ciphertext) };
        serde_json::to_vec(&envelope).map_err(|_| EnvelopeError::Runtime)
    }).await
}

/// Open only version 1; invalid formats never fall back to legacy encryption.
pub async fn open(password: &str, context: &WalletContext, serialized: &[u8]) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    if password.len() > 4096 || !context_valid(context) { return Err(EnvelopeError::InvalidFormat); }
    let (_, salt, nonce, ciphertext) = parse(serialized)?;
    if password.is_empty() { return Err(EnvelopeError::Authentication); }
    let permit = slots().clone().acquire_owned().await.map_err(|_| EnvelopeError::Runtime)?;
    let password = Zeroizing::new(password.as_bytes().to_vec());
    let context = context.clone();
    blocking_job(permit, move || {
        let key = derive(&password, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| EnvelopeError::Runtime)?;
        cipher.decrypt(XNonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &aad(&context, &salt, &nonce) }).map(Zeroizing::new).map_err(|_| EnvelopeError::Authentication)
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn ctx() -> WalletContext { WalletContext { wallet_id: [7; 16], xpub: "xpub-test".into(), derivation: "m/44'/0'/0'".into() } }
    #[test]
    fn aad_encoding_is_stable() {
        assert_eq!(hex::encode(aad(&ctx(), &[0;16], &[0;24])), concat!("0000001f656c65637472756d73762d6d632f77616c6c65742d736563726574732f76310000000400000001000000086172676f6e326964000000040001000000000004000000030000000400000001000000100000000000000000000000000000000000000011786368616368613230706f6c793133303500000018000000000000000000000000000000000000000000000000000000100707070707070707070707070707070700000009787075622d746573740000000b6d2f3434272f30272f3027"));
    }
    #[test]
    fn published_crypto_vectors() {
        let mut out = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(65536, 2, 1, Some(32)).unwrap()).hash_password_into(b"password", b"somesalt", &mut out).unwrap();
        assert_eq!(hex::encode(out), "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7");
        // draft-arciszewski-xchacha-03, A.1, also in RustCrypto tests.
        let key: Vec<u8> = (0x80..=0x9f).collect(); let nonce: Vec<u8> = (0x40..=0x57).collect();
        let a = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let p = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let out = XChaCha20Poly1305::new_from_slice(&key).unwrap().encrypt(XNonce::from_slice(&nonce), Payload { msg: p, aad: &a }).unwrap();
        assert_eq!(hex::encode(out), concat!("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb", "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452", "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9", "21f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49"));
    }
    #[tokio::test]
    async fn roundtrip_and_tampering() {
        let c = ctx(); let encoded = seal("pw", &c, b"secret").await.unwrap();
        assert_eq!(&*open("pw", &c, &encoded).await.unwrap(), b"secret");
        for password in ["", "wrong"] { assert_eq!(open(password, &c, &encoded).await.unwrap_err(), EnvelopeError::Authentication); }
        for field in ["salt", "nonce", "ciphertext", "tag"] {
            let mut v: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            let key = if field == "tag" { "ciphertext" } else { field };
            let mut b = hex::decode(v[key].as_str().unwrap()).unwrap(); let i = if field == "tag" { b.len()-1 } else { 0 }; b[i] ^= 1; v[key] = json!(hex::encode(b));
            assert_eq!(open("pw", &c, &serde_json::to_vec(&v).unwrap()).await.unwrap_err(), EnvelopeError::Authentication);
        }
        for changed in [WalletContext { wallet_id: [8; 16], ..c.clone() }, WalletContext { xpub: "other".into(), ..c.clone() }, WalletContext { derivation: "m/1".into(), ..c.clone() }] {
            assert_eq!(open("pw", &changed, &encoded).await.unwrap_err(), EnvelopeError::Authentication);
        }
    }
    #[tokio::test]
    async fn rejects_invalid_format_and_bounds() {
        let c = ctx(); assert_eq!(seal("", &c, b"x").await.unwrap_err(), EnvelopeError::EmptyPassword);
        assert_eq!(seal("pw", &c, &vec![0; MAX_PAYLOAD+1]).await.unwrap_err(), EnvelopeError::InvalidFormat);
        let encoded = seal("pw", &c, b"x").await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        for (name, val) in [("version", json!(2)), ("kdf", json!("other")), ("memory_kib", json!(u32::MAX)), ("iterations", json!(99)), ("lanes", json!(99)), ("cipher", json!("other")), ("salt", json!("00")), ("nonce", json!("zz".repeat(24))), ("ciphertext", json!("f")), ("extra", json!(true))] {
            let mut changed = v.clone(); changed[name] = val;
            assert_eq!(open("pw", &c, &serde_json::to_vec(&changed).unwrap()).await.unwrap_err(), EnvelopeError::InvalidFormat, "{name}");
        }
        assert_eq!(parse(&vec![b' '; MAX_JSON+1]).err(), Some(EnvelopeError::InvalidFormat));
        let dup = String::from_utf8(encoded).unwrap().replacen('{', "{\"version\":1,", 1);
        assert_eq!(parse(dup.as_bytes()).err(), Some(EnvelopeError::InvalidFormat));
    }
    #[tokio::test]
    async fn cancelled_job_retains_permit_until_blocking_work_finishes() {
        let semaphore = Arc::new(Semaphore::new(1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let task = tokio::spawn(blocking_job(permit, move || {
            started_tx.send(()).unwrap(); finish_rx.recv().unwrap(); Ok(())
        }));
        started_rx.await.unwrap(); task.abort();
        assert_eq!(semaphore.available_permits(), 0);
        finish_tx.send(()).unwrap();
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        drop(permit);
        assert_eq!(semaphore.available_permits(), 1);
    }

}
