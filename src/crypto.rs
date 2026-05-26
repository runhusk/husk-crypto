// Shared symmetric crypto for Husk's at-rest containers.
//
// Used by:
//   - `vault.rs` for the password manager (HVLT container)
//   - `profile_manager.rs` for encrypted profiles (HPRF container)
//   - Future "secure notes" feature if/when it lands
//
// Stack (won't change without a version bump on every consumer):
//   - Argon2id KDF (OWASP 2024 params for Moderate, paranoia tier for
//     Sensitive). Derives a 32-byte key from a user phrase + salt.
//   - ChaCha20-Poly1305 AEAD for the actual encryption. Same construction
//     as libsodium's secretbox-but-with-AAD. 12-byte nonce, MUST be
//     unique per (key, plaintext) pair — caller's responsibility.
//   - AAD binds ciphertext to a context string ("husk-vault-v1") so a
//     stolen blob can't be replayed across containers / versions.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

#[derive(Debug)]
pub enum CryptoError {
    /// Argon2id failed — only happens for invalid params (we control
    /// those) or out-of-memory at huge cost levels.
    Argon(String),
    /// AEAD failed. On decrypt this almost certainly means wrong key
    /// (= wrong phrase) or tampered ciphertext. Either way callers
    /// should surface this as "wrong phrase" to the user.
    Aead(&'static str),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Argon(s) => write!(f, "Key derivation failed: {}", s),
            CryptoError::Aead(s) => write!(f, "Cipher error: {}", s),
        }
    }
}
impl std::error::Error for CryptoError {}

/// Argon2id cost level. We persist the LEVEL (not raw params) so a
/// container is portable across machines even if we change the
/// underlying numbers in a future release. Adding a new variant is
/// allowed; removing one would brick existing files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgonProfile {
    Moderate,
    Sensitive,
}

impl ArgonProfile {
    pub fn as_byte(self) -> u8 {
        match self {
            ArgonProfile::Moderate => 0,
            ArgonProfile::Sensitive => 1,
        }
    }
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(ArgonProfile::Moderate),
            1 => Some(ArgonProfile::Sensitive),
            _ => None,
        }
    }
    /// `(memory_kb, time_cost, lanes)` for the Argon2 params builder.
    fn params(self) -> (u32, u32, u32) {
        match self {
            // ~300–500ms on a 2024 laptop, 256 MB. OWASP-recommended
            // for password-encrypted local storage.
            ArgonProfile::Moderate => (256 * 1024, 3, 1),
            // ~1–3s, 1 GB. Paranoia tier — resists GPU/ASIC much
            // better but unlock becomes a perceptible chore.
            ArgonProfile::Sensitive => (1024 * 1024, 4, 1),
        }
    }
}

/// 32-byte symmetric key. Zeroed on drop via the `zeroize` derive —
/// compiles to a volatile memset the optimiser can't elide, so stale
/// bytes don't linger on the stack after the key falls out of scope.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey(pub [u8; KEY_LEN]);

impl DerivedKey {
    /// Borrowed view for passing into `ChaCha20Poly1305::new_from_slice`
    /// without copying. The lifetime ties the view to the key.
    fn as_aead_key(&self) -> &Key {
        Key::from_slice(&self.0)
    }
}

pub fn derive_key(
    phrase: &str,
    salt: &[u8],
    profile: ArgonProfile,
) -> Result<DerivedKey, CryptoError> {
    let (mem_kb, time_cost, lanes) = profile.params();
    let params = Params::new(mem_kb, time_cost, lanes, Some(KEY_LEN))
        .map_err(|e| CryptoError::Argon(format!("{:?}", e)))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(phrase.as_bytes(), salt, &mut out)
        .map_err(|e| CryptoError::Argon(format!("{:?}", e)))?;
    Ok(DerivedKey(out))
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut b = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut b = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut b);
    b
}

/// AEAD encrypt. `aad` (associated data) is authenticated but not
/// encrypted — bind the ciphertext to a context string like
/// `"husk-profile-v1"` so a blob from one container can't be swapped
/// into another. Caller MUST ensure the nonce is unique per (key,
/// plaintext) — reuse breaks the cipher catastrophically.
pub fn encrypt(
    key: &DerivedKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.as_aead_key());
    let n = Nonce::from_slice(nonce);
    cipher
        .encrypt(n, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Aead("encrypt failed"))
}

/// AEAD decrypt. Failure (wrong key, tampered bytes, wrong AAD) all
/// surface as a single error variant — by design, callers should NOT
/// distinguish "wrong key" from "tampered" externally (that side
/// channel would leak phrase-correctness info).
pub fn decrypt(
    key: &DerivedKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.as_aead_key());
    let n = Nonce::from_slice(nonce);
    cipher
        .decrypt(n, Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::Aead("decrypt failed (wrong phrase or corrupted file)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = derive_key("hunter2", &random_salt(), ArgonProfile::Moderate).unwrap();
        let nonce = random_nonce();
        let pt = b"hello husk";
        let ct = encrypt(&key, &nonce, pt, b"test-aad").unwrap();
        let got = decrypt(&key, &nonce, &ct, b"test-aad").unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn wrong_aad_fails() {
        let key = derive_key("hunter2", &random_salt(), ArgonProfile::Moderate).unwrap();
        let nonce = random_nonce();
        let ct = encrypt(&key, &nonce, b"secret", b"ctx-a").unwrap();
        assert!(decrypt(&key, &nonce, &ct, b"ctx-b").is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let salt = random_salt();
        let nonce = random_nonce();
        let k1 = derive_key("hunter2", &salt, ArgonProfile::Moderate).unwrap();
        let k2 = derive_key("hunter3", &salt, ArgonProfile::Moderate).unwrap();
        let ct = encrypt(&k1, &nonce, b"secret", b"aad").unwrap();
        assert!(decrypt(&k2, &nonce, &ct, b"aad").is_err());
    }

    #[test]
    fn argon_profile_byte_roundtrip() {
        assert_eq!(
            ArgonProfile::from_byte(ArgonProfile::Moderate.as_byte()),
            Some(ArgonProfile::Moderate)
        );
        assert_eq!(
            ArgonProfile::from_byte(ArgonProfile::Sensitive.as_byte()),
            Some(ArgonProfile::Sensitive)
        );
        assert_eq!(ArgonProfile::from_byte(99), None);
    }
}
