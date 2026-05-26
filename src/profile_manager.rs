// Husk profiles — multi-tenant per-client browsing isolation.
//
// Layout (decision 2026-05-20):
//   - `default` profile = the base root (`%APPDATA%/Husk/` or
//     `<exe>/HuskData/` in portable mode). Keeps the current layout
//     intact for ALL existing installs — zero migration risk against
//     WebView2's user-data-folder (touching that dir while it's
//     active could brick the chrome).
//   - Named profiles = `<base>/profiles/<name>/`. Each holds its own
//     bookmarks.json / history.json / vault.husk / settings.json /
//     session.json / WebView2 UDF / Screenshots/. Switching profile =
//     tearing down + rebuilding the WebViews against the new root.
//
// The active profile id is persisted in `<base>/active_profile.txt`
// (plain text, one line, no trailing whitespace). Single source of
// truth on boot; the file is rewritten every time the user switches.
//
// Encryption (phase 2, next session): a named profile can be marked
// encrypted by storing its JSON files inside a single `profile.enc`
// blob (Argon2id + ChaCha20-Poly1305, same crypto stack as the vault).
// The blob is decrypted to memory on unlock, files materialised to
// disk, used during the session, then re-encrypted + scrubbed on lock.
// This module does NOT implement that yet — the type system reserves
// the space via the `ProfileKind` enum so callers stay forward-compat.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    self, ArgonProfile, CryptoError, DerivedKey, NONCE_LEN, SALT_LEN,
};

pub const DEFAULT_PROFILE: &str = "default";

/// Where the per-profile root sits inside the base data dir. Used to
/// validate profile names (no slashes, no leading dots) so a malicious
/// or accidental name can't escape into the parent or hidden dirs.
pub const PROFILES_SUBDIR: &str = "profiles";

const ACTIVE_PROFILE_FILE: &str = "active_profile.txt";

/// Stable identifier — just the directory name. Plain `default` is
/// reserved and always-present; other ids are user-picked strings
/// validated through `is_valid_profile_name`.
pub type ProfileId = String;

/// Kind reserved for the encryption work in phase 2. Today the
/// constructor only ever returns `Plain` so existing call paths
/// don't need to branch on it.
#[allow(dead_code)] // Phase 2: encryption variant arrives with the unlock UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileKind {
    /// No at-rest encryption. Data files are written in cleartext —
    /// same threat model as a regular browser profile.
    Plain,
    /// Phase 2: phrase-protected profile. Data files live inside an
    /// encrypted container and are only materialised while unlocked.
    #[allow(dead_code)]
    Encrypted,
}

/// Compute the root directory for a given profile id. Does NOT create
/// the directory — call `ensure_profile_root` for that. Pure function
/// so the result is safe to use from anywhere (including init paths
/// that run before App is constructed).
pub fn profile_root(base: &Path, id: &str) -> PathBuf {
    if id == DEFAULT_PROFILE {
        base.to_path_buf()
    } else {
        base.join(PROFILES_SUBDIR).join(id)
    }
}

/// Same as `profile_root` but creates the dir tree if missing.
#[allow(dead_code)] // Reserved for the profile-switch UI in the next session.
pub fn ensure_profile_root(base: &Path, id: &str) -> std::io::Result<PathBuf> {
    let p = profile_root(base, id);
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

/// Reject names that would escape the profiles dir or shadow special
/// files. Conservative: ASCII alphanum + `-` + `_`, length 1..=64.
/// Rejects "default" too — that's a reserved magic id whose creation
/// path is different (no dir under `profiles/`, lives at the root).
pub fn is_valid_profile_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    if name == DEFAULT_PROFILE {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Enumerate profiles present on disk. Returns "default" first
/// (always exists, even if `profiles/` is empty), then any subdir
/// names under `<base>/profiles/` whose name passes validation.
#[allow(dead_code)] // Reserved for the profile-switch UI in the next session.
pub fn list_profiles(base: &Path) -> Vec<ProfileId> {
    let mut out = vec![DEFAULT_PROFILE.to_string()];
    let dir = base.join(PROFILES_SUBDIR);
    let Ok(entries) = std::fs::read_dir(&dir) else { return out };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
        if is_valid_profile_name(&name) {
            out.push(name);
        }
    }
    out
}

/// Create a fresh profile directory. Errors if the name is invalid,
/// the dir already exists, or filesystem permissions reject the mkdir.
#[allow(dead_code)] // Reserved for the profile-switch UI in the next session.
pub fn create_profile(base: &Path, id: &str) -> std::io::Result<PathBuf> {
    if !is_valid_profile_name(id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid profile name",
        ));
    }
    let dir = profile_root(base, id);
    if dir.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "profile already exists",
        ));
    }
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Read the persisted "last active profile" id, or fall back to
/// "default" when the file is missing / unreadable / contains an
/// invalid name. The fallback keeps boot resilient against tampering
/// with that file.
// Currently unused — `husk.exe` boot ignores active_profile.txt and
// always opens the default profile when no --profile is passed (the
// "resume last" behaviour was confusing once pinned shortcuts entered
// the picture). Kept around so we can wire it back behind an explicit
// "remember last profile" setting if users miss the behaviour.
#[allow(dead_code)]
pub fn read_active_profile(base: &Path) -> ProfileId {
    let path = base.join(ACTIVE_PROFILE_FILE);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return DEFAULT_PROFILE.to_string();
    };
    let trimmed = raw.trim();
    if trimmed == DEFAULT_PROFILE {
        return trimmed.to_string();
    }
    if is_valid_profile_name(trimmed) {
        // Also verify the directory still exists — a profile dir the
        // user deleted by hand shouldn't leave us pointing at it.
        if profile_root(base, trimmed).exists() {
            return trimmed.to_string();
        }
    }
    DEFAULT_PROFILE.to_string()
}

/// Persist the active profile id. Errors are surfaced but should be
/// rare (filesystem full / readonly mount); on next boot we'd fall
/// back to "default" and the user re-picks.
pub fn write_active_profile(base: &Path, id: &str) -> std::io::Result<()> {
    let _ = std::fs::create_dir_all(base);
    let path = base.join(ACTIVE_PROFILE_FILE);
    let tmp = path.with_extension("txt.tmp");
    std::fs::write(&tmp, id.as_bytes())?;
    std::fs::rename(&tmp, &path)
}

// =====================================================================
// Encrypted profiles
// =====================================================================
//
// On-disk layout (`<profile_dir>/profile.enc`):
//   bytes 0..4    magic "HPRF"
//   bytes 4..5    version (1)
//   bytes 5..6    argon profile byte (0 = Moderate, 1 = Sensitive)
//   bytes 6..22   salt (16 bytes — generated at create, never rotated)
//   bytes 22..34  nonce (12 bytes — rotated on every save)
//   bytes 34..    ciphertext (ChaCha20-Poly1305 sealed JSON payload)
//
// Plaintext payload shape (JSON):
//   {
//     "version": 1,
//     "files": { "<filename>": "<base64 content>", ... }
//   }
//
// Files tracked: bookmarks.json, history.json, settings.json,
// session.json, vault.husk. The vault file is BINARY (its own encryption
// container) — base64 keeps the JSON payload uniform.
//
// IMPORTANT: WebView2's user-data-folder (cookies / storage / cache) is
// NOT in the payload. It can be hundreds of MB and would make every
// lock/unlock crawl. Instead, encrypted profiles get a FRESH WebView2
// UDF each unlock under the temp dir — wiped on lock. Trade-off:
// cookies don't persist between sessions on encrypted profiles, but
// "zero traces" is the stronger property anyway.

const PROFILE_MAGIC: &[u8; 4] = b"HPRF";
const PROFILE_VERSION: u8 = 1;
const PROFILE_HEADER_LEN: usize = 4 + 1 + 1 + SALT_LEN + NONCE_LEN; // 34
const PROFILE_AAD: &[u8] = b"husk-profile-v1";

/// Filename of the encrypted container inside a profile's dir. Its
/// existence is also the marker that signals "this profile is
/// encrypted" — UI shows the 🔒 icon based on this probe.
pub const PROFILE_ENC_FILE: &str = "profile.enc";

/// Plaintext files that travel inside the encrypted container. Add a
/// new name here when introducing a new per-profile JSON file —
/// `lock_unlocked_profile` reads exactly this list, and on unlock the
/// materialised dir will contain just these entries.
pub const ENCRYPTED_FILE_NAMES: &[&str] = &[
    "bookmarks.json",
    "history.json",
    "settings.json",
    "session.json",
    "vault.husk",
    "notes.json",
];

#[derive(Debug)]
pub enum ProfileEncError {
    Io(String),
    BadFormat(&'static str),
    Crypto(CryptoError),
    Serde(String),
}

impl std::fmt::Display for ProfileEncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileEncError::Io(s) => write!(f, "I/O error: {}", s),
            ProfileEncError::BadFormat(s) => {
                write!(f, "Profile container corrupted: {}", s)
            }
            ProfileEncError::Crypto(e) => write!(f, "{}", e),
            ProfileEncError::Serde(s) => write!(f, "Serialization error: {}", s),
        }
    }
}
impl std::error::Error for ProfileEncError {}
impl From<CryptoError> for ProfileEncError {
    fn from(e: CryptoError) -> Self {
        ProfileEncError::Crypto(e)
    }
}
impl From<std::io::Error> for ProfileEncError {
    fn from(e: std::io::Error) -> Self {
        ProfileEncError::Io(format!("{}", e))
    }
}

/// JSON payload that lives inside the AEAD ciphertext.
#[derive(Debug, Serialize, Deserialize, Default)]
struct EncryptedPayload {
    #[serde(default = "default_payload_version")]
    version: u32,
    #[serde(default)]
    files: std::collections::BTreeMap<String, String>, // name -> base64 content
}
fn default_payload_version() -> u32 {
    1
}

/// Parsed view of a profile.enc file. `ciphertext` is the AEAD output
/// — still encrypted. Unlock turns this into an `EncryptedPayload`
/// via the user's phrase.
pub struct ProfileEncHeader {
    pub argon: ArgonProfile,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl ProfileEncHeader {
    fn parse(bytes: &[u8]) -> Result<Self, ProfileEncError> {
        if bytes.len() < PROFILE_HEADER_LEN {
            return Err(ProfileEncError::BadFormat("file shorter than header"));
        }
        if &bytes[0..4] != PROFILE_MAGIC {
            return Err(ProfileEncError::BadFormat("magic mismatch"));
        }
        if bytes[4] != PROFILE_VERSION {
            return Err(ProfileEncError::BadFormat("unsupported version"));
        }
        let argon = ArgonProfile::from_byte(bytes[5])
            .ok_or(ProfileEncError::BadFormat("unknown argon profile"))?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[6..6 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[6 + SALT_LEN..PROFILE_HEADER_LEN]);
        Ok(ProfileEncHeader {
            argon,
            salt,
            nonce,
            ciphertext: bytes[PROFILE_HEADER_LEN..].to_vec(),
        })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PROFILE_HEADER_LEN + self.ciphertext.len());
        buf.extend_from_slice(PROFILE_MAGIC);
        buf.push(PROFILE_VERSION);
        buf.push(self.argon.as_byte());
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }
}

/// Atomic write: `<path>.tmp` then rename. Avoids leaving a half-
/// written profile.enc on disk if the process dies mid-flush.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), ProfileEncError> {
    let tmp = path.with_extension("enc.tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Quick check: does this profile have an encrypted container? Used
/// by the UI to render the 🔒 icon and by switch_profile to decide
/// whether to prompt for a phrase.
/// Wipe every entry under an encrypted profile's root EXCEPT
/// `profile.enc` itself. Used after re-encrypt to ensure on-disk
/// state matches the contract: a locked encrypted profile = exactly
/// one file, the encrypted container. Anything else (EBWebView,
/// bookmarks.json from an old plain-profile incarnation, Screenshots,
/// log files, etc.) leaks data at rest, defeating the encryption.
///
/// Best-effort — IO errors are swallowed so a transient file lock
/// (e.g. WebView2 still releasing handles) doesn't fail the lock
/// flow. The next lock will retry.
pub fn scrub_encrypted_profile_dir(profile_root: &Path) {
    let Ok(entries) = std::fs::read_dir(profile_root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.file_name().and_then(|n| n.to_str()) == Some(PROFILE_ENC_FILE) {
            continue;
        }
        // Secure-wipe instead of plain remove — NTFS unlink leaves the
        // file bytes in unallocated clusters until reused. For an
        // encrypted profile at lock-time those bytes ARE the secrets
        // we just re-encrypted; forensic recovery (Sleuthkit etc.) can
        // reconstruct them in minutes from the disk image.
        if path.is_dir() {
            let _ = secure_wipe_dir(&path);
        } else {
            let _ = secure_wipe_file(&path);
        }
    }
}

/// Overwrite a file with zeros (one pass) then unlink. On NTFS / FAT
/// this defeats simple forensic carving since the file's clusters now
/// contain zeros instead of the previous content. Caveats: SSD wear-
/// levelling may have already moved the bytes to a different physical
/// cell that this overwrite doesn't reach; full coverage requires
/// disk-level encryption (BitLocker, VeraCrypt) which is the user's
/// responsibility.
///
/// Best-effort throughout: if anything goes wrong (file locked by
/// another process, permission denied, transient IO error), we fall
/// through to plain unlink. A partial wipe is strictly better than
/// no wipe.
pub fn secure_wipe_file(path: &Path) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    // Use OpenOptions + write so the same handle that writes also
    // truncates — this is what flushes the zeros to the same clusters
    // (vs. a separate truncate-then-write that could land elsewhere).
    if let Ok(meta) = std::fs::metadata(path) {
        let len = meta.len();
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            // Zero in 64 KiB chunks. Slower than a single big buffer
            // for huge files but keeps RAM bounded.
            const CHUNK: usize = 64 * 1024;
            let zeros = [0u8; CHUNK];
            let mut remaining = len;
            let _ = f.seek(SeekFrom::Start(0));
            while remaining > 0 {
                let n = remaining.min(CHUNK as u64) as usize;
                if f.write_all(&zeros[..n]).is_err() {
                    break;
                }
                remaining -= n as u64;
            }
            let _ = f.flush();
            // Truncate to 0 length so the directory entry doesn't
            // advertise the file's previous size to anyone walking the
            // FS before our unlink lands.
            let _ = f.set_len(0);
        }
    }
    std::fs::remove_file(path)
}

/// Recursive secure wipe of a directory. Walks bottom-up, calling
/// `secure_wipe_file` on each file and `remove_dir` on each emptied
/// directory. See `secure_wipe_file` for caveats.
pub fn secure_wipe_dir(dir: &Path) -> std::io::Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return std::fs::remove_dir_all(dir);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let _ = secure_wipe_dir(&path);
        } else {
            let _ = secure_wipe_file(&path);
        }
    }
    std::fs::remove_dir(dir)
}

pub fn is_profile_encrypted(base: &Path, id: &str) -> bool {
    profile_root(base, id).join(PROFILE_ENC_FILE).exists()
}

/// Create a brand-new encrypted profile. Writes a fresh profile.enc
/// containing an empty `files` payload. The phrase is consumed (not
/// stored) — once this returns the only path back into the profile is
/// re-deriving the key via the same phrase.
pub fn create_encrypted_profile(
    base: &Path,
    id: &str,
    phrase: &str,
    argon: ArgonProfile,
) -> Result<PathBuf, ProfileEncError> {
    if !is_valid_profile_name(id) {
        return Err(ProfileEncError::BadFormat("invalid profile name"));
    }
    let dir = profile_root(base, id);
    if dir.exists() {
        return Err(ProfileEncError::Io(format!(
            "profile \"{}\" already exists",
            id
        )));
    }
    std::fs::create_dir_all(&dir)?;
    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = crypto::derive_key(phrase, &salt, argon)?;
    let payload = EncryptedPayload::default();
    let plaintext =
        serde_json::to_vec(&payload).map_err(|e| ProfileEncError::Serde(format!("{}", e)))?;
    let ciphertext = crypto::encrypt(&key, &nonce, &plaintext, PROFILE_AAD)?;
    let header = ProfileEncHeader {
        argon,
        salt,
        nonce,
        ciphertext,
    };
    let enc_path = dir.join(PROFILE_ENC_FILE);
    atomic_write(&enc_path, &header.serialize())?;
    Ok(dir)
}

/// Live state of an unlocked encrypted profile. Holds the derived key
/// so re-encryption on lock doesn't re-prompt the user. Dropped =
/// temp dir wiped (intentional — caller MUST call `lock_*` first to
/// persist mutations; the Drop is the safety net for crash paths).
pub struct UnlockedProfile {
    pub id: ProfileId,
    pub temp_dir: PathBuf,
    pub key: DerivedKey,
    pub salt: [u8; SALT_LEN],
    pub argon: ArgonProfile,
}

impl Drop for UnlockedProfile {
    fn drop(&mut self) {
        // Secure-wipe instead of plain unlink. The temp dir held the
        // decrypted vault, bookmarks, history etc.; on NTFS a plain
        // remove_dir_all just unlinks, leaving the bytes in
        // unallocated clusters until reused. Forensic recovery from a
        // disk image at this point would defeat encryption-at-rest.
        let _ = secure_wipe_dir(&self.temp_dir);
    }
}

/// Decrypt a profile.enc + materialise its files into a fresh temp
/// dir. Returns the unlocked handle. Errors on wrong phrase or
/// corrupted container.
pub fn unlock_encrypted_profile(
    base: &Path,
    id: &str,
    phrase: &str,
) -> Result<UnlockedProfile, ProfileEncError> {
    let enc_path = profile_root(base, id).join(PROFILE_ENC_FILE);
    let bytes = std::fs::read(&enc_path)?;
    let header = ProfileEncHeader::parse(&bytes)?;
    let key = crypto::derive_key(phrase, &header.salt, header.argon)?;
    // SECURITY: every error from this point down must be coalesced
    // to the SAME variant the AEAD-fail returns. Otherwise the
    // post-decrypt parse path leaks "phrase was correct, payload
    // shape is weird" — distinguishable from "phrase was wrong" by
    // any attacker scripting the API. Audit T1-H06.
    let plaintext = crypto::decrypt(&key, &header.nonce, &header.ciphertext, PROFILE_AAD)
        .map_err(|_| ProfileEncError::Crypto(crypto::CryptoError::Aead("wrong phrase")))?;
    let payload: EncryptedPayload = serde_json::from_slice(&plaintext)
        .map_err(|_| ProfileEncError::Crypto(crypto::CryptoError::Aead("wrong phrase")))?;

    // Materialise to a fresh temp dir. We include the profile id so a
    // user with multiple unlocked profiles (future multi-window) can
    // tell them apart at a glance under %TEMP%.
    let safe_id: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let temp_dir = std::env::temp_dir().join(format!(
        "husk-prof-{}-{}",
        safe_id,
        std::process::id()
    ));
    // Wipe any leftover from a previous crashed session before
    // materialising — same name reuse means stale files would mix
    // with fresh ones otherwise. Use secure-wipe in case the prior
    // session crashed mid-unlock and left decrypted bytes around.
    let _ = secure_wipe_dir(&temp_dir);
    std::fs::create_dir_all(&temp_dir)?;

    let b64 = base64::engine::general_purpose::STANDARD;
    for (name, b64_content) in &payload.files {
        // Refuse anything that's not in the canonical file list so a
        // tampered payload can't write arbitrary names.
        if !ENCRYPTED_FILE_NAMES.iter().any(|allowed| *allowed == name) {
            continue;
        }
        // Same coalescing as the decrypt path above: any post-AEAD
        // error must look like WrongPhrase to keep the oracle closed.
        let bytes = b64
            .decode(b64_content)
            .map_err(|_| ProfileEncError::Crypto(crypto::CryptoError::Aead("wrong phrase")))?;
        std::fs::write(temp_dir.join(name), bytes)?;
    }

    Ok(UnlockedProfile {
        id: id.to_string(),
        temp_dir,
        key,
        salt: header.salt,
        argon: header.argon,
    })
}

/// Re-encrypt the unlocked profile's files back into its profile.enc,
/// then wipe the temp dir. Idempotent — calling twice in a row writes
/// the same content (second call's temp_dir is already gone, harmless).
pub fn lock_encrypted_profile(
    base: &Path,
    unlocked: &UnlockedProfile,
) -> Result<(), ProfileEncError> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut files = std::collections::BTreeMap::new();
    for name in ENCRYPTED_FILE_NAMES {
        let p = unlocked.temp_dir.join(name);
        if let Ok(bytes) = std::fs::read(&p) {
            files.insert((*name).to_string(), b64.encode(&bytes));
        }
    }
    let payload = EncryptedPayload {
        version: 1,
        files,
    };
    let plaintext =
        serde_json::to_vec(&payload).map_err(|e| ProfileEncError::Serde(format!("{}", e)))?;
    // Fresh nonce every save — never reuse with the same key.
    let nonce = crypto::random_nonce();
    let ciphertext = crypto::encrypt(&unlocked.key, &nonce, &plaintext, PROFILE_AAD)?;
    let header = ProfileEncHeader {
        argon: unlocked.argon,
        salt: unlocked.salt,
        nonce,
        ciphertext,
    };
    let prof_root = profile_root(base, &unlocked.id);
    let enc_path = prof_root.join(PROFILE_ENC_FILE);
    atomic_write(&enc_path, &header.serialize())?;
    // Secure-wipe temp dir (NOT plain remove_dir_all — see
    // secure_wipe_dir docstring for the NTFS forensic rationale).
    // The Drop impl on UnlockedProfile also does this as a safety
    // net for panic paths.
    let _ = secure_wipe_dir(&unlocked.temp_dir);
    // Scrub anything else in the profile root — EBWebView, stale
    // bookmarks.json from a pre-encryption run, screenshots dir, etc.
    // The contract is "encrypted profile = profile.enc on disk, full
    // stop". Anything else is either obsolete or an at-rest leak.
    scrub_encrypted_profile_dir(&prof_root);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_root_equals_base() {
        let base = Path::new("/tmp/husk");
        assert_eq!(profile_root(base, DEFAULT_PROFILE), base);
    }

    #[test]
    fn named_root_under_profiles() {
        let base = Path::new("/tmp/husk");
        assert_eq!(
            profile_root(base, "work"),
            base.join("profiles").join("work")
        );
    }

    #[test]
    fn rejects_dotdot_and_slashes() {
        assert!(!is_valid_profile_name(".."));
        assert!(!is_valid_profile_name("a/b"));
        assert!(!is_valid_profile_name("a\\b"));
        assert!(!is_valid_profile_name(".hidden"));
        assert!(!is_valid_profile_name(""));
        assert!(!is_valid_profile_name(&"x".repeat(65)));
        assert!(!is_valid_profile_name(DEFAULT_PROFILE));
    }

    #[test]
    fn accepts_typical_names() {
        assert!(is_valid_profile_name("work"));
        assert!(is_valid_profile_name("client-acme"));
        assert!(is_valid_profile_name("client_xyz_2026"));
        assert!(is_valid_profile_name("DEV"));
    }
}
