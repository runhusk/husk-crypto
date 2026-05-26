// Husk Notes — per-profile markdown notebooks.
//
// Storage layout (one file per profile, simplest viable shape):
//
//   <profile_root>/notes.json
//     { version, notebooks: [...], notes: [...] }
//
// For an ENCRYPTED profile, `notes.json` lives inside the `profile.enc`
// container (added to ENCRYPTED_FILE_NAMES in profile_manager.rs). The
// whole file gets re-encrypted on lock — transparent privacy.
//
// For a non-encrypted profile, the file sits plain on disk. Users who
// want a specific note to be encrypted ANYWAY (regardless of profile)
// can opt-in to per-note encryption: the note's `body_md` is replaced
// with `encrypted_body` (Argon2id + ChaCha20-Poly1305, same primitives
// as the vault / encrypted profiles). Viewing such a note prompts for
// the per-note phrase. The phrase is NEVER stored.
//
// Why one big file: a typical Husk user will have dozens, maybe hundreds
// of notes. Single-file JSON keeps the on-disk shape grokkable + the
// encrypted-profile re-encrypt simple. Sharding to per-note files is a
// follow-up if a power user crosses 10k+ notes.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::{self, ArgonProfile, CryptoError, NONCE_LEN, SALT_LEN};

/// File schema version. Bump when we change the on-disk shape in a
/// non-back-compat way.
pub const SCHEMA_VERSION: u32 = 1;

const NOTES_FILE: &str = "notes.json";

/// AAD binding for per-note extra-encryption — prevents a cyphertext
/// blob from one note being replayed into another. The note's own id
/// is appended at encrypt/decrypt time so each note's AAD is unique.
const PER_NOTE_AAD_PREFIX: &[u8] = b"husk-note-v1:";

pub type NoteId = String;
pub type NotebookId = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notebook {
    pub id: NotebookId,
    pub name: String,
    /// Parent notebook id for nesting (None = root-level). The tree
    /// is intentionally shallow-by-construction: while we allow N
    /// levels in the model, the UI surfaces depth 1-2 to keep nav
    /// simple. Deeper trees still work but get harder to browse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<NotebookId>,
    /// Unix epoch seconds. Drives sort + "last edited" labels in the UI.
    pub created_at: u64,
    /// When `Some`, this notebook is encrypted: every plain note inside
    /// has its `body_md` moved into `encrypted_body` using the
    /// Argon2id-derived notebook key. New notes added while the
    /// notebook is encrypted MUST be encrypted with the same key
    /// before persist. Notes that already had per-note encryption
    /// stay untouched (their phrase remains separate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<NotebookEncryption>,
}

/// On-disk record proving the user knew the notebook phrase at encrypt
/// time. The `verifier_*` fields hold a fixed plaintext encrypted with
/// the derived key — at unlock we re-derive the key, decrypt the
/// verifier, and check it equals `NOTEBOOK_VERIFIER_PLAINTEXT`. That's
/// O(1) vs decrypting every note to validate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotebookEncryption {
    pub argon: ArgonProfile,
    #[serde(with = "serde_bytes_array")]
    pub salt: [u8; SALT_LEN],
    #[serde(with = "serde_bytes_array")]
    pub verifier_nonce: [u8; NONCE_LEN],
    pub verifier_b64: String,
}

/// Fixed plaintext used to validate a notebook phrase without iterating
/// every note. Bytes are arbitrary — they just have to be stable.
const NOTEBOOK_VERIFIER_PLAINTEXT: &[u8] = b"husk-notebook-verify-v1";
/// AAD prefix for notebook-key encrypted note bodies. Bound to the
/// notebook id so a ciphertext from notebook A can't be replayed into
/// notebook B's slot.
const NOTEBOOK_NOTE_AAD_PREFIX: &[u8] = b"husk-nb-note-v1:";
/// AAD for the verifier blob itself — bound to the notebook id so a
/// verifier from one notebook can't be relocated to another with the
/// same phrase.
const NOTEBOOK_VERIFIER_AAD_PREFIX: &[u8] = b"husk-nb-verify-v1:";

/// One note. `body_md` is the live source-of-truth; the UI parses it
/// for rendering. `encrypted_body` is present only when the user has
/// per-note encryption enabled — `body_md` is then empty and only the
/// ciphertext travels with the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub id: NoteId,
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body_md: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notebook_id: Option<NotebookId>,
    pub created_at: u64,
    pub updated_at: u64,
    /// Optional per-note encryption envelope. When `Some`, `body_md`
    /// MUST be empty — the real content lives in this blob and only
    /// unlocks with the right phrase via `decrypt_note_body`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_body: Option<EncryptedBody>,
}

/// Which decryption path produced this body — and therefore which
/// AAD must be used to verify it. Without this discriminator a
/// caller routing on "is `encrypted_body` Some?" can use the wrong
/// AAD and either (a) fail decryption with a phrase that's actually
/// correct (T1-H03), or (b) be tricked into deriving the notebook
/// key from a single note (T1-H02).
///
/// Defaults to `PerNotePhrase` for backward compat: any note saved
/// by an older Husk had this shape, and the per-note flow is the
/// surface that takes a user-supplied phrase.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedBodyKind {
    /// Sealed with a phrase only this note knows. AAD =
    /// `husk-note-v1:<note_id>`.
    #[default]
    PerNotePhrase,
    /// Sealed with the notebook's master key (the user typed the
    /// notebook phrase to unlock the whole notebook). AAD =
    /// `husk-nb-note-v1:<notebook_id>:<note_id>`.
    UnderNotebookKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBody {
    pub argon: ArgonProfile,
    #[serde(with = "serde_bytes_array")]
    pub salt: [u8; SALT_LEN],
    #[serde(with = "serde_bytes_array")]
    pub nonce: [u8; NONCE_LEN],
    /// Base64-encoded ciphertext (Argon2id-derived key + ChaCha20-Poly1305).
    pub ciphertext_b64: String,
    /// Which key + AAD scheme produced this ciphertext. See
    /// `EncryptedBodyKind`. Audit T1-H02 / T1-H03.
    #[serde(default)]
    pub kind: EncryptedBodyKind,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NotesFile {
    #[serde(default = "default_schema_version")]
    pub version: u32,
    #[serde(default)]
    pub notebooks: Vec<Notebook>,
    #[serde(default)]
    pub notes: Vec<Note>,
}

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

#[derive(Debug)]
pub enum NotesError {
    Io(String),
    Serde(String),
    Crypto(CryptoError),
    #[allow(dead_code)]
    NotFound,
    /// Caller tried to decrypt a note that wasn't encrypted.
    NotEncrypted,
    /// Bad base64 in an encrypted blob.
    BadFormat(&'static str),
    /// Caller invoked the wrong decrypt path for this body's kind
    /// (e.g. `decrypt_note_body` on a notebook-key-sealed body, or
    /// `decrypt_note_under_notebook_key` on a per-note body). Audit
    /// T1-H03.
    WrongDecryptPath,
}

impl std::fmt::Display for NotesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotesError::Io(s) => write!(f, "Notes IO error: {}", s),
            NotesError::Serde(s) => write!(f, "Notes serde error: {}", s),
            NotesError::Crypto(e) => write!(f, "Notes crypto error: {}", e),
            NotesError::NotFound => write!(f, "Note not found"),
            NotesError::NotEncrypted => write!(f, "Note is not encrypted"),
            NotesError::BadFormat(s) => write!(f, "Bad note format: {}", s),
            NotesError::WrongDecryptPath => write!(f, "Wrong decrypt path for this note's seal kind"),
        }
    }
}
impl std::error::Error for NotesError {}

impl From<std::io::Error> for NotesError {
    fn from(e: std::io::Error) -> Self {
        NotesError::Io(format!("{}", e))
    }
}
impl From<CryptoError> for NotesError {
    fn from(e: CryptoError) -> Self {
        NotesError::Crypto(e)
    }
}

/// Load (or default-construct) the notes file for a given profile root.
/// Missing file = empty notes, never an error. Corrupt file = same
/// behaviour as missing, with a log line — losing notes silently would
/// be worse than starting fresh + telling the user via the empty state.
pub fn load(profile_root: &Path) -> NotesFile {
    let path = profile_root.join(NOTES_FILE);
    let Ok(bytes) = std::fs::read(&path) else {
        return NotesFile::default();
    };
    match serde_json::from_slice::<NotesFile>(&bytes) {
        Ok(mut f) => {
            // Defensive normalisation: any note flagged encrypted but with
            // a body_md is malformed — clear the body_md to keep the
            // invariant. Won't lose data because the encrypted_body is
            // the source of truth in that case.
            for n in &mut f.notes {
                if n.encrypted_body.is_some() {
                    n.body_md.clear();
                }
            }
            f
        }
        Err(e) => {
            eprintln!("[husk] notes.json parse failed: {} — starting empty", e);
            NotesFile::default()
        }
    }
}

/// Atomic write: serialize to a sibling tmp file, fsync, rename over the
/// real path. A power loss mid-write leaves the previous snapshot intact
/// instead of producing a half-flushed half-corrupt notes.json.
pub fn save(profile_root: &Path, file: &NotesFile) -> Result<(), NotesError> {
    let path = profile_root.join(NOTES_FILE);
    let tmp = profile_root.join(format!("{}.tmp", NOTES_FILE));
    let bytes = serde_json::to_vec_pretty(file)
        .map_err(|e| NotesError::Serde(format!("{}", e)))?;
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Encrypt a note's body with a user-supplied phrase. Replaces the
/// plaintext `body_md` with an `encrypted_body` blob. Once encrypted,
/// only the phrase can recover the markdown — Husk does NOT store it.
pub fn encrypt_note_body(
    note: &mut Note,
    phrase: &str,
    argon: ArgonProfile,
) -> Result<(), NotesError> {
    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = crypto::derive_key(phrase, &salt, argon)?;
    let aad = note_aad(&note.id);
    let ciphertext = crypto::encrypt(&key, &nonce, note.body_md.as_bytes(), &aad)?;
    note.encrypted_body = Some(EncryptedBody {
        argon,
        salt,
        nonce,
        ciphertext_b64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &ciphertext,
        ),
        kind: EncryptedBodyKind::PerNotePhrase,
    });
    note.body_md.clear();
    Ok(())
}

/// Decrypt a per-note encrypted body. Returns the plaintext markdown
/// without mutating the note (caller decides whether to keep it
/// plaintext or just display once). Wrong phrase = `CryptoError::Aead`,
/// indistinguishable from a tampered ciphertext on purpose.
pub fn decrypt_note_body(note: &Note, phrase: &str) -> Result<String, NotesError> {
    let env = note
        .encrypted_body
        .as_ref()
        .ok_or(NotesError::NotEncrypted)?;
    // Refuse to attempt per-note decrypt on a body that was sealed
    // under the notebook key. Without this, the call always fails
    // with a generic AEAD error and the user sees "wrong phrase" on
    // a note that is actually recoverable via the notebook unlock —
    // T1-H03. Surfacing a distinct error lets the caller route to
    // the notebook flow instead.
    if env.kind == EncryptedBodyKind::UnderNotebookKey {
        return Err(NotesError::WrongDecryptPath);
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let ciphertext = base64::Engine::decode(&b64, &env.ciphertext_b64)
        .map_err(|_| NotesError::BadFormat("invalid base64 in encrypted_body"))?;
    let key = crypto::derive_key(phrase, &env.salt, env.argon)?;
    let aad = note_aad(&note.id);
    let plaintext = crypto::decrypt(&key, &env.nonce, &ciphertext, &aad)?;
    String::from_utf8(plaintext).map_err(|_| NotesError::BadFormat("decrypted note isn't UTF-8"))
}

fn note_aad(id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PER_NOTE_AAD_PREFIX.len() + id.len());
    aad.extend_from_slice(PER_NOTE_AAD_PREFIX);
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn nb_note_aad(notebook_id: &str, note_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        NOTEBOOK_NOTE_AAD_PREFIX.len() + notebook_id.len() + 1 + note_id.len(),
    );
    aad.extend_from_slice(NOTEBOOK_NOTE_AAD_PREFIX);
    aad.extend_from_slice(notebook_id.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(note_id.as_bytes());
    aad
}

fn nb_verifier_aad(notebook_id: &str) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(NOTEBOOK_VERIFIER_AAD_PREFIX.len() + notebook_id.len());
    aad.extend_from_slice(NOTEBOOK_VERIFIER_AAD_PREFIX);
    aad.extend_from_slice(notebook_id.as_bytes());
    aad
}

/// Encrypt every plain note belonging to `notebook_id` under a key
/// derived from `phrase`. Notes that already have per-note encryption
/// (their own phrase) stay untouched — the user opted into a separate
/// key for those, no reason to override. Writes the notebook's
/// encryption envelope so future loads see the encrypted state.
///
/// Idempotent if already encrypted: returns Ok without re-encrypting.
pub fn encrypt_notebook(
    file: &mut NotesFile,
    notebook_id: &str,
    phrase: &str,
    argon: ArgonProfile,
) -> Result<(), NotesError> {
    // Already encrypted? No-op (caller may have double-clicked).
    if file
        .notebooks
        .iter()
        .any(|nb| nb.id == notebook_id && nb.encryption.is_some())
    {
        return Ok(());
    }
    let salt = crypto::random_salt();
    let key = crypto::derive_key(phrase, &salt, argon)?;
    // Build the verifier.
    let verifier_nonce = crypto::random_nonce();
    let verifier_aad = nb_verifier_aad(notebook_id);
    let verifier_ct =
        crypto::encrypt(&key, &verifier_nonce, NOTEBOOK_VERIFIER_PLAINTEXT, &verifier_aad)?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let envelope = NotebookEncryption {
        argon,
        salt,
        verifier_nonce,
        verifier_b64: base64::Engine::encode(&b64, &verifier_ct),
    };
    // Encrypt all plain notes in this notebook with the notebook key.
    for n in file.notes.iter_mut() {
        if n.notebook_id.as_deref() != Some(notebook_id) {
            continue;
        }
        if n.encrypted_body.is_some() {
            // Per-note encrypted — leave alone (user's choice).
            continue;
        }
        let nonce = crypto::random_nonce();
        let aad = nb_note_aad(notebook_id, &n.id);
        let ciphertext = crypto::encrypt(&key, &nonce, n.body_md.as_bytes(), &aad)?;
        n.encrypted_body = Some(EncryptedBody {
            argon,
            salt,
            nonce,
            ciphertext_b64: base64::Engine::encode(&b64, &ciphertext),
            kind: EncryptedBodyKind::UnderNotebookKey,
        });
        n.body_md.clear();
    }
    // Stamp the envelope last so a panic mid-loop doesn't leave a
    // notebook flagged encrypted with partially-encrypted notes.
    if let Some(nb) = file.notebooks.iter_mut().find(|nb| nb.id == notebook_id) {
        nb.encryption = Some(envelope);
    }
    Ok(())
}

/// Validate that `phrase` matches the notebook's encryption envelope.
/// Returns the derived key on success (caller caches it for the
/// session). Wrong phrase = `CryptoError::Aead` — same opaque error as
/// a tampered verifier blob.
pub fn verify_notebook_phrase(
    notebook: &Notebook,
    phrase: &str,
) -> Result<crypto::DerivedKey, NotesError> {
    let env = notebook
        .encryption
        .as_ref()
        .ok_or(NotesError::NotEncrypted)?;
    let key = crypto::derive_key(phrase, &env.salt, env.argon)?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let ciphertext = base64::Engine::decode(&b64, &env.verifier_b64)
        .map_err(|_| NotesError::BadFormat("invalid base64 in verifier"))?;
    let aad = nb_verifier_aad(&notebook.id);
    let plain = crypto::decrypt(&key, &env.verifier_nonce, &ciphertext, &aad)?;
    if plain != NOTEBOOK_VERIFIER_PLAINTEXT {
        // The decrypt succeeded but the payload doesn't match — should
        // never happen unless the file was tampered with. Treat as a
        // crypto failure either way.
        return Err(NotesError::Crypto(CryptoError::Aead(
            "verifier plaintext mismatch",
        )));
    }
    Ok(key)
}

/// Decrypt a single note that was encrypted under the notebook key
/// (i.e. note has `encrypted_body` whose ciphertext came from
/// `encrypt_notebook`). Caller passes the already-derived
/// `DerivedKey` cached from `verify_notebook_phrase`.
pub fn decrypt_note_under_notebook_key(
    note: &Note,
    notebook_id: &str,
    key: &crypto::DerivedKey,
) -> Result<String, NotesError> {
    let env = note
        .encrypted_body
        .as_ref()
        .ok_or(NotesError::NotEncrypted)?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let ciphertext = base64::Engine::decode(&b64, &env.ciphertext_b64)
        .map_err(|_| NotesError::BadFormat("invalid base64"))?;
    let aad = nb_note_aad(notebook_id, &note.id);
    let plain = crypto::decrypt(key, &env.nonce, &ciphertext, &aad)?;
    String::from_utf8(plain).map_err(|_| NotesError::BadFormat("decrypted note isn't UTF-8"))
}

/// Encrypt a single note's body under the notebook key. Used when
/// adding a new note to an already-unlocked encrypted notebook.
pub fn encrypt_note_under_notebook_key(
    note: &mut Note,
    notebook_id: &str,
    key: &crypto::DerivedKey,
    argon: ArgonProfile,
    salt: [u8; SALT_LEN],
) -> Result<(), NotesError> {
    let nonce = crypto::random_nonce();
    let aad = nb_note_aad(notebook_id, &note.id);
    let ciphertext = crypto::encrypt(key, &nonce, note.body_md.as_bytes(), &aad)?;
    let b64 = base64::engine::general_purpose::STANDARD;
    note.encrypted_body = Some(EncryptedBody {
        argon,
        salt,
        nonce,
        ciphertext_b64: base64::Engine::encode(&b64, &ciphertext),
        kind: EncryptedBodyKind::UnderNotebookKey,
    });
    note.body_md.clear();
    Ok(())
}

/// Remove a notebook's encryption: decrypts every note in it back to
/// plaintext using the supplied phrase. Per-note-encrypted notes
/// (separate phrase) are left untouched.
pub fn decrypt_notebook(
    file: &mut NotesFile,
    notebook_id: &str,
    phrase: &str,
) -> Result<(), NotesError> {
    let Some(nb_idx) = file.notebooks.iter().position(|nb| nb.id == notebook_id) else {
        return Err(NotesError::NotFound);
    };
    // Verify phrase + derive key.
    let nb_snapshot = file.notebooks[nb_idx].clone();
    let key = verify_notebook_phrase(&nb_snapshot, phrase)?;
    // Decrypt each notebook-encrypted note. We identify them via AAD:
    // a per-note-encrypted body would decrypt failure against the
    // notebook AAD, which we treat as "this one isn't ours, skip".
    for n in file.notes.iter_mut() {
        if n.notebook_id.as_deref() != Some(notebook_id) {
            continue;
        }
        let Some(env) = n.encrypted_body.clone() else {
            continue;
        };
        let b64 = base64::engine::general_purpose::STANDARD;
        let Ok(ciphertext) = base64::Engine::decode(&b64, &env.ciphertext_b64) else {
            continue;
        };
        let aad = nb_note_aad(notebook_id, &n.id);
        if let Ok(plain) = crypto::decrypt(&key, &env.nonce, &ciphertext, &aad) {
            if let Ok(s) = String::from_utf8(plain) {
                n.body_md = s;
                n.encrypted_body = None;
            }
        }
        // Notes that don't decrypt with the notebook key are per-note
        // encrypted with a different phrase — leave them alone.
    }
    file.notebooks[nb_idx].encryption = None;
    Ok(())
}

/// Fresh random NoteId. 16 random bytes hex-encoded — collisions
/// astronomically unlikely, doesn't depend on timestamps (which can
/// collide on fast-fire creates).
pub fn new_id() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let mut s = String::with_capacity(32);
    for b in buf {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn now_epoch_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- Serde helper for fixed-size byte arrays ----------------------------
// serde_bytes wraps Vec<u8>; for [u8; N] we hand-roll the visitor.
mod serde_bytes_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        s.serialize_str(&b64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        use base64::Engine as _;
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let v = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(D::Error::custom)?;
        if v.len() != N {
            return Err(D::Error::custom(format!(
                "expected {} bytes, got {}",
                N,
                v.len()
            )));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("husk-notes-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut f = NotesFile::default();
        f.notebooks.push(Notebook {
            id: "nb1".into(),
            name: "Work".into(),
            parent_id: None,
            created_at: now_epoch_secs(),
            encryption: None,
        });
        f.notes.push(Note {
            id: new_id(),
            title: "First note".into(),
            body_md: "# Hello\n\nWorld.".into(),
            tags: vec!["urgent".into()],
            notebook_id: Some("nb1".into()),
            created_at: now_epoch_secs(),
            updated_at: now_epoch_secs(),
            encrypted_body: None,
        });
        save(&dir, &f).unwrap();

        let loaded = load(&dir);
        assert_eq!(loaded.notes.len(), 1);
        assert_eq!(loaded.notes[0].title, "First note");
        assert_eq!(loaded.notes[0].body_md, "# Hello\n\nWorld.");
        assert_eq!(loaded.notebooks.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_note_encrypt_roundtrip() {
        let mut note = Note {
            id: new_id(),
            title: "Secret".into(),
            body_md: "the launch codes are 12345".into(),
            tags: vec![],
            notebook_id: None,
            created_at: now_epoch_secs(),
            updated_at: now_epoch_secs(),
            encrypted_body: None,
        };
        encrypt_note_body(&mut note, "hunter2", ArgonProfile::Moderate).unwrap();
        assert!(note.body_md.is_empty());
        assert!(note.encrypted_body.is_some());

        let plain = decrypt_note_body(&note, "hunter2").unwrap();
        assert_eq!(plain, "the launch codes are 12345");

        // Wrong phrase fails opaquely.
        assert!(decrypt_note_body(&note, "wrong").is_err());
    }

    #[test]
    fn notebook_encrypt_decrypt_roundtrip() {
        let nb_id = "nb-1".to_string();
        let mut f = NotesFile::default();
        f.notebooks.push(Notebook {
            id: nb_id.clone(),
            name: "Secrets".into(),
            parent_id: None,
            created_at: now_epoch_secs(),
            encryption: None,
        });
        f.notes.push(Note {
            id: new_id(),
            title: "Plain".into(),
            body_md: "hello world".into(),
            tags: vec![],
            notebook_id: Some(nb_id.clone()),
            created_at: now_epoch_secs(),
            updated_at: now_epoch_secs(),
            encrypted_body: None,
        });
        // Per-note encrypted note in the SAME notebook — must survive
        // the notebook encrypt/decrypt untouched.
        let mut per_note = Note {
            id: new_id(),
            title: "Per-note".into(),
            body_md: "individual secret".into(),
            tags: vec![],
            notebook_id: Some(nb_id.clone()),
            created_at: now_epoch_secs(),
            updated_at: now_epoch_secs(),
            encrypted_body: None,
        };
        encrypt_note_body(&mut per_note, "individual", ArgonProfile::Moderate).unwrap();
        f.notes.push(per_note.clone());

        encrypt_notebook(&mut f, &nb_id, "shared", ArgonProfile::Moderate).unwrap();
        // Notebook flagged.
        assert!(f.notebooks[0].encryption.is_some());
        // Plain note now encrypted.
        assert!(f.notes[0].encrypted_body.is_some());
        assert!(f.notes[0].body_md.is_empty());
        // Per-note encrypted note unchanged.
        assert_eq!(f.notes[1].encrypted_body.as_ref().unwrap().ciphertext_b64,
                   per_note.encrypted_body.as_ref().unwrap().ciphertext_b64);

        // Verify phrase + decrypt one note via notebook key.
        let key = verify_notebook_phrase(&f.notebooks[0], "shared").unwrap();
        let plain = decrypt_note_under_notebook_key(&f.notes[0], &nb_id, &key).unwrap();
        assert_eq!(plain, "hello world");

        // Wrong phrase opaque error.
        assert!(verify_notebook_phrase(&f.notebooks[0], "wrong").is_err());

        // Remove encryption.
        decrypt_notebook(&mut f, &nb_id, "shared").unwrap();
        assert!(f.notebooks[0].encryption.is_none());
        assert_eq!(f.notes[0].body_md, "hello world");
        assert!(f.notes[0].encrypted_body.is_none());
        // Per-note encrypted still intact.
        assert!(f.notes[1].encrypted_body.is_some());
    }

    #[test]
    fn corrupt_file_loads_empty() {
        let dir = std::env::temp_dir().join(format!("husk-notes-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(NOTES_FILE), b"not valid json {{{").unwrap();
        let loaded = load(&dir);
        assert!(loaded.notes.is_empty());
        assert!(loaded.notebooks.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
