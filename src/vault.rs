// Password vault — Phase 1A + duress (Phase 3).
//
// On-disk format v2: `vault.husk` holds TWO encrypted blobs (real +
// duress). The duress blob exists EVEN WHEN the user hasn't configured
// a fake vault — in that case it's filled with random bytes that look
// indistinguishable from a real ciphertext under an unknown key. This
// is the plausible-deniability story: the file structure NEVER reveals
// whether a duress phrase has been set.
//
//   bytes  field
//   0..4   magic "HVLT"
//   4      version u8 (1 = legacy single-blob, 2 = dual-blob)
//   --- real blob ---
//   5      argon level u8 (real)
//   6..22  salt (16 bytes)
//   22..34 nonce (12 bytes)
//   34..38 ciphertext_len u32 LE   (v2 only — v1 had no length, read to EOF)
//   38..   ciphertext
//   --- duress blob (v2 only) ---
//   +0     argon level u8 (duress)
//   +1..17 salt (16 bytes)
//   +17..29 nonce (12 bytes)
//   +29..33 ciphertext_len u32 LE
//   +33..  ciphertext
//
// v1 vaults load fine: the read path detects version byte and either
// parses single-blob (v1) or dual-blob (v2). v1 vaults get auto-upgraded
// to v2 on the next save, with the duress slot filled with random bytes
// of plausible length. This makes "vault was created before duress
// existed" indistinguishable from "user just hasn't set duress yet".
//
// Argon2id derives a 32-byte key from the user's master phrase and the
// stored salt. Key lives in RAM only while the vault is unlocked, then
// is zeroized on lock / drop. Unlock tries the REAL blob first, then
// falls back to the duress blob — succeeding on EITHER produces an
// unlocked vault, with VaultManager.duress_mode flagging which one.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAGIC: &[u8; 4] = b"HVLT";
// Export blob magic — distinct from the local-vault magic so we
// refuse to import a malformed file into our vault (someone trying
// to overwrite vault.husk with a non-export blob would get a clear
// "not an export" error instead of mysterious failure modes).
const EXPORT_MAGIC: &[u8; 4] = b"HVLE";
const VERSION_V1: u8 = 1;
const VERSION_V2: u8 = 2;
const VERSION_V3: u8 = 3;
#[allow(dead_code)]
const VERSION: u8 = VERSION_V3;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
// v1 header: magic(4) + version(1) + argon(1) + salt(16) + nonce(12).
// Still used as-is for the export blob (HVLE) which kept the single-
// blob layout — duress doesn't apply to exports.
const HEADER_LEN: usize = 4 + 1 + 1 + SALT_LEN + NONCE_LEN; // 34
#[allow(dead_code)]
const V1_HEADER_LEN: usize = HEADER_LEN;
// v2 per-blob serialised size = argon(1) + salt(16) + nonce(12) + ct_len(4) + ct
const V2_BLOB_FIXED_LEN: usize = 1 + SALT_LEN + NONCE_LEN + 4;
// Every blob (real + every duress) is padded to this FIXED ciphertext
// size on disk. Why fixed (not stepped): with a step function, the
// real blob bumps to a new tier when content grows; existing configured
// duress slots stay at the old tier (we don't have their keys to
// repad). The size delta then re-reveals "this slot is stale" to a
// forensic examiner — same leak T1-H01 was originally about.
//
// 256 KiB easily covers any realistic credential vault (typical JSON
// is < 100 KiB even at thousands of entries). On-disk file ends up at
// ~512 KiB for a vault with one duress slot — trivial cost on modern
// storage in exchange for completely flattening the size signal.
//
// Plaintext padding is added as trailing whitespace to the JSON
// (JSON tolerates arbitrary trailing whitespace, so the deserialiser
// handles it without code changes). Duress placeholders are raw
// random bytes of length BLOB_FIXED_CT_LEN — indistinguishable from
// a real ciphertext under any external observation.
const AEAD_TAG_LEN: usize = 16;
const BLOB_FIXED_CT_LEN: usize = 256 * 1024;
const BLOB_FIXED_PT_LEN: usize = BLOB_FIXED_CT_LEN - AEAD_TAG_LEN;
// Legacy alias kept for back-compat references (encrypted profile
// re-uses similar reasoning; this constant is private so it's safe).
#[allow(dead_code)]
const DURESS_PAD_FLOOR: usize = BLOB_FIXED_CT_LEN;
// AEAD associated data — binds the ciphertext to "Husk vault v1" so an
// attacker can't take the bytes and reuse them in a different context
// where the same key+nonce pair might re-emerge.
const AEAD_AAD: &[u8] = b"husk-vault-v1";

#[derive(Debug)]
pub enum VaultError {
    Io(String),
    BadFormat(&'static str),
    WrongPhrase,
    Argon(String),
    Cipher(&'static str),
    Serde(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(s) => write!(f, "I/O error: {}", s),
            VaultError::BadFormat(s) => write!(f, "Vault file is corrupted or not a Husk vault ({})", s),
            VaultError::WrongPhrase => write!(f, "Wrong master phrase"),
            VaultError::Argon(s) => write!(f, "Key derivation failed: {}", s),
            VaultError::Cipher(s) => write!(f, "Cipher error: {}", s),
            VaultError::Serde(s) => write!(f, "Serialization error: {}", s),
        }
    }
}
impl std::error::Error for VaultError {}

// Argon2 cost level. MODERATE matches OWASP 2024 recommendation for
// password-encrypted local storage; SENSITIVE is for users who want to
// trade unlock latency for stronger brute-force resistance. We persist
// the *level* (not raw params) so a vault is portable across machines
// even if we change the underlying numbers in a later release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgonProfile {
    Moderate,
    Sensitive,
}

impl ArgonProfile {
    fn as_byte(self) -> u8 {
        match self {
            ArgonProfile::Moderate => 0,
            ArgonProfile::Sensitive => 1,
        }
    }
    fn from_byte(b: u8) -> Result<Self, VaultError> {
        match b {
            0 => Ok(ArgonProfile::Moderate),
            1 => Ok(ArgonProfile::Sensitive),
            _ => Err(VaultError::BadFormat("unknown argon profile")),
        }
    }
    // (memory_kb, time_cost, lanes)
    fn params(self) -> (u32, u32, u32) {
        match self {
            // ~300-500ms on a 2024 laptop, 256 MB. OWASP-recommended.
            ArgonProfile::Moderate => (256 * 1024, 3, 1),
            // ~1-3s, 1 GB. Paranoia tier; resists GPU/ASIC much better
            // but lock/unlock becomes a perceptible chore.
            ArgonProfile::Sensitive => (1024 * 1024, 4, 1),
        }
    }
}

// 32-byte symmetric key wiped on drop. We rely on `zeroize` rather than
// just letting `[u8; 32]` go out of scope because Rust may keep stale
// bytes on the stack indefinitely — zeroize compiles to a volatile
// memset that the optimizer can't elide.
#[derive(Zeroize, ZeroizeOnDrop)]
struct MasterKey([u8; KEY_LEN]);

fn derive_key(phrase: &str, salt: &[u8], profile: ArgonProfile) -> Result<MasterKey, VaultError> {
    let (mem_kb, time_cost, lanes) = profile.params();
    let params = Params::new(mem_kb, time_cost, lanes, Some(KEY_LEN))
        .map_err(|e| VaultError::Argon(format!("{:?}", e)))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(phrase.as_bytes(), salt, &mut out)
        .map_err(|e| VaultError::Argon(format!("{:?}", e)))?;
    Ok(MasterKey(out))
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

// One credential entry. Free-form `notes` field for arbitrary plaintext
// (e.g. recovery codes, security questions). `tags` is reserved for v1.5+
// search filtering — empty for now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: u64,
    pub parent: Option<u64>,
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    // Unix epoch secs — used by the sidebar to surface "recently added".
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    // Float so reorder can insert between two existing siblings without
    // renumbering — new_order = (prev.order + next.order) / 2. Default
    // 0.0 means legacy items added before this field existed; they get
    // their order re-assigned on first reorder pass.
    #[serde(default)]
    pub order: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFolder {
    pub id: u64,
    pub parent: Option<u64>,
    pub name: String,
    #[serde(default)]
    pub order: f64,
}

// Flat list of nodes with explicit parent pointers (vs. nested children)
// makes mutation simple: no recursion, ids are stable across edits, the
// JS tree builder just groups by `parent`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultTree {
    #[serde(default)]
    pub folders: Vec<VaultFolder>,
    #[serde(default)]
    pub items: Vec<VaultItem>,
    #[serde(default = "default_next_id")]
    pub next_id: u64,
}

fn default_next_id() -> u64 {
    1
}

impl VaultTree {
    /// Overwrite every secret-bearing field with zero bytes BEFORE
    /// the tree is dropped / replaced. `String::clear()` would only
    /// reset the length — the bytes stay in the heap allocator's
    /// free list, where co-resident malware reading Husk's memory
    /// (the threat model explicitly lists this attacker class)
    /// could lift them well after lock(). Audit T1-M03 / T1-L09.
    pub fn zeroize_in_place(&mut self) {
        use zeroize::Zeroize;
        for item in self.items.iter_mut() {
            // Zeroize the underlying Vec<u8> of each String. Safe
            // because we drop the String right after — the
            // invariant that contents are valid UTF-8 only matters
            // for code that READS the string afterwards.
            unsafe {
                item.password.as_mut_vec().zeroize();
                item.notes.as_mut_vec().zeroize();
                item.username.as_mut_vec().zeroize();
                item.name.as_mut_vec().zeroize();
            }
            item.password.clear();
            item.notes.clear();
            item.username.clear();
            item.name.clear();
        }
        for folder in self.folders.iter_mut() {
            unsafe { folder.name.as_mut_vec().zeroize(); }
            folder.name.clear();
        }
    }

    pub fn fresh_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    /// Overwrite every item's password with a fresh random 16-char
    /// string. Used by the duress setup flow when cloning the real
    /// vault into a decoy: same URLs + usernames (makes the fake feel
    /// populated and credible) but useless passwords. `notes` is
    /// preserved by default — clearing it would make the decoy feel
    /// hollow; users who store sensitive data in notes can clear them
    /// manually after setup.
    pub fn replace_all_passwords_with_random(&mut self) {
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
        for item in self.items.iter_mut() {
            let mut buf = [0u8; 16];
            OsRng.fill_bytes(&mut buf);
            let new_pw: String = buf
                .iter()
                .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
                .collect();
            item.password = new_pw;
        }
    }

    // Returns the highest `order` across all children of `parent`
    // (folders + items together — we want a unified rank space so a
    // folder can sit between two items if the user reorders that way).
    fn max_order_for(&self, parent: Option<u64>) -> f64 {
        let mut max = 0.0_f64;
        for f in self.folders.iter().filter(|f| f.parent == parent) {
            if f.order > max { max = f.order; }
        }
        for i in self.items.iter().filter(|i| i.parent == parent) {
            if i.order > max { max = i.order; }
        }
        max
    }

    pub fn add_folder(&mut self, name: &str, parent: Option<u64>) -> u64 {
        let id = self.fresh_id();
        let order = self.max_order_for(parent) + 1000.0;
        self.folders.push(VaultFolder {
            id,
            parent,
            name: name.to_string(),
            order,
        });
        id
    }

    pub fn add_item(&mut self, name: &str, parent: Option<u64>) -> u64 {
        let id = self.fresh_id();
        let now = now_secs();
        let order = self.max_order_for(parent) + 1000.0;
        self.items.push(VaultItem {
            id,
            parent,
            name: name.to_string(),
            url: String::new(),
            username: String::new(),
            password: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
            order,
        });
        id
    }

    pub fn update_item(&mut self, id: u64, mutate: impl FnOnce(&mut VaultItem)) -> bool {
        if let Some(it) = self.items.iter_mut().find(|i| i.id == id) {
            mutate(it);
            it.updated_at = now_secs();
            true
        } else {
            false
        }
    }

    pub fn rename_folder(&mut self, id: u64, new_name: &str) -> bool {
        if let Some(f) = self.folders.iter_mut().find(|f| f.id == id) {
            f.name = new_name.to_string();
            true
        } else {
            false
        }
    }

    // Move a folder or item under a new parent. `new_parent = None`
    // moves to root. `before` (when Some) names a sibling under
    // new_parent — the moved node is positioned just before it
    // (allowing reorder above the first child). When `before = None`,
    // the node lands at the end of new_parent's children.
    //
    // Refuses the operation if:
    //   - id doesn't exist
    //   - new_parent is set but doesn't refer to an existing folder
    //   - id is a folder and new_parent is the same folder or one of
    //     its descendants (would create a cycle / unreachable subtree)
    //   - before is set but doesn't share new_parent
    // Returns true if the move actually changed something.
    pub fn move_node(
        &mut self,
        id: u64,
        new_parent: Option<u64>,
        before: Option<u64>,
    ) -> bool {
        // Validate target — must be either None (root) or an existing folder.
        if let Some(pid) = new_parent {
            if !self.folders.iter().any(|f| f.id == pid) {
                return false;
            }
            // Cycle check: if id is a folder, walk down its descendants
            // and refuse if pid is among them (or equals id itself).
            if pid == id {
                return false;
            }
            if self.folders.iter().any(|f| f.id == id) {
                let mut descendants: Vec<u64> = Vec::new();
                let mut frontier: Vec<u64> = vec![id];
                while let Some(cur) = frontier.pop() {
                    for f in self.folders.iter().filter(|f| f.parent == Some(cur)) {
                        descendants.push(f.id);
                        frontier.push(f.id);
                    }
                }
                if descendants.contains(&pid) {
                    return false;
                }
            }
        }
        // Validate `before`: must share new_parent and not equal id.
        if let Some(bid) = before {
            if bid == id { return false; }
            let bparent = self.parent_of(bid);
            if bparent != Some(new_parent) {
                // Either `bid` doesn't exist (None outer) or has a
                // different parent. Either way, reject — JS shouldn't
                // ever send this combination, but defense-in-depth.
                return false;
            }
        }

        // Compute target order: between `before`'s order and the order
        // of the sibling immediately preceding it (or 0 if before is
        // the first sibling). If `before` is None, target = max+1000.
        let target_order = self.compute_target_order(new_parent, before);

        // Apply parent + order in one pass to keep the tree consistent.
        if let Some(f) = self.folders.iter_mut().find(|f| f.id == id) {
            let unchanged = f.parent == new_parent && (f.order - target_order).abs() < 1e-9;
            if unchanged { return false; }
            f.parent = new_parent;
            f.order = target_order;
            return true;
        }
        if let Some(it) = self.items.iter_mut().find(|i| i.id == id) {
            let unchanged = it.parent == new_parent && (it.order - target_order).abs() < 1e-9;
            if unchanged { return false; }
            it.parent = new_parent;
            it.order = target_order;
            it.updated_at = now_secs();
            return true;
        }
        false
    }

    // Lookup helper. Returns Some(parent_option) wrapping the parent
    // value if `id` exists. None outer means the id wasn't found in
    // either folders or items.
    fn parent_of(&self, id: u64) -> Option<Option<u64>> {
        if let Some(f) = self.folders.iter().find(|f| f.id == id) {
            return Some(f.parent);
        }
        if let Some(it) = self.items.iter().find(|i| i.id == id) {
            return Some(it.parent);
        }
        None
    }

    // Returns the float order to give a node being inserted into
    // `parent` immediately before `before`. When `before = None`, the
    // node lands at the end (max_order + 1000). When inserting between
    // two siblings, we take the midpoint of their orders.
    fn compute_target_order(&self, parent: Option<u64>, before: Option<u64>) -> f64 {
        let Some(before_id) = before else {
            return self.max_order_for(parent) + 1000.0;
        };
        // Collect siblings (excluding the one being moved — well, we
        // don't have its id here, but the move applies AFTER this calc
        // so the moved node's old order is still in the list, fine).
        let mut siblings: Vec<f64> = Vec::new();
        for f in self.folders.iter().filter(|f| f.parent == parent) {
            siblings.push(f.order);
        }
        for i in self.items.iter().filter(|i| i.parent == parent) {
            siblings.push(i.order);
        }
        // Sort ascending so we can find the predecessor of `before`.
        // partial_cmp because f64 isn't Ord (NaN). We never produce NaN
        // ourselves so unwrap_or Equal is fine.
        siblings.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let before_order = self
            .folders
            .iter()
            .find(|f| f.id == before_id)
            .map(|f| f.order)
            .or_else(|| self.items.iter().find(|i| i.id == before_id).map(|i| i.order))
            .unwrap_or(1000.0);
        let prev = siblings
            .iter()
            .copied()
            .filter(|o| *o < before_order)
            .fold(f64::NEG_INFINITY, f64::max);
        if prev == f64::NEG_INFINITY {
            // before is the first sibling — insert above it.
            before_order / 2.0
        } else {
            (prev + before_order) / 2.0
        }
    }

    // Delete a node and (for folders) all descendants. Iterative walk
    // because recursion on user data is a footgun — a deep folder tree
    // shouldn't be able to blow the stack.
    pub fn delete_node(&mut self, id: u64) -> bool {
        // Collect all folder ids transitively under `id`.
        let mut to_kill_folders: Vec<u64> = vec![id];
        let mut frontier: Vec<u64> = vec![id];
        while let Some(cur) = frontier.pop() {
            for f in self.folders.iter().filter(|f| f.parent == Some(cur)) {
                to_kill_folders.push(f.id);
                frontier.push(f.id);
            }
        }
        let killed_folders = self.folders.len();
        let killed_items = self.items.len();
        self.folders.retain(|f| !to_kill_folders.contains(&f.id));
        self.items.retain(|i| {
            !to_kill_folders.contains(&i.id)
                && !to_kill_folders
                    .iter()
                    .any(|fid| i.parent == Some(*fid))
        });
        // Also kill an item that was the direct target.
        self.items.retain(|i| i.id != id);
        killed_folders != self.folders.len() || killed_items != self.items.len()
    }

    // Build a self-contained VaultTree rooted at `root_id`. Returns
    // None if the id doesn't exist. The returned tree's root node has
    // `parent: None` so it imports as a top-level entry under the
    // recipient's wrapper folder. Used by the per-node export action.
    pub fn extract_subtree(&self, root_id: u64) -> Option<VaultTree> {
        let mut out = VaultTree::default();
        out.next_id = self.next_id;

        // Item-rooted export: just the one item, parent dropped.
        if let Some(it) = self.items.iter().find(|i| i.id == root_id) {
            let mut clone = it.clone();
            clone.parent = None;
            out.items.push(clone);
            return Some(out);
        }

        // Folder-rooted: collect all descendant folder ids first, then
        // pull every folder/item whose parent chain leads back to root.
        if !self.folders.iter().any(|f| f.id == root_id) {
            return None;
        }
        let mut include: Vec<u64> = vec![root_id];
        let mut frontier: Vec<u64> = vec![root_id];
        while let Some(cur) = frontier.pop() {
            for f in self.folders.iter().filter(|f| f.parent == Some(cur)) {
                include.push(f.id);
                frontier.push(f.id);
            }
        }
        for f in &self.folders {
            if include.contains(&f.id) {
                let mut clone = f.clone();
                if clone.id == root_id {
                    clone.parent = None;
                }
                out.folders.push(clone);
            }
        }
        for it in &self.items {
            if it.parent.map_or(false, |pid| include.contains(&pid)) {
                out.items.push(it.clone());
            }
        }
        Some(out)
    }

    pub fn find_for_origin(&self, origin: &str) -> Vec<&VaultItem> {
        let host = parse_host(origin).unwrap_or_default();
        if host.is_empty() {
            return Vec::new();
        }
        self.items
            .iter()
            .filter(|it| {
                let h = parse_host(&it.url).unwrap_or_default();
                // host_matches(page, stored): the page we're visiting may
                // be a subdomain of the stored URL. e.g. stored="google.com"
                // matches page="accounts.google.com". Pass page first.
                !h.is_empty() && host_matches(&host, &h)
            })
            .collect()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// "https://accounts.google.com/signin" → "accounts.google.com". Strips
// scheme + path + port; ASCII-lowercased so case mismatches don't miss.
fn parse_host(url_str: &str) -> Option<String> {
    let u = ::url::Url::parse(url_str).ok()?;
    Some(u.host_str()?.to_ascii_lowercase())
}

// Domain-suffix match: "accounts.google.com" matches a stored
// "google.com" entry. Strict equality first to keep the common case
// fast; suffix walk handles subdomains. We require a leading "." so
// that "evil-google.com" doesn't match "google.com".
fn host_matches(page_host: &str, stored_host: &str) -> bool {
    if page_host == stored_host {
        return true;
    }
    if page_host.len() > stored_host.len() {
        let tail = &page_host[page_host.len() - stored_host.len() - 1..];
        if tail.starts_with('.') && &tail[1..] == stored_host {
            return true;
        }
    }
    false
}

// One encrypted blob inside the vault file. The vault file holds two
// of these (real + duress) in v2; v1 had only one and gets auto-
// upgraded on the next save.
#[derive(Clone)]
pub struct VaultFileHeader {
    pub profile: ArgonProfile,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// A complete on-disk vault file. One real blob + N duress blobs.
/// Every "Set up a fake vault" action APPENDS to `duress` rather than
/// replacing — so every previously-configured fake phrase keeps
/// working. This is what makes the "attacker tests by setting up
/// their own fake" scenario safe: user can still type their original
/// fake phrase later and land on the same fake content the attacker
/// already inspected.
///
/// A freshly-created vault starts with one random-placeholder duress
/// blob (so the file shape doesn't reveal "user hasn't configured a
/// fake"). v1/v2 read paths upgrade to this layout transparently.
pub struct VaultFile {
    pub real: VaultFileHeader,
    pub duress: Vec<VaultFileHeader>,
}

impl VaultFile {
    /// Parse `vault.husk` bytes. Tolerates:
    ///   v1: single blob → synthesise one random duress placeholder
    ///   v2: real + ONE duress blob → wrap in single-element Vec
    ///   v3: real + duress_count u8 + N duress blobs
    /// Wrong magic / version / truncation → BadFormat.
    fn read(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < HEADER_LEN {
            return Err(VaultError::BadFormat("file shorter than header"));
        }
        if &bytes[0..4] != MAGIC {
            return Err(VaultError::BadFormat("magic mismatch"));
        }
        let version = bytes[4];
        match version {
            VERSION_V1 => {
                let real = VaultFileHeader::read_v1_after_header(&bytes[5..])?;
                let placeholder =
                    VaultFileHeader::random_placeholder(real.ciphertext.len());
                Ok(VaultFile { real, duress: vec![placeholder] })
            }
            VERSION_V2 => {
                let (real, after_real) = VaultFileHeader::read_v2_blob(&bytes[5..])?;
                let (duress0, _rest) = VaultFileHeader::read_v2_blob(after_real)?;
                Ok(VaultFile { real, duress: vec![duress0] })
            }
            VERSION_V3 => {
                let (real, after_real) = VaultFileHeader::read_v2_blob(&bytes[5..])?;
                if after_real.is_empty() {
                    return Err(VaultError::BadFormat("v3 missing duress count"));
                }
                let count = after_real[0] as usize;
                let mut cursor = &after_real[1..];
                let mut duress = Vec::with_capacity(count);
                for _ in 0..count {
                    let (blob, rest) = VaultFileHeader::read_v2_blob(cursor)?;
                    duress.push(blob);
                    cursor = rest;
                }
                if duress.is_empty() {
                    // Treat zero-blob files as malformed — every vault
                    // should ship at least one placeholder duress slot
                    // so the file shape doesn't reveal "fake never set".
                    let placeholder =
                        VaultFileHeader::random_placeholder(real.ciphertext.len());
                    duress.push(placeholder);
                }
                Ok(VaultFile { real, duress })
            }
            _ => Err(VaultError::BadFormat("unsupported version")),
        }
    }

    /// Serialise as v3 (magic + version=3 + real-blob + duress_count + N duress blobs).
    fn write(&self) -> Vec<u8> {
        let est = 4 + 1 + V2_BLOB_FIXED_LEN + self.real.ciphertext.len() + 1
            + self.duress.iter().map(|b| V2_BLOB_FIXED_LEN + b.ciphertext.len()).sum::<usize>();
        let mut buf = Vec::with_capacity(est);
        buf.extend_from_slice(MAGIC);
        buf.push(VERSION_V3);
        self.real.write_v2_blob_into(&mut buf);
        // Cap the count at 255 — that's more decoys than any realistic
        // user will ever configure, and keeping the count as u8 lets us
        // stay byte-compact for the file-size-matters threat model.
        let count = self.duress.len().min(255) as u8;
        buf.push(count);
        for blob in self.duress.iter().take(count as usize) {
            blob.write_v2_blob_into(&mut buf);
        }
        buf
    }
}

impl VaultFileHeader {
    /// Parse a v1 file body (the bytes AFTER the version byte). Layout:
    /// argon(1) + salt(SALT_LEN) + nonce(NONCE_LEN) + ciphertext(to EOF).
    fn read_v1_after_header(bytes: &[u8]) -> Result<Self, VaultError> {
        // 1 + SALT_LEN + NONCE_LEN = 29
        if bytes.len() < 1 + SALT_LEN + NONCE_LEN {
            return Err(VaultError::BadFormat("v1 body shorter than header"));
        }
        let profile = ArgonProfile::from_byte(bytes[0])?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[1..1 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN]);
        let ciphertext = bytes[1 + SALT_LEN + NONCE_LEN..].to_vec();
        Ok(VaultFileHeader { profile, salt, nonce, ciphertext })
    }

    /// Parse a v2 blob starting at `bytes`. Returns the blob + the
    /// remaining bytes (so the caller can chain to the next blob).
    fn read_v2_blob(bytes: &[u8]) -> Result<(Self, &[u8]), VaultError> {
        if bytes.len() < V2_BLOB_FIXED_LEN {
            return Err(VaultError::BadFormat("v2 blob truncated"));
        }
        let profile = ArgonProfile::from_byte(bytes[0])?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[1..1 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN]);
        let ct_len_off = 1 + SALT_LEN + NONCE_LEN;
        let ct_len = u32::from_le_bytes([
            bytes[ct_len_off],
            bytes[ct_len_off + 1],
            bytes[ct_len_off + 2],
            bytes[ct_len_off + 3],
        ]) as usize;
        let ct_off = V2_BLOB_FIXED_LEN;
        if bytes.len() < ct_off + ct_len {
            return Err(VaultError::BadFormat("v2 ciphertext truncated"));
        }
        let ciphertext = bytes[ct_off..ct_off + ct_len].to_vec();
        Ok((
            VaultFileHeader { profile, salt, nonce, ciphertext },
            &bytes[ct_off + ct_len..],
        ))
    }

    fn write_v2_blob_into(&self, buf: &mut Vec<u8>) {
        buf.push(self.profile.as_byte());
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);
    }

    /// Build a duress-slot placeholder: random salt, nonce, and ciphertext
    /// of BLOB_FIXED_CT_LEN bytes. No phrase will ever decrypt this —
    /// it's indistinguishable from a real duress blob whose phrase the
    /// attacker doesn't know. Used when upgrading v1 → v2 OR when the
    /// user creates a fresh vault without configuring duress.
    ///
    /// `_mirror_len` parameter retained for API back-compat but ignored:
    /// every blob is now the same fixed size on disk. See
    /// BLOB_FIXED_CT_LEN for the size rationale.
    fn random_placeholder(_mirror_len: usize) -> Self {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mut ciphertext = vec![0u8; BLOB_FIXED_CT_LEN];
        OsRng.fill_bytes(&mut ciphertext);
        VaultFileHeader {
            profile: ArgonProfile::Moderate,
            salt,
            nonce,
            ciphertext,
        }
    }
}

/// Pad a JSON plaintext with trailing spaces so the AEAD ciphertext
/// always ends up exactly BLOB_FIXED_CT_LEN bytes on disk. Vault
/// content significantly under the limit gets a lot of padding;
/// content over the limit is rejected (in practice the limit covers
/// thousands of credentials).
fn pad_plaintext_for_save(json: &mut Vec<u8>) -> Result<(), VaultError> {
    if json.len() > BLOB_FIXED_PT_LEN {
        return Err(VaultError::Cipher(
            "vault content exceeds fixed blob size — too many entries",
        ));
    }
    json.resize(BLOB_FIXED_PT_LEN, b' ');
    Ok(())
}

#[allow(dead_code)]
impl VaultFileHeader {
    fn _legacy_v1_write_unused(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        buf.extend_from_slice(MAGIC);
        buf.push(VERSION_V1);
        buf.push(self.profile.as_byte());
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }
}

// Runtime state. When `key` is Some, the vault is unlocked and `tree`
// holds the live data. When `key` is None, only the on-disk file
// (both blobs) is in memory; the tree itself isn't touched until the
// user provides a phrase. The phrase matches EITHER the real blob OR
// the duress blob — `duress_mode` flags which one.
pub struct VaultManager {
    locked_file: Option<VaultFile>,
    key: Option<MasterKey>,
    salt: [u8; SALT_LEN],
    profile: ArgonProfile,
    tree: VaultTree,
    dirty: bool,
    /// True when the currently-unlocked vault is one of the DURESS
    /// views (not the real). Drives the user-only visual marker in
    /// chrome (subtle stripe) and tells `save` which blob to rewrite.
    duress_mode: bool,
    /// When `duress_mode` is true, the index inside `locked_file.duress`
    /// that's currently unlocked. Set so `save` writes back to the
    /// right slot and append-on-setup creates a NEW slot rather than
    /// clobbering the current one.
    duress_idx: Option<usize>,
    /// True if the user has actively configured at least one duress
    /// phrase this session. Random placeholders don't count. We only
    /// track this in-memory; the on-disk file can't reveal "duress is
    /// configured" without leaking the user's setup.
    duress_configured: bool,
}

impl VaultManager {
    // Load a vault file from disk into the "locked" state. If the file
    // doesn't exist yet, returns a placeholder VaultManager that the UI
    // can fill via `create(phrase, profile)`.
    pub fn load_or_empty(path: &Path) -> Result<Self, VaultError> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let file = VaultFile::read(&bytes)?;
                Ok(VaultManager {
                    salt: file.real.salt,
                    profile: file.real.profile,
                    locked_file: Some(file),
                    key: None,
                    tree: VaultTree::default(),
                    dirty: false,
                    duress_mode: false,
                    duress_idx: None,
                    duress_configured: false,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(VaultManager {
                locked_file: None,
                key: None,
                salt: [0u8; SALT_LEN],
                profile: ArgonProfile::Moderate,
                tree: VaultTree::default(),
                dirty: false,
                duress_mode: false,
                duress_idx: None,
                duress_configured: false,
            }),
            Err(e) => Err(VaultError::Io(e.to_string())),
        }
    }

    /// True if the vault is currently unlocked via the duress phrase.
    /// Exposed so chrome can render the user-only marker.
    pub fn is_duress_mode(&self) -> bool {
        self.duress_mode
    }

    /// True when the user has actively configured a duress phrase (vs
    /// a random placeholder). Doesn't tell the chrome anything about
    /// WHICH mode is unlocked — just whether the feature is set up.
    pub fn has_duress(&self) -> bool {
        self.duress_configured
    }

    pub fn exists(&self) -> bool {
        self.locked_file.is_some()
    }

    pub fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }

    // First-time setup. Generates a fresh salt + nonce, derives the
    // master key, writes an empty tree. After this returns, the vault
    // is unlocked and `save_if_dirty` will persist on the next call.
    pub fn create(
        &mut self,
        path: &Path,
        phrase: &str,
        profile: ArgonProfile,
    ) -> Result<(), VaultError> {
        if phrase.is_empty() {
            return Err(VaultError::WrongPhrase);
        }
        self.salt = random_bytes::<SALT_LEN>();
        self.profile = profile;
        let key = derive_key(phrase, &self.salt, profile)?;
        self.key = Some(key);
        self.tree = VaultTree::default();
        self.tree.next_id = 1;
        self.dirty = true;
        self.save(path)?;
        // After save: dirty cleared, locked_header populated.
        Ok(())
    }

    // Verify a phrase against the stored blobs and, on success, hold
    // the derived key + decrypt the tree into memory. Tries the REAL
    // blob first, then the DURESS blob — succeeding on either is a
    // valid unlock (with `duress_mode` flagging which).
    //
    // Wrong phrase against BOTH yields `WrongPhrase` — same UX no
    // matter whether real, duress, or "neither + corrupt placeholder"
    // failed. Critically, this means an attacker who tries the
    // duress phrase against a vault that DOESN'T have one configured
    // sees the SAME error as a wrong real phrase — no information
    // about whether duress is set up leaks through unlock attempts.
    pub fn unlock(&mut self, phrase: &str) -> Result<(), VaultError> {
        let file = self
            .locked_file
            .as_ref()
            .ok_or(VaultError::BadFormat("no vault on disk"))?;
        // Try real first.
        if let Ok((tree, key)) = Self::try_decrypt_blob(&file.real, phrase) {
            self.key = Some(key);
            self.salt = file.real.salt;
            self.profile = file.real.profile;
            self.tree = tree;
            self.dirty = false;
            self.duress_mode = false;
            self.duress_idx = None;
            return Ok(());
        }
        // Real failed — iterate every duress blob in order. First match wins.
        for (idx, blob) in file.duress.iter().enumerate() {
            if let Ok((tree, key)) = Self::try_decrypt_blob(blob, phrase) {
                self.key = Some(key);
                self.salt = blob.salt;
                self.profile = blob.profile;
                self.tree = tree;
                self.dirty = false;
                self.duress_mode = true;
                self.duress_idx = Some(idx);
                // Successful decrypt proves at least one duress slot was
                // actually configured (random placeholders never decrypt).
                self.duress_configured = true;
                return Ok(());
            }
        }
        Err(VaultError::WrongPhrase)
    }

    // Internal helper: derive key from phrase + try to decrypt one
    // blob. Returns the tree + the derived key on success. Wrong phrase
    // (or random-bytes placeholder) → Err.
    fn try_decrypt_blob(
        blob: &VaultFileHeader,
        phrase: &str,
    ) -> Result<(VaultTree, MasterKey), VaultError> {
        let key = derive_key(phrase, &blob.salt, blob.profile)?;
        let cipher = ChaCha20Poly1305::new(key.0[..].into());
        let mut buf = blob.ciphertext.clone();
        cipher
            .decrypt_in_place(&blob.nonce.into(), AEAD_AAD, &mut buf)
            .map_err(|_| VaultError::WrongPhrase)?;
        let tree: VaultTree =
            serde_json::from_slice(&buf).map_err(|_| VaultError::WrongPhrase)?;
        buf.zeroize();
        Ok((tree, key))
    }

    // Drop the master key + clear the in-memory tree. Persists anything
    // pending first (we don't lose user edits even if they don't manually
    // save between mutations — `dirty` is set after every mutation).
    pub fn lock(&mut self, path: &Path) -> Result<(), VaultError> {
        if self.dirty {
            self.save(path)?;
        }
        // key drops here → zeroized via ZeroizeOnDrop. The tree's
        // password strings are zeroized in place BEFORE replacing
        // with default; otherwise their bytes linger in the heap
        // allocator's free list, recoverable by co-resident malware
        // (Husk's stated threat model). Audit T1-M03 / T1-L09.
        self.key = None;
        self.tree.zeroize_in_place();
        self.tree = VaultTree::default();
        self.duress_mode = false;
        Ok(())
    }

    fn save(&mut self, path: &Path) -> Result<(), VaultError> {
        let Some(key) = self.key.as_ref() else {
            return Err(VaultError::Cipher("vault is locked"));
        };
        let mut plaintext =
            serde_json::to_vec(&self.tree).map_err(|e| VaultError::Serde(e.to_string()))?;
        // Pad to the fixed blob size so every save lands at the same
        // on-disk length, indistinguishable from any duress slot or
        // placeholder. See BLOB_FIXED_CT_LEN.
        pad_plaintext_for_save(&mut plaintext)?;
        let nonce = random_bytes::<NONCE_LEN>();
        let cipher = ChaCha20Poly1305::new(key.0[..].into());
        let mut buf = plaintext;
        cipher
            .encrypt_in_place(&nonce.into(), AEAD_AAD, &mut buf)
            .map_err(|_| VaultError::Cipher("encrypt failed"))?;
        let active_blob = VaultFileHeader {
            profile: self.profile,
            salt: self.salt,
            nonce,
            ciphertext: buf,
        };
        // Compose the on-disk file with both blobs. The blob NOT
        // currently unlocked is preserved verbatim from disk (we don't
        // re-derive its key — we don't have its phrase). For a vault
        // that's never had duress configured, the duress slot holds
        // random bytes; that's preserved too, looking identical to an
        // unused real slot to any outside observer.
        let file = match (self.locked_file.take(), self.duress_mode, self.duress_idx) {
            (Some(mut prev), false, _) => {
                // Real unlock: overwrite real, keep every duress intact.
                // All blobs (including duress) are already padded to the
                // same fixed on-disk length, so the size signal that
                // motivated T1-H01 simply can't exist any more.
                prev.real = active_blob;
                prev
            }
            (Some(mut prev), true, Some(idx)) if idx < prev.duress.len() => {
                // Duress unlock: overwrite ONLY the active duress slot,
                // keep real + every OTHER duress intact (so previously
                // configured fake phrases still unlock their content).
                prev.duress[idx] = active_blob;
                prev
            }
            (Some(mut prev), true, _) => {
                // Duress index out of range or missing — shouldn't
                // happen post-unlock but recover by appending.
                prev.duress.push(active_blob);
                self.duress_idx = Some(prev.duress.len() - 1);
                prev
            }
            (None, _, _) => {
                // Fresh vault. Spawn a random-placeholder duress slot
                // so the brand-new file already has the multi-blob shape.
                let placeholder =
                    VaultFileHeader::random_placeholder(active_blob.ciphertext.len());
                VaultFile { real: active_blob, duress: vec![placeholder] }
            }
        };
        let on_disk = file.write();
        // Write to a temp file then rename — atomic on Win32 NTFS as long
        // as the rename target is on the same volume (it is, both in our
        // data root). Prevents a torn write from corrupting the vault.
        let tmp = path.with_extension("husk.tmp");
        std::fs::write(&tmp, &on_disk).map_err(|e| VaultError::Io(e.to_string()))?;
        std::fs::rename(&tmp, path).map_err(|e| VaultError::Io(e.to_string()))?;
        self.locked_file = Some(file);
        self.dirty = false;
        Ok(())
    }

    pub fn save_if_dirty(&mut self, path: &Path) -> Result<(), VaultError> {
        if self.dirty {
            self.save(path)?;
        }
        Ok(())
    }

    /// Change the master phrase of the currently-unlocked vault. Works
    /// for either mode: when unlocked via the real phrase, this
    /// rotates the real blob's key; when unlocked via the duress
    /// phrase, it rotates only the duress blob. The OTHER blob is
    /// preserved verbatim — its phrase isn't known to us in this
    /// session.
    ///
    /// We do NOT require the old phrase: the user already proved they
    /// knew it by unlocking. Empty new phrase = WrongPhrase (treat as
    /// guardrail, not actual "wrong" semantics).
    pub fn change_phrase(&mut self, path: &Path, new_phrase: &str) -> Result<(), VaultError> {
        if new_phrase.is_empty() {
            return Err(VaultError::WrongPhrase);
        }
        if self.key.is_none() {
            return Err(VaultError::Cipher("vault is locked"));
        }
        // Fresh salt + key derived from the new phrase. The Argon2
        // profile stays the same as the current session — changing
        // cost level would surprise the user (re-unlock would feel
        // suddenly slower / faster).
        let new_salt = random_bytes::<SALT_LEN>();
        let new_key = derive_key(new_phrase, &new_salt, self.profile)?;
        self.salt = new_salt;
        self.key = Some(new_key);
        self.dirty = true;
        // Persist immediately so the new phrase takes effect even if
        // the user doesn't make any other mutation in this session.
        self.save(path)?;
        Ok(())
    }

    /// Configure (or reconfigure) the duress phrase. Requires the
    /// vault to be currently unlocked in REAL mode — duress can only
    /// be set up from the legitimate session. The decoy tree starts
    /// either empty (`copy_from_real = false`) or cloned from the
    /// real tree with every password replaced by a fresh random
    /// 16-char string (`copy_from_real = true`). Cloning makes the
    /// fake feel populated to an attacker but exposes no real creds.
    ///
    /// Errors if the supplied phrase matches the real one — the two
    /// MUST be different, otherwise `unlock()` would never reach the
    /// duress path.
    pub fn setup_duress(
        &mut self,
        path: &Path,
        phrase: &str,
        copy_from_real: bool,
    ) -> Result<(), VaultError> {
        if phrase.is_empty() {
            return Err(VaultError::WrongPhrase);
        }
        // NOTE: allowed from BOTH real and fake modes by design.
        //   - Real mode: standard setup or replace of the fake config.
        //   - Fake mode: REPLACES the existing fake blob with a fresh
        //     configuration. The REAL blob stays untouched (we don't
        //     have its key in this session). This is the "fake-of-fake"
        //     escape hatch: an attacker who tests Husk by trying to
        //     "set up a fake from this vault" creates yet another
        //     decoy without ever learning whether they're in the real
        //     or fake one — they just replace whatever fake exists.
        let active_key = self
            .key
            .as_ref()
            .ok_or(VaultError::Cipher("vault is locked"))?;
        // Reject if the new phrase decrypts any EXISTING blob — real
        // OR any duress slot. Without this cross-blob check, a user
        // in fake mode could set up a new fake with a phrase that
        // happens to equal the REAL phrase (we wouldn't notice because
        // we only have the fake key here). Their next "fake" unlock
        // would then surface the REAL vault. The audit (T1-H07)
        // flagged that the previous check, which compared keys
        // derived from `self.salt`, only covered the currently-active
        // blob. We now trial-decrypt every blob in the file.
        if let Some(file) = self.locked_file.as_ref() {
            let candidates: Vec<&VaultFileHeader> = std::iter::once(&file.real)
                .chain(file.duress.iter())
                .collect();
            for blob in candidates {
                // Derive the candidate key with THIS blob's argon
                // profile and salt — that's the only thing that could
                // possibly decrypt it.
                let probe = derive_key(phrase, &blob.salt, blob.profile)?;
                let cipher = ChaCha20Poly1305::new(probe.0[..].into());
                let mut ct = blob.ciphertext.clone();
                if cipher
                    .decrypt_in_place(&blob.nonce.into(), AEAD_AAD, &mut ct)
                    .is_ok()
                {
                    return Err(VaultError::Cipher(
                        "phrase already unlocks another vault slot — pick a different one",
                    ));
                }
            }
        }
        // Additional sanity check kept for back-compat: catch the
        // unlikely case where new salt happens to equal `self.salt`.
        let duress_test_key = derive_key(phrase, &self.salt, self.profile)?;
        if duress_test_key.0 == active_key.0 {
            return Err(VaultError::Cipher(
                "phrase derives the same key as the current vault — pick a different one",
            ));
        }
        drop(duress_test_key);

        // Build the decoy tree.
        let mut decoy_tree = if copy_from_real {
            let mut t = self.tree.clone();
            // Replace every item's password with a random 16-char string.
            // URLs + usernames stay (makes the decoy plausible — same
            // sites the user would actually visit). Notes stay too —
            // they're rarely sensitive on their own, and clearing them
            // would make the fake feel hollow.
            t.replace_all_passwords_with_random();
            t
        } else {
            let mut t = VaultTree::default();
            t.next_id = 1;
            t
        };
        // Bump next_id so a fresh save doesn't collide with the cloned
        // ids (the decoy lives in a separate ciphertext so id
        // collisions across vaults don't matter, but keep it tidy).
        let _ = &mut decoy_tree;

        // Derive a fresh salt for the duress key. Critical: never reuse
        // the real salt — that would let an attacker who recovered the
        // real key try it against the duress nonce and validate via
        // AEAD tag, partially defeating the deniability.
        let duress_salt = random_bytes::<SALT_LEN>();
        let duress_profile = self.profile;
        let duress_key = derive_key(phrase, &duress_salt, duress_profile)?;
        let duress_nonce = random_bytes::<NONCE_LEN>();
        let mut decoy_plaintext = serde_json::to_vec(&decoy_tree)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        // Pad the decoy plaintext to the same fixed size as the real
        // blob — without this, a fresh duress on an empty tree would
        // ciphertext to ~46 bytes while the real blob is at the
        // 256 KiB tier, leaving a clear size signal on disk (T1-H01).
        pad_plaintext_for_save(&mut decoy_plaintext)?;
        let cipher = ChaCha20Poly1305::new(duress_key.0[..].into());
        let mut buf = decoy_plaintext;
        cipher
            .encrypt_in_place(&duress_nonce.into(), AEAD_AAD, &mut buf)
            .map_err(|_| VaultError::Cipher("encrypt failed"))?;
        let duress_blob = VaultFileHeader {
            profile: duress_profile,
            salt: duress_salt,
            nonce: duress_nonce,
            ciphertext: buf,
        };
        // APPEND the new duress blob — never replace an existing one.
        // This is the "fake-of-fake" safety contract: an attacker who
        // tests by configuring a fake while in a duress session leaves
        // every previously-set fake phrase intact. The user can still
        // type their original fake phrase later, land on the same fake
        // content the attacker has already seen, and avoid suspicion.
        //
        // First-time setup from real mode discards the random
        // placeholder that was filling the duress slot — we don't want
        // an empty unused slot lingering, and the placeholder content
        // wasn't decryptable by anyone anyway.
        let mut file = self.locked_file.take().ok_or(VaultError::BadFormat(
            "vault file missing — call create first",
        ))?;
        if file.duress.len() == 1 && !self.duress_configured {
            // The single slot is still the random placeholder from
            // create/v1-upgrade. Replace it with our first real fake
            // (no need to grow the file just for that).
            file.duress[0] = duress_blob;
        } else {
            file.duress.push(duress_blob);
        }
        self.locked_file = Some(file);
        self.duress_configured = true;
        // Persist immediately so the user doesn't have to mutate
        // anything in the real vault to trigger a save.
        self.dirty = true;
        self.save(path)?;
        Ok(())
    }

    pub fn tree(&self) -> &VaultTree {
        &self.tree
    }

    pub fn add_folder(&mut self, name: &str, parent: Option<u64>) -> u64 {
        let id = self.tree.add_folder(name, parent);
        self.dirty = true;
        id
    }

    pub fn add_item(&mut self, name: &str, parent: Option<u64>) -> u64 {
        let id = self.tree.add_item(name, parent);
        self.dirty = true;
        id
    }

    pub fn update_item(&mut self, id: u64, mutate: impl FnOnce(&mut VaultItem)) -> bool {
        let changed = self.tree.update_item(id, mutate);
        if changed {
            self.dirty = true;
        }
        changed
    }

    pub fn rename_folder(&mut self, id: u64, new_name: &str) -> bool {
        let ok = self.tree.rename_folder(id, new_name);
        if ok {
            self.dirty = true;
        }
        ok
    }

    pub fn delete_node(&mut self, id: u64) -> bool {
        let ok = self.tree.delete_node(id);
        if ok {
            self.dirty = true;
        }
        ok
    }

    pub fn move_node(
        &mut self,
        id: u64,
        new_parent: Option<u64>,
        before: Option<u64>,
    ) -> bool {
        let ok = self.tree.move_node(id, new_parent, before);
        if ok {
            self.dirty = true;
        }
        ok
    }

    // Encrypt `tree` under `phrase` and return the HVLE blob bytes.
    // Pulled out as a free function so the full-vault export and the
    // sub-tree share-export use the exact same on-disk shape (a
    // recipient never has to know whether they got a partial or full
    // export — same magic, same decode path).
    fn encrypt_tree(tree: &VaultTree, phrase: &str) -> Result<Vec<u8>, VaultError> {
        if phrase.is_empty() {
            return Err(VaultError::WrongPhrase);
        }
        let salt = random_bytes::<SALT_LEN>();
        let profile = ArgonProfile::Moderate;
        let key = derive_key(phrase, &salt, profile)?;
        let plaintext = serde_json::to_vec(tree)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        let nonce = random_bytes::<NONCE_LEN>();
        let cipher = ChaCha20Poly1305::new(key.0[..].into());
        let mut buf = plaintext;
        cipher
            .encrypt_in_place(&nonce.into(), AEAD_AAD, &mut buf)
            .map_err(|_| VaultError::Cipher("encrypt failed"))?;
        let mut out = Vec::with_capacity(HEADER_LEN + buf.len());
        out.extend_from_slice(EXPORT_MAGIC);
        out.push(VERSION);
        out.push(profile.as_byte());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&buf);
        Ok(out)
    }

    // Full-vault export. The whole tree gets encrypted under `phrase`.
    pub fn export_blob(&self, phrase: &str) -> Result<Vec<u8>, VaultError> {
        if !self.is_unlocked() {
            return Err(VaultError::Cipher("vault is locked"));
        }
        Self::encrypt_tree(&self.tree, phrase)
    }

    // Single-node / sub-tree export (right-click → "Export this...").
    // - If `root_id` is a folder: includes that folder + every
    //   descendant folder + every item under any of those folders.
    // - If `root_id` is an item: includes just that one item.
    // - Otherwise (unknown id): error.
    //
    // The root node's parent is reset to None in the exported tree —
    // on import it'll land under the receiver's auto-named "Imported"
    // wrapper folder cleanly.
    pub fn export_subtree(
        &self,
        phrase: &str,
        root_id: u64,
    ) -> Result<Vec<u8>, VaultError> {
        if !self.is_unlocked() {
            return Err(VaultError::Cipher("vault is locked"));
        }
        let sub = self.tree.extract_subtree(root_id).ok_or(
            VaultError::BadFormat("node not found"),
        )?;
        Self::encrypt_tree(&sub, phrase)
    }

    // Decrypt + parse an HVLE blob, return the contained tree. Caller
    // is responsible for merging the tree into the current vault.
    pub fn decode_import_blob(
        bytes: &[u8],
        phrase: &str,
    ) -> Result<VaultTree, VaultError> {
        if bytes.len() < HEADER_LEN {
            return Err(VaultError::BadFormat("file shorter than header"));
        }
        if &bytes[0..4] != EXPORT_MAGIC {
            return Err(VaultError::BadFormat(
                "magic mismatch (not a Husk vault export)",
            ));
        }
        if bytes[4] != VERSION {
            return Err(VaultError::BadFormat("unsupported export version"));
        }
        let profile = ArgonProfile::from_byte(bytes[5])?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[6..6 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[6 + SALT_LEN..HEADER_LEN]);
        let key = derive_key(phrase, &salt, profile)?;
        let cipher = ChaCha20Poly1305::new(key.0[..].into());
        let mut buf = bytes[HEADER_LEN..].to_vec();
        cipher
            .decrypt_in_place(&nonce.into(), AEAD_AAD, &mut buf)
            .map_err(|_| VaultError::WrongPhrase)?;
        let tree: VaultTree =
            serde_json::from_slice(&buf).map_err(|_| VaultError::WrongPhrase)?;
        buf.zeroize();
        Ok(tree)
    }

    // Merge an imported tree into the current vault. New IDs are
    // assigned everywhere so no collision with existing entries.
    // Everything imported lands under a single wrapper folder named
    // `wrapper_name` (typically "Imported YYYY-MM-DD HH:MM") so the
    // user can find it instantly + drag entries out as needed.
    //
    // Vault must be unlocked.
    pub fn merge_imported_tree(
        &mut self,
        imported: VaultTree,
        wrapper_name: &str,
    ) -> Result<(usize, usize), VaultError> {
        if !self.is_unlocked() {
            return Err(VaultError::Cipher("vault is locked"));
        }
        // Build an id-translation map: imported_id → new_id_in_this_vault.
        // We process folders first (some items may parent on folders),
        // then items. Root entries in the imported tree get reparented
        // to our new wrapper folder.
        let wrapper_id = self.tree.add_folder(wrapper_name, None);
        let mut id_map: std::collections::HashMap<u64, u64> =
            std::collections::HashMap::new();
        // Walk folders in BFS order from roots so parent ids are
        // already mapped by the time children are processed.
        let mut to_process: Vec<u64> = imported
            .folders
            .iter()
            .filter(|f| f.parent.is_none())
            .map(|f| f.id)
            .collect();
        while let Some(cur_id) = to_process.pop() {
            let Some(cur) = imported.folders.iter().find(|f| f.id == cur_id) else {
                continue;
            };
            let new_parent = match cur.parent {
                None => Some(wrapper_id),
                Some(pid) => id_map.get(&pid).copied().or(Some(wrapper_id)),
            };
            let new_id = self.tree.add_folder(&cur.name, new_parent);
            id_map.insert(cur.id, new_id);
            // Queue children for next iteration.
            for child in imported
                .folders
                .iter()
                .filter(|f| f.parent == Some(cur.id))
            {
                to_process.push(child.id);
            }
        }
        // Items: parent is either a folder (mapped) or the root → wrapper.
        let mut imported_items = 0;
        for it in &imported.items {
            let new_parent = match it.parent {
                None => Some(wrapper_id),
                Some(pid) => id_map.get(&pid).copied().or(Some(wrapper_id)),
            };
            let new_id = self.tree.add_item(&it.name, new_parent);
            self.tree.update_item(new_id, |dst| {
                dst.url = it.url.clone();
                dst.username = it.username.clone();
                dst.password = it.password.clone();
                dst.notes = it.notes.clone();
                dst.tags = it.tags.clone();
                dst.created_at = it.created_at;
                dst.updated_at = it.updated_at;
            });
            imported_items += 1;
        }
        let imported_folders = id_map.len();
        self.dirty = true;
        Ok((imported_folders, imported_items))
    }

    // Nuke the vault file and scrub in-memory state. After this the
    // VaultManager is back to its placeholder-empty state, the chrome
    // sidebar will render the Setup view, and `exists()` returns false.
    // No going back — this is the user explicitly asking to start over.
    pub fn wipe(&mut self, path: &Path) -> Result<(), VaultError> {
        // Best-effort file removal. We don't abort on NotFound — the
        // user might be wiping a vault that exists only in memory
        // (created but never saved, edge case).
        if path.exists() {
            std::fs::remove_file(path)
                .map_err(|e| VaultError::Io(e.to_string()))?;
        }
        // Drop key + tree. ZeroizeOnDrop scrubs the key bytes; we
        // explicitly zeroize the tree's secret strings BEFORE
        // replacing with default — otherwise the heap allocator's
        // free list keeps the password bytes recoverable to
        // co-resident malware. Audit T1-M03 / T1-L09.
        self.key = None;
        self.tree.zeroize_in_place();
        self.tree = VaultTree::default();
        self.locked_file = None;
        self.salt = [0u8; SALT_LEN];
        self.profile = ArgonProfile::Moderate;
        self.dirty = false;
        self.duress_mode = false;
        self.duress_configured = false;
        Ok(())
    }

    pub fn find_for_origin(&self, origin: &str) -> Vec<&VaultItem> {
        self.tree.find_for_origin(origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_create_unlock() {
        let dir = std::env::temp_dir().join(format!("husk-vault-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.husk");
        let _ = std::fs::remove_file(&path);

        let mut v = VaultManager::load_or_empty(&path).unwrap();
        assert!(!v.exists());
        v.create(&path, "correct horse battery staple", ArgonProfile::Moderate)
            .unwrap();
        v.add_folder("Work", None);
        let _ = v.add_item("Gmail", None);
        v.save_if_dirty(&path).unwrap();
        v.lock(&path).unwrap();

        let mut v2 = VaultManager::load_or_empty(&path).unwrap();
        assert!(v2.exists());
        assert!(v2.unlock("wrong phrase").is_err());
        v2.unlock("correct horse battery staple").unwrap();
        assert_eq!(v2.tree().folders.len(), 1);
        assert_eq!(v2.tree().items.len(), 1);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn duress_setup_and_unlock_roundtrip() {
        let dir = std::env::temp_dir()
            .join(format!("husk-vault-duress-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.husk");
        let _ = std::fs::remove_file(&path);

        // Set up the real vault with a couple of items.
        let mut v = VaultManager::load_or_empty(&path).unwrap();
        v.create(&path, "real-phrase", ArgonProfile::Moderate).unwrap();
        let real_gmail_id = v.add_item("Gmail", None);
        v.update_item(real_gmail_id, |it| {
            it.username = "user@gmail".into();
            it.password = "real-secret-pw".into();
            it.url = "https://gmail.com".into();
        });
        v.save_if_dirty(&path).unwrap();

        // Configure duress with copy-from-real → same names/urls/usernames,
        // randomised passwords. No leak of the real password.
        v.setup_duress(&path, "duress-phrase", true).unwrap();
        assert!(v.has_duress());
        assert!(!v.is_duress_mode());
        v.lock(&path).unwrap();

        // Re-open: real phrase yields the REAL tree.
        let mut v2 = VaultManager::load_or_empty(&path).unwrap();
        v2.unlock("real-phrase").unwrap();
        assert!(!v2.is_duress_mode());
        let item = v2
            .tree()
            .items
            .iter()
            .find(|i| i.name == "Gmail")
            .unwrap();
        assert_eq!(item.password, "real-secret-pw");
        v2.lock(&path).unwrap();

        // Duress phrase yields a DIFFERENT tree (same names/urls but
        // randomised passwords).
        let mut v3 = VaultManager::load_or_empty(&path).unwrap();
        v3.unlock("duress-phrase").unwrap();
        assert!(v3.is_duress_mode());
        let decoy = v3
            .tree()
            .items
            .iter()
            .find(|i| i.name == "Gmail")
            .unwrap();
        assert_eq!(decoy.username, "user@gmail");
        assert_eq!(decoy.url, "https://gmail.com");
        assert_ne!(decoy.password, "real-secret-pw");
        assert_eq!(decoy.password.len(), 16);

        // Wrong phrase against both blobs → WrongPhrase.
        let mut v4 = VaultManager::load_or_empty(&path).unwrap();
        assert!(matches!(v4.unlock("nope"), Err(VaultError::WrongPhrase)));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn nested_fake_preserves_earlier_fakes() {
        // Critical scenario: user has real + fake1. Attacker coerces
        // them into unlocking, types fake1 → duress session. Attacker
        // tests by clicking "Set up fake vault" and configuring a
        // fake2. We MUST NOT clobber fake1 — otherwise when the
        // attacker asks "type your phrase again", the original fake1
        // phrase wouldn't work and the user is caught.
        let dir = std::env::temp_dir()
            .join(format!("husk-vault-nested-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.husk");
        let _ = std::fs::remove_file(&path);

        let mut v = VaultManager::load_or_empty(&path).unwrap();
        v.create(&path, "real-phrase", ArgonProfile::Moderate).unwrap();
        v.add_item("Gmail", None);
        v.save_if_dirty(&path).unwrap();
        // First fake from real mode.
        v.setup_duress(&path, "fake1-phrase", true).unwrap();
        v.lock(&path).unwrap();

        // Attacker enters fake1.
        let mut attacker_view = VaultManager::load_or_empty(&path).unwrap();
        attacker_view.unlock("fake1-phrase").unwrap();
        assert!(attacker_view.is_duress_mode());
        // Attacker tries to set up a fake from the fake.
        attacker_view
            .setup_duress(&path, "fake2-phrase", false)
            .unwrap();
        attacker_view.lock(&path).unwrap();

        // KEY ASSERTION: fake1 phrase STILL unlocks the original fake1
        // content. That's what makes "type your phrase again" safe.
        let mut v2 = VaultManager::load_or_empty(&path).unwrap();
        v2.unlock("fake1-phrase").unwrap();
        assert!(v2.is_duress_mode());
        assert!(v2.tree().items.iter().any(|i| i.name == "Gmail"));
        v2.lock(&path).unwrap();

        // fake2 also works (independent fake).
        v2.unlock("fake2-phrase").unwrap();
        assert!(v2.is_duress_mode());
        v2.lock(&path).unwrap();

        // Real phrase still unlocks real.
        v2.unlock("real-phrase").unwrap();
        assert!(!v2.is_duress_mode());
        assert!(v2.tree().items.iter().any(|i| i.name == "Gmail"));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn change_phrase_rotates_only_active_blob() {
        let dir = std::env::temp_dir()
            .join(format!("husk-vault-change-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.husk");
        let _ = std::fs::remove_file(&path);

        // Create real vault + configure duress.
        let mut v = VaultManager::load_or_empty(&path).unwrap();
        v.create(&path, "real-1", ArgonProfile::Moderate).unwrap();
        let _ = v.add_item("Gmail", None);
        v.save_if_dirty(&path).unwrap();
        v.setup_duress(&path, "fake-1", false).unwrap();
        v.lock(&path).unwrap();

        // Rotate the REAL phrase.
        let mut v2 = VaultManager::load_or_empty(&path).unwrap();
        v2.unlock("real-1").unwrap();
        v2.change_phrase(&path, "real-2").unwrap();
        v2.lock(&path).unwrap();

        // Real-1 should NO LONGER work; real-2 should.
        let mut v3 = VaultManager::load_or_empty(&path).unwrap();
        assert!(v3.unlock("real-1").is_err());
        v3.unlock("real-2").unwrap();
        assert!(!v3.is_duress_mode());
        // Fake phrase untouched.
        v3.lock(&path).unwrap();
        v3.unlock("fake-1").unwrap();
        assert!(v3.is_duress_mode());

        // Rotate the FAKE phrase while in fake mode.
        v3.change_phrase(&path, "fake-2").unwrap();
        v3.lock(&path).unwrap();

        // Fake-1 dead; fake-2 works.
        let mut v4 = VaultManager::load_or_empty(&path).unwrap();
        assert!(v4.unlock("fake-1").is_err());
        v4.unlock("fake-2").unwrap();
        assert!(v4.is_duress_mode());
        // Real-2 still works → no cross-contamination.
        v4.lock(&path).unwrap();
        v4.unlock("real-2").unwrap();
        assert!(!v4.is_duress_mode());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn export_import_roundtrip() {
        let dir = std::env::temp_dir().join(format!("husk-vault-exp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.husk");
        let _ = std::fs::remove_file(&path);

        let mut v = VaultManager::load_or_empty(&path).unwrap();
        v.create(&path, "master", ArgonProfile::Moderate).unwrap();
        let work = v.add_folder("Work", None);
        let g_id = v.add_item("Gmail", Some(work));
        v.update_item(g_id, |it| {
            it.url = "https://gmail.com".into();
            it.username = "user@gmail.com".into();
            it.password = "s3cret!".into();
        });

        // Export with a SHARE password (not the master).
        let blob = v.export_blob("share-pw").unwrap();
        assert!(blob.len() > 50);
        assert_eq!(&blob[0..4], b"HVLE");

        // Wrong password → import refused.
        assert!(VaultManager::decode_import_blob(&blob, "wrong").is_err());

        // Right password → tree decoded.
        let imported = VaultManager::decode_import_blob(&blob, "share-pw").unwrap();
        assert_eq!(imported.folders.len(), 1);
        assert_eq!(imported.items.len(), 1);
        let gmail = imported.items.iter().find(|it| it.name == "Gmail").unwrap();
        assert_eq!(gmail.password, "s3cret!");

        // Merge into a fresh second vault — the imported entries should
        // land under a single "Imported" wrapper folder with brand-new IDs.
        let path2 = dir.join("vault2.husk");
        let _ = std::fs::remove_file(&path2);
        let mut v2 = VaultManager::load_or_empty(&path2).unwrap();
        v2.create(&path2, "m2", ArgonProfile::Moderate).unwrap();
        let (nf, ni) = v2.merge_imported_tree(imported, "Imported test").unwrap();
        assert_eq!(nf, 1);
        assert_eq!(ni, 1);
        let imported_gmail = v2
            .tree()
            .items
            .iter()
            .find(|it| it.name == "Gmail")
            .unwrap();
        assert_eq!(imported_gmail.password, "s3cret!");
        // The new gmail item should be under a folder that's under our
        // wrapper folder, NOT collide with anything pre-existing.
        assert_ne!(imported_gmail.id, g_id);

        // Wipe → vault file gone, manager back to placeholder.
        v.wipe(&path).unwrap();
        assert!(!path.exists());
        assert!(!v.exists());
        assert!(!v.is_unlocked());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&path2);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn move_node_cycle_safety() {
        let dir = std::env::temp_dir().join(format!("husk-vault-move-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.husk");
        let _ = std::fs::remove_file(&path);
        let mut v = VaultManager::load_or_empty(&path).unwrap();
        v.create(&path, "test", ArgonProfile::Moderate).unwrap();

        let work = v.add_folder("Work", None);
        let proj = v.add_folder("Project", Some(work));
        let sub = v.add_folder("Sub", Some(proj));
        let item = v.add_item("Cred", Some(sub));

        // Legitimate move: item from Sub to Work.
        assert!(v.move_node(item, Some(work), None));
        assert_eq!(
            v.tree().items.iter().find(|i| i.id == item).unwrap().parent,
            Some(work)
        );

        // Cycle attempt: move Work into Sub (Sub is a descendant of Work).
        assert!(!v.move_node(work, Some(sub), None));
        // Self-cycle: move Work into Work.
        assert!(!v.move_node(work, Some(work), None));
        // Non-existent target.
        assert!(!v.move_node(work, Some(99999), None));
        // Move folder to root.
        assert!(v.move_node(proj, None, None));
        assert_eq!(
            v.tree().folders.iter().find(|f| f.id == proj).unwrap().parent,
            None
        );

        // Reorder: add a second root-level folder, then put it BEFORE work.
        let other = v.add_folder("Other", None);
        let work_order_before = v.tree().folders.iter().find(|f| f.id == work).unwrap().order;
        assert!(v.move_node(other, None, Some(work)));
        let other_order_after = v.tree().folders.iter().find(|f| f.id == other).unwrap().order;
        assert!(other_order_after < work_order_before,
            "after reorder, `other` should sort before `work`");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn origin_matching() {
        let mut v = VaultManager::load_or_empty(std::path::Path::new("nonexistent")).unwrap();
        let phrase = "test";
        let dir = std::env::temp_dir().join(format!("husk-vault-match-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.husk");
        let _ = std::fs::remove_file(&path);
        v.create(&path, phrase, ArgonProfile::Moderate).unwrap();
        let id = v.add_item("Google", None);
        v.update_item(id, |it| it.url = "https://google.com".into());
        assert_eq!(v.find_for_origin("https://google.com").len(), 1);
        assert_eq!(v.find_for_origin("https://accounts.google.com/x").len(), 1);
        assert_eq!(v.find_for_origin("https://evil-google.com").len(), 0);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
