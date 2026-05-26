//! # husk-crypto
//!
//! The trust-critical surface of the Husk browser, published verbatim
//! for independent audit. This crate has NO dependency on the rest of
//! Husk — it's the same source files the binary ships, extracted so
//! you can `cargo build`, `cargo test`, and review them in isolation.
//!
//! Scope: everything that decides whether "encrypted" is true in
//! Husk. Out of scope: UI, networking, WebView integration, settings,
//! sandboxing — those live in the closed binary.
//!
//! Modules:
//! * `crypto` — Argon2id KDF parameters + ChaCha20-Poly1305 envelope
//!   primitives.
//! * `vault` — credential store, real / duress two-blob layout, fixed-
//!   size padding, atomic on-disk format.
//! * `profile_manager` — encrypted-profile container (profile.enc).
//! * `notes` — per-note + per-notebook seals, AAD discriminator.
//!
//! Every published security finding from the v0.1 launch audit
//! (`SECURITY_AUDIT.md` in the Husk repo) is fixed in this code as of
//! the tagged version.

pub mod crypto;
pub mod notes;
pub mod profile_manager;
pub mod vault;
