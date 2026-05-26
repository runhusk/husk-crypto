# husk-crypto

The trust-critical crypto surface of the [Husk](https://husk.run) privacy-first
browser, published verbatim for independent audit.

These are the exact same source files the Husk binary ships, extracted into a
standalone Rust crate so you can `cargo build`, `cargo test`, and review them
without needing the rest of Husk.

## Why this repo exists

Privacy-first software lives or dies on whether the encrypted-at-rest claim
holds up under scrutiny. Husk's stance is: **the trust-critical surface — the
part that decides whether "encrypted" is true — must be auditable.** The
rest of the browser (UI, multi-window, interceptor, etc.) stays closed, but
the crypto is open so anyone can verify it.

## What's in scope

| Module | Purpose |
|---|---|
| `crypto` | Argon2id KDF parameters + ChaCha20-Poly1305 envelope primitives |
| `vault` | Credential store, real / duress two-blob layout, fixed-size padding (256 KiB per blob), atomic on-disk format |
| `profile_manager` | Encrypted-profile container (`profile.enc`) — HPRF magic header, secure wipe of materialized temp dirs |
| `notes` | Per-note + per-notebook seals with `EncryptedBodyKind` AAD discriminator |

## What's NOT in this repo

UI, WebView integration, IPC routing, settings, sandboxing, request interceptor,
the rendering engine wrap (wry), Windows-specific glue (single-instance mutex,
F9 cross-process events). All of that lives in the closed Husk binary. The
boundary is intentional: this crate covers everything that handles secrets;
the closed surface covers everything else.

## Specs at a glance

- **KDF**: Argon2id, 256 MiB / t=3 / lanes=1 (moderate) or 1 GiB / t=4 / lanes=1
  (sensitive). Both vastly exceed OWASP 2024 minimums (19 MiB / t=2).
- **AEAD**: ChaCha20-Poly1305, 256-bit key, 96-bit nonce, fresh nonce per save.
- **AAD**: per-container version strings (`husk-vault-v1`, `husk-profile-v1`,
  `husk-note-v1`, `husk-nb-note-v1`, `husk-nb-verify-v1`) — block reuse of
  ciphertext across contexts.
- **Format**: magic header + version byte + salt + nonce + ciphertext +
  AEAD tag. Atomic write via `tmp + rename`. On-disk size padded to a fixed
  256 KiB per blob so the duress / real size delta can't be read off the
  file.
- **RNG**: `rand::rngs::OsRng` everywhere for secrets. No `thread_rng` in any
  key / nonce / salt generation path.
- **Key hygiene**: `DerivedKey` / `MasterKey` zero-on-drop via the `zeroize`
  crate. `VaultTree::zeroize_in_place` scrubs password / username / notes
  strings before the tree is replaced on lock / wipe.
- **Duress**: two-blob layout (real + N duress). Unlock tries every blob,
  surfaces which one matched. Cross-blob phrase-collision check rejects a
  new duress phrase that decrypts any existing blob.

## Auditing this code

```bash
git clone https://github.com/runhusk/husk-crypto
cd husk-crypto
cargo test          # 19 tests, ~2 min (Argon2id is slow on purpose)
cargo doc --open    # inline reference
```

Findings or questions: **security@husk.run** (PGP key coming soon — until
then encrypted disclosure via keys.openpgp.org is welcome).

## Version mapping

The version tags here track Husk binary releases:

| husk-crypto tag | Husk binary |
|---|---|
| v0.1.0 | 0.1.0 (launch) |

Each tag is the verbatim snapshot of the corresponding binary release.

## License

Apache License 2.0. See [LICENSE](LICENSE). You may use, modify, and
redistribute this code in your own projects (open or closed source) provided
you preserve the copyright notice and the `NOTICE` file with attribution to
Husk. Apache 2.0 also includes an explicit patent grant — anyone suing Husk
over a patent loses their license to the code automatically.
