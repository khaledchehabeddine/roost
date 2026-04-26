# Hermes

## Overview

Hermes is the shared cryptographic and networking core for a private, peer-to-peer encrypted messaging system that works offline over short-range wireless links.

## Architecture

Ports-and-adapters layout. Crate dependencies (`A → B` means "A depends on B"):

- `hermes-crypto`
- `hermes-core` → `hermes-crypto`
- `hermes-transport-ble` → `hermes-core`
- `hermes-uniffi` → `hermes-core`, `hermes-transport-ble`

## Coding Guidelines

### Agent Config

- When updating one agent's customization, mirror the change in the other agent's equivalent (Claude ↔ Codex)
- Follow the structure and style from existing peer customizations of the same type within the same agent — applies to root config files, rules, agents, and skills

### Crypto

- Cryptographic primitives:
  - Encryption: XChaCha20-Poly1305
  - Key exchange: X25519
  - Signing: Ed25519
  - Key derivation: Argon2id
- Production randomness must use `OsRng` — no other RNG source outside test modules
- AEAD nonces must be derived alongside the message key via HKDF — never randomly under a long-lived key
- Every HKDF call must use a distinct info string for domain separation
- Wrap heap secrets (`Vec<u8>`, decrypted output) and FFI-bound values in `Zeroizing`. Stack-locals consumed immediately by a constructor don't need wrapping.
- Wrap decrypted output in `Zeroizing::new()` immediately — before any validation or early returns
- Types holding secret material must not derive `Clone`, `Debug`, or `Serialize` unless they also derive `ZeroizeOnDrop` — add a comment explaining why
- Comparisons of MACs, tokens, or hashes must use `subtle::ConstantTimeEq`, never `==`
- Collections sized by external input (`HashMap`, `Vec`) must have a hard cap constant
- Protocol: Double Ratchet:
  - Replayed messages must be rejected
  - Ratchet steps must follow the correct sequence
  - Expired keys must be deleted
  - Skipped message keys must have a hard cap (per chain and total) and a max age — drop the oldest on overflow

### Error Handling

- Each crate defines its own domain error type
- All error paths return `Result` — `unwrap()`, `expect()`, and `panic!()` are banned outside of tests
- Error `Display` implementations should be detailed enough to debug from logs alone — not localized UI strings
- Error `Display` must never include secret material — key bytes, plaintext, decrypted output, or seeds. Use reference identifiers (key IDs, message numbers) instead.

### Rust Style

- Module ordering: `mod` declarations → `use` declarations → types → traits → impls → functions
- No `pub use` glob re-exports

### UniFFI

- FFI-incompatible core types must be wrapped within the `hermes-uniffi` crate
- Errors crossing the UniFFI boundary must use `#[derive(uniffi::Error)]` — library errors and panics cannot propagate

## Workflow

- See `CONTRIBUTING.md` for branches, commits, and PR conventions
- After responding to a non-obvious discovery, fix, or workaround, suggest creating a decision record or an `AGENTS.md` update
