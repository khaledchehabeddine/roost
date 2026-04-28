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

- When updating one agent's customization, mirror the behavioral change in the other agent's equivalent (Claude ↔ Codex). Stylistic patterns differ between agents per their respective documentation — do not harmonize style across agents
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
  - Skipped message keys must have a hard cap (per chain and total) — reject on overflow rather than evict (eviction-based caches are vulnerable to flooding; conservative rejection preserves replay protection)

### Dependencies

- Necessity check before adding any dep — can the standard library or an existing dep cover the need?
- For crypto-adjacent crates (touching keys, signatures, encryption, KDFs): require maintainer reputation (RustCrypto org, dalek-cryptography, etc.) and audit history
- MSRV of any added dep must be ≤ Hermes' MSRV (currently `1.94.0` per `rust-toolchain.toml`)
- Prefer audited crates: `subtle` for constant-time, `zeroize` for secret zeroing, `rand` (`OsRng`) for production randomness, `hkdf`/`hmac`/`sha2` for KDF/MAC, dalek crates for asymmetric primitives
- `cargo-deny` mechanically enforces license, advisory, source, and yanked policy — see `deny.toml`. This rule covers the human-judgment criteria cargo-deny cannot enforce
- Pin major versions in each crate's `Cargo.toml` (current pattern); when a dep is shared across two or more crates, hoist to `[workspace.dependencies]`. Update via `cargo update -p <crate>` with explicit reasoning in commit message
- After bumping any crypto-adjacent dep, run `cargo deny check bans` to catch new transitive duplicates. If a duplicate is unavoidable (e.g., build-time tool), add an explicit entry to `deny.toml`'s `[bans] skip` with reasoning

### Error Handling

- Each crate defines its own domain error type
- All error paths return `Result` — `unwrap()`, `expect()`, and `panic!()` are banned outside of tests
- Error `Display` implementations should be detailed enough to debug from logs alone — not localized UI strings
- Error `Display` must never include secret material — key bytes, plaintext, decrypted output, or seeds. Use reference identifiers (key IDs, message numbers) instead.

### Public API

- Binary-breaking FFI changes (struct field layout under `#[repr(C)]`, removing a `#[uniffi::export]`) require a major version bump — affects Swift/Kotlin bindings
- Prefer adding a new function over breaking an existing one
- `pub` minimization — every `pub` item must have an external consumer (another crate, the FFI surface, or a documented public re-export). `pub` items with no consumer are dead code; demote to `pub(crate)` or remove
- FFI-exposed APIs (`#[uniffi::export]`, `#[derive(uniffi::*)]`) require corresponding `From<InternalError> for HermesError` impls within `hermes-uniffi` for every error type they can return
- No `unwrap()`, `expect()`, or `panic!()` in `#[uniffi::export]` paths — use `Result<T, HermesError>` for fallible operations
- Public types must have rustdoc per `docs/agents/rust-docs/style.md` tier (T1 for `hermes-uniffi`, T2 for other crates)

### Rust Style

- Module ordering: `mod` declarations → `use` declarations → types → traits → impls → functions
- No `pub use` glob re-exports

### Tests

- Inline unit tests live in `#[cfg(test)] mod tests { ... }` at the bottom of the source file they exercise — not in a sibling `tests.rs` module
- Integration tests live in `crates/<crate>/tests/<scenario>.rs` and exercise only the public API
- One scenario per integration test file — split rather than grow into mega-files
- KAT vector tests cite their derivation source (RFC, upstream library + version, or paired derivation script) in a doc comment alongside the expected constant
- KAT expected outputs live in named constants (`<PRIMITIVE>_KAT_EXPECTED`) — never inlined as literals at the assertion site
- Test inputs are deterministic — fixed timestamps (`const FIXED_TS: u64 = ...`) or fixed byte arrays. No `SystemTime::now()` or `OsRng` in test paths. See `crates/hermes-crypto/tests/session.rs` for the established pattern
- No shared mutable state across tests — each test owns its `Setup` via a `setup()` function, no `static mut` or `Lazy<>`
- Test-only dependencies live under `[dev-dependencies]` in Cargo.toml — never `[dependencies]`

### UniFFI

- FFI-incompatible core types must be wrapped within the `hermes-uniffi` crate
- Errors crossing the UniFFI boundary must use `#[derive(uniffi::Error)]` — library errors and panics cannot propagate

## Workflow

- See `CONTRIBUTING.md` for branches, commits, and PR conventions
- After responding to a non-obvious discovery, fix, or workaround, suggest creating a decision record or an `AGENTS.md` update
