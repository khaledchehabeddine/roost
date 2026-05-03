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

- Customizations that benefit collaborators on this project must live in project scope (`.agents/`, `.claude/`, `.codex/`, `AGENTS.md`, `CLAUDE.md`)
- Customization may live in user scope only if it neither shapes the project's workflow nor improves agent quality for collaborators
- When updating one agent's customization, mirror the behavioral change in the other agent's equivalent (Claude ↔ Codex). Stylistic patterns differ between agents per their respective documentation — do not harmonize style across agents
- Follow the structure and style from existing peer customizations of the same type within the same agent — applies to root config files, rules, agents, and skills
- Pattern-skill body items follow a cohesive ordering (workflow, scope, criticality, frequency, etc.) — not mechanical alphabetical sort
- Pattern-skill descriptions list the same items as the body, in the same order
- Skills that set `paths:` must not restate the location filter in their description — `paths:` gates autoloading; descriptions describe activity
- Customization descriptions don't explicitly reference the project name (Hermes) — context is implicit from the repo. Literal paths like `crates/hermes-uniffi` are exceptions (they identify actual files, not prose)

### Crypto

- Cryptographic primitives:
  - Encryption: XChaCha20-Poly1305
  - Key exchange: X25519
  - Signing: Ed25519
  - Key derivation: Argon2id
- Production randomness must come from the OS CSPRNG — `OsRng` or `getrandom::getrandom`. No `thread_rng()`, seeded RNGs, or test RNGs outside test modules
- AEAD nonces must be derived alongside the message key via HKDF — never randomly under a long-lived key
- Every HKDF call must use a distinct, non-empty `info` string for domain separation
- Wrap heap secrets (`Vec<u8>`, decrypted output) and FFI-bound values in `Zeroizing` immediately — before validation or early returns. Stack-locals consumed immediately by a constructor don't need wrapping
- Custom secret-bearing structs derive `Zeroize, ZeroizeOnDrop`. Mark fields with `#[zeroize(skip)]` if they are non-secret or if the field's type doesn't impl `Zeroize` (e.g., `ed25519_dalek::Signature`)
- Types holding secret material must not derive `Clone`, `Debug`, or `Serialize` unless they also derive `ZeroizeOnDrop` — add a comment explaining why
- Comparisons of MACs, keys, tokens, or hashes must use `subtle::ConstantTimeEq`, never `==`
- Collections sized by external input (`HashMap`, `Vec`) must have a hard cap constant
- Protocol invariants (Double Ratchet, X3DH-lite): replay rejection, ratchet ordering, key expiration, skipped-key caps — see `docs/agents/crypto-protocol-state.md` for detail

### Dependencies

- Necessity check before adding any dep — can the standard library or an existing dep cover the need?
- MSRV of any added dep must be ≤ workspace MSRV (see `rust-toolchain.toml`)
- For crypto-adjacent crates (touching keys, signatures, encryption, KDFs): require maintainer reputation (RustCrypto org, dalek-cryptography, etc.) and audit history
- Prefer audited crates: `subtle` for constant-time, `zeroize` for secret zeroing, `rand` (`OsRng`) for production randomness, `hkdf`/`hmac`/`sha2` for KDF/MAC, dalek crates for asymmetric primitives
- Pin major versions in each crate's `Cargo.toml`; hoist shared deps to `[workspace.dependencies]`. Update via `cargo update -p <crate>` with reasoning in the commit message
- License, advisory, source, and yanked policy: enforced by `cargo-deny` — see `deny.toml`
- After bumping any crypto-adjacent dep, run `cargo deny check bans` for transitive duplicates. Allowed duplicates need an explicit `[bans] skip` entry in `deny.toml` with reasoning

### Error Handling

- Each crate defines its own domain error type
- All error paths return `Result` — `unwrap()`, `expect()`, and `panic!()` are banned outside of tests
- Error `Display` implementations should be detailed enough to debug from logs alone — not localized UI strings
- Error `Display` must never include secret material — key bytes, plaintext, decrypted output, or seeds. Use reference identifiers (key IDs, message numbers) instead

### Public API

- Modules are organizational, not public-API boundaries
- `pub` minimization — every `pub` item needs an out-of-crate user (a `pub use` at `lib.rs` doesn't count)
- Public types must have rustdoc per `docs/agents/rust-docs-style.md` tier (T1 for `hermes-uniffi`, T2 for other crates)
- Prefer adding a new function over breaking an existing one
- Binary-breaking FFI changes (struct field layout under `#[repr(C)]`, removing a `#[uniffi::export]`) require a major version bump — affects Swift/Kotlin bindings
- Internal errors crossing the FFI must convert to `HermesError` via `From` impls
- No `unwrap()`, `expect()`, or `panic!()` in `#[uniffi::export]` paths — use `Result<T, HermesError>` for fallible operations

### Rust Style

- Module ordering: `mod` declarations → `use` declarations → types → traits → impls → functions
- No `pub use` glob re-exports

### Tests

- Inline unit tests live in `#[cfg(test)] mod tests { ... }` at the bottom of the source file they exercise
- Integration tests live in `crates/<crate>/tests/<scenario>.rs` and exercise only the public API; if a test needs an internal item, the test belongs inline
- One scenario per integration test file
- Module docstring on integration tests states the scenario and what crosses what boundary
- Test-only dependencies live under `[dev-dependencies]` in Cargo.toml
- Test assertions must not depend on `SystemTime::now()` or `OsRng` outputs — both may be opaque inputs (e.g., relative timestamps, round-trip keys)
- No shared mutable state across tests — each test owns its `Setup` via a `setup()` function, no `static mut` or `Lazy<>`
- KAT vector tests cite the specific function call (e.g., `pyca/cryptography 46 HKDF-SHA256`) in a doc comment alongside the expected constant
- KAT expected outputs live in named constants (`<PRIMITIVE>_KAT_EXPECTED`); both directions (encrypt/decrypt, sign/verify) reference the same constant
- KAT derivation source preference: RFC vectors → reference implementation → independent crate/library → hand-derived (flag for security-auditor review)
- KAT expected outputs must never be derived against the implementation under test

### UniFFI

- FFI-incompatible core types must be wrapped within the `hermes-uniffi` crate. Common cases: `&str`, `&[u8]`, lifetimes, trait objects without `#[uniffi::export(with_foreign)]`, tuples, external-crate types without conversion
- Stateful types wrap with `#[derive(uniffi::Object)]` and interior mutability — decouples internal type evolution from FFI stability
- Foreign-implementable traits use `#[uniffi::export(with_foreign)]` to let clients implement Rust-callable traits
- Secret bytes cross the FFI as bare `Vec<u8>` and wrap in `Zeroizing` immediately on the Rust side — wrapping happens in the adapter layer, not in client code
- Errors crossing the UniFFI boundary must use `#[derive(uniffi::Error)]` — library errors and panics cannot propagate
- `HermesError` variants describe failures in client-relevant terms (e.g., `AlreadyExists`, `NotFound`). Internal failures the client cannot meaningfully handle (e.g., lock poisoning, KDF output overflow) reduce to a generic `InternalError { reason: String }` — the `reason` is for logs, not for client logic

## Workflow

- See `CONTRIBUTING.md` for branches, commits, and PR conventions
- After responding to a non-obvious discovery, fix, or workaround, suggest creating a decision record or an `AGENTS.md` update
