# Hermes

## What is Hermes

Hermes is a private Rust workspace implementing the cryptographic and networking core for an encrypted peer-to-peer messaging system over Bluetooth Low Energy (BLE). It exposes a single API surface to Swift (iOS) and Kotlin (Android) via UniFFI.

## Crate Dependency Graph

```
hermes-crypto
      ↓
hermes-core  ←  hermes-transport-ble
      ↓
hermes-uniffi
```

Each crate may only depend on crates below it in this graph. `hermes-crypto` has no `hermes-*` dependencies.

## Before Modifying a Crate

Read `crates/*/README.md` first — each crate documents its own constraints.

## Workflow Rules

- Follow `CONTRIBUTING.md` for all commits — do not question user intent on commit type or format.
- Cross-crate changes: small scope (single feature touching 2–3 crates) → implement in one pass bottom-up through the dependency graph. Large scope (new capability across all layers) → implement layer by layer.

## Project Facts

- Encryption: XChaCha20-Poly1305 (NOT AES-256-GCM)
- Key exchange: X25519 · Signing: Ed25519
- Key derivation: Argon2id
- Secret keys are always wrapped in `Zeroizing<T>` — never raw `Vec<u8>`
- UniFFI library name: `hermes` (not `hermes_uniffi`)

## Rust Style Guide

Based on the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) and std lib conventions.

### Doc Comments

- `//!` module docs: required on every `lib.rs` and public module. One sentence explaining what the module provides.
- `///` on all `pub` items: first line is a single-sentence summary. Add `# Errors` when returning `Result`. Add `# Panics` only if the function can actually panic (rare, given the `unwrap` ban). Add `# Examples` for non-obvious APIs. Skip docs on private helpers unless the logic is subtle.

### Code Structure

- Module ordering: `use` declarations → types → trait impls → functions.
- Consider extracting functions over ~40 lines.
- No `pub use` glob re-exports.
