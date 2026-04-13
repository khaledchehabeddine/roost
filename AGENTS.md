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

### Crypto

- Encryption: XChaCha20-Poly1305
- Key exchange: X25519 · Signing: Ed25519
- Key derivation: Argon2id
- Secret keys are always wrapped in `Zeroizing<T>` — never raw `Vec<u8>`
- Secret material crossing FFI must use `Zeroizing` wrappers — public keys as `Vec<u8>` are acceptable
- Production randomness must use `OsRng` — no other RNG source outside test modules
- Protocol: Double Ratchet — replayed messages must be rejected, ratchet steps must follow correct sequence, expired keys must be deleted

### Error Handling

- All error paths return `Result` — `unwrap()`, `expect()`, and `panic!()` are banned outside of tests
- Each crate defines its own domain error type
- Errors never cross the UniFFI boundary — only domain errors defined in the UniFFI Definition Language (UDL) propagate to the platform layer
- Error `Display` implementations should be detailed and developer-facing

### Rust Style

- Module ordering: `use` declarations → types → traits → impls → functions
- No `pub use` glob re-exports

### UniFFI

- FFI-incompatible core types must be re-wrapped within the `hermes-uniffi` crate

## Workflow

- See `CONTRIBUTING.md` for branches, commits, and PR conventions
- After responding to a non-obvious discovery, fix, or workaround, suggest creating a decision record or an `AGENTS.md` update
