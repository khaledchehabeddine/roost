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

- Protocol: Double Ratchet — replayed messages must be rejected, ratchet steps must follow correct sequence, expired keys must be deleted
- Collections sized by external input (`HashMap`, `Vec`) must have a hard cap constant
- Comparisons of MACs, tokens, or hashes must use `subtle::ConstantTimeEq`, never `==`
- `Zeroizing` wrapping: required for heap secrets (`Vec<u8>`, decrypted output) and FFI boundaries — not needed for stack-local values consumed immediately by a constructor
- Wrap decrypted output in `Zeroizing::new()` immediately — before any validation or early returns
- Types holding secret material must not derive `Clone`, `Debug`, or `Serialize` unless they also derive `ZeroizeOnDrop` — add a comment explaining why
- Production randomness must use `OsRng` — no other RNG source outside test modules
- Encryption: XChaCha20-Poly1305 · Key exchange: X25519 · Signing: Ed25519 · Key derivation: Argon2id

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
