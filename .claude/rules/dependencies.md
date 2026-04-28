---
paths:
  - "**/Cargo.toml"
  - "**/deny.toml"
---

# Dependencies Rules

- Necessity check before adding any dep — can the standard library or an existing dep cover the need?
- For crypto-adjacent crates (touching keys, signatures, encryption, KDFs): require maintainer reputation (RustCrypto org, dalek-cryptography, etc.) and audit history
- MSRV of any added dep must be ≤ Hermes' MSRV (currently `1.94.0` per `rust-toolchain.toml`)
- Prefer audited crates: `subtle` for constant-time, `zeroize` for secret zeroing, `rand` (`OsRng`) for production randomness, `hkdf`/`hmac`/`sha2` for KDF/MAC, dalek crates for asymmetric primitives
- `cargo-deny` mechanically enforces license, advisory, source, and yanked policy — see `deny.toml`. This rule covers the human-judgment criteria cargo-deny cannot enforce
- Pin major versions in each crate's `Cargo.toml` (current pattern); when a dep is shared across two or more crates, hoist to `[workspace.dependencies]`. Update via `cargo update -p <crate>` with explicit reasoning in commit message
- After bumping any crypto-adjacent dep, run `cargo deny check bans` to catch new transitive duplicates. If a duplicate is unavoidable (e.g., build-time tool), add an explicit entry to `deny.toml`'s `[bans] skip` with reasoning
