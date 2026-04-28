---
paths:
  - "**/Cargo.toml"
  - "**/deny.toml"
---

# Dependencies Rules

- Necessity check before adding any dep — can the standard library or an existing dep cover the need?
- MSRV of any added dep must be ≤ workspace MSRV (see [rust-toolchain.toml](../../rust-toolchain.toml))
- For crypto-adjacent crates (touching keys, signatures, encryption, KDFs): require maintainer reputation (RustCrypto org, dalek-cryptography, etc.) and audit history
- Prefer audited crates
- Pin major versions in each crate's `Cargo.toml`; hoist shared deps to `[workspace.dependencies]`. Update via `cargo update -p <crate>` with reasoning in the commit message
- License, advisory, source, and yanked policy: enforced by `cargo-deny`
- After bumping any crypto-adjacent dep, run `cargo deny check bans` for transitive duplicates. Allowed duplicates need an explicit `[bans] skip` entry in `deny.toml` with reasoning
