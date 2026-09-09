---
paths:
  - "**/Cargo.toml"
---

# Dependencies Rules

- Necessity check before adding any dep — can the standard library or an existing dep cover the need?
- MSRV of any added dep must be ≤ workspace MSRV (see [rust-toolchain.toml](../../rust-toolchain.toml))
- For crypto-adjacent crates (touching keys, signatures, encryption, KDFs): require maintainer reputation (RustCrypto org, dalek-cryptography, etc.) and audit history
- Prefer audited crates
- Pin major versions in each crate's `Cargo.toml`; hoist shared deps to `[workspace.dependencies]`. Update via `cargo update -p <crate>` with reasoning in the commit message
- Dependabot owns vulnerability alerts and security-update PRs; the maintainer configures it in GitHub
- When adding or updating dependencies, review licenses, sources, maintenance status, and new transitive duplicates
