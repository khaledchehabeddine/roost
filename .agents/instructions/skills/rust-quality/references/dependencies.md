# Dependencies

- First check whether the standard library or an existing workspace dependency covers the need.
- Keep every dependency compatible with workspace MSRV 1.95.0 from `Cargo.toml` and `rust-toolchain.toml`.
- For crates touching keys, signatures, encryption, or KDFs, require reputable maintainers and credible audit history. Prefer audited crates.
- Pin major versions in crate manifests and hoist shared dependencies to `[workspace.dependencies]`. Keep workspace version, edition, MSRV, and local crate versions authoritative at the root.
- Update through `cargo update -p <crate>` and explain the reason in the commit message. Review `Cargo.lock` and every affected manifest.
- Enforce license, advisory, source, yanked, wildcard, and duplicate-version policy through `deny.toml` and `cargo deny`.
- After any crypto-adjacent bump, run `cargo deny check bans`. Add a `[bans] skip` only for an unavoidable duplicate and include a concrete reason.
- Run `scripts/check.sh supply-chain` for dependency changes and `scripts/check.sh quick` for manifest changes; the publish workflow still requires the full base-aware gate.
