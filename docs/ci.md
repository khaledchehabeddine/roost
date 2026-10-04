# CI

Roost uses one Linux job for pull requests and pushes to `main`. It runs formatting,
Clippy, workspace tests and rustdoc with the pinned Rust toolchain. Release-command regressions
require Python 3.11 or newer for `tomllib`; select that interpreter locally before running the checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
python3 scripts/release/test_commands.py
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
```

Run the manual package consumption workflow in `roost-swift` and `roost-kotlin` when bindings
or packaging change, and before each mobile release. Select the same Roost source revision in
both repositories. Each builds its platform once and exercises the resulting package on one
simulator or emulator. The checks cover native loading, unexpected foreign storage errors,
lost-write recovery, binary Transport Binding conversion and canonical evidence results. Swift
also verifies signatures with CryptoKit.
Rust owns protocol behavior; native suites keep small local inputs for package checks.

The Security workflow runs `cargo deny` weekly, on pull requests that change `Cargo.toml`,
`Cargo.lock` or `deny.toml`, and on demand. `prepare-mobile.yml` runs it again before signing. Run it
locally after changing dependencies:

```bash
cargo deny check advisories licenses sources
```

The maintainer will enable Dependabot alerts and security updates after this cleanup. Dependency
additions and updates still need review of maintenance and new transitive duplicates. First-party
unsafe code is denied by workspace Rust lints.

Reproducibility is an on-demand check for toolchain or build-system changes. Final artifact signing
and checksums remain, but there is no custom gate-evidence packet, SBOM pipeline, duplicate mobile
release build, scheduled diagnostics, fuzz setup or coverage reporting. CI job results are the
verification record. See [building packages](building-mobile.md), [mobile publication](mobile-publication.md) and
[coverage limits](protocol-state-invariant-tests.md).

Repository settings must require the `Rust / check` job instead of the removed workflow jobs.
Workflow files alone cannot update branch protection.

The same job checks release commands with small files and isolated external-tool responses.
It tests source/run rejection, pinned signatures and checksums, and retries without replacing bytes.
The signing test uses a temporary keyring; CI needs no release credential for these regressions.
