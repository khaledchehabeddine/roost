# CI Verification

CI separates fast pull-request checks from release gates. Pull-request checks protect source
quality, dependency policy, and the supported runtime verification subset. Release gates verify the
mobile artifacts that ship from a commit.

## Runtime Verification

Miri runs on nightly for `aether-crypto` and `aether-core` library tests:

```bash
scripts/ci/miri-test.sh
```

The Miri subset runs `aether-core` with `--features blake3/pure` so the run stays in Rust code that
Miri can interpret. `aether-crypto` has no BLAKE3 feature, so its library tests run without that
feature flag. The subset intentionally excludes `aether-uniffi`, generated Swift/Kotlin bindings,
Android, and iOS artifacts because those paths cross FFI, dynamic libraries, or platform toolchains
that Miri does not model.

AddressSanitizer and MemorySanitizer run on nightly Linux for the same Rust packages:

```bash
scripts/ci/sanitizer-test.sh address
scripts/ci/sanitizer-test.sh memory
```

The sanitizer subset targets `x86_64-unknown-linux-gnu` and runs library plus integration tests for
`aether-crypto` and `aether-core` with `-Z build-std`. The sanitizer jobs also use
`--features blake3/pure` to avoid native BLAKE3 C/assembly code that would otherwise fall outside
the Rust-instrumented test surface. UniFFI binding replay and mobile target builds remain covered by
their own workflows, not by sanitizer jobs.

## Constrained Decryption Budget

The v0.9.0 constrained decryption release gate runs the optimized Core budget harness:

```bash
scripts/ci/constrained-decryption-budget.sh
```

The harness measures the real `ProtocolStateEngine::decrypt_message` path one operation at a time
against the documented 24 MiB tracked Rust heap allocation budget and 250 ms wall-clock budget. It
is a release gate for the profiled constrained path, not a general endpoint security guarantee.

## Supply Chain

`deny.toml` is the committed dependency policy. It blocks disallowed licenses, vulnerable or yanked
crates, unknown sources, wildcard dependencies, and duplicate dependency versions unless a duplicate
has an explicit skip reason.

The supply-chain workflow runs on pull requests, `main`, and release tags. It enforces:

- `cargo deny check`
- a negative cargo-deny license-policy dry run that must fail
- `cargo audit --deny warnings`
- `cargo geiger` reports for each workspace package
- no first-party `unsafe` in `crates/**/*.rs`

`cargo-audit` is an advisory backstop for the RustSec database. `cargo-geiger` records the unsafe
posture of first-party and dependency code; first-party unsafe remains a hard failure until a future
review deliberately changes that policy.

Crypto-adjacent dependency changes must include explicit maintainer reputation, audit-history, and
duplicate-dependency reasoning before release. If a duplicate becomes necessary, add a targeted
`[bans] skip` entry in `deny.toml` with the reason.
