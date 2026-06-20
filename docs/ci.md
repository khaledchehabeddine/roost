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

The v1.0.0 constrained decryption release gate runs the optimized Core budget harness:

```bash
scripts/ci/constrained-decryption-budget.sh
```

The harness measures the real `ProtocolStateEngine::decrypt_message` path one operation at a time
against the documented 24 MiB tracked Rust heap allocation budget and 250 ms wall-clock budget. It
is a release gate for the profiled constrained path, not a general endpoint security guarantee.

## Android AAR Distribution

The release-verification workflow builds the Android AAR from the checked-out source, publishes it
to a local Maven repository, uploads the unsigned Maven layout for later signing, and runs two
consumer checks:

- happy path: resolve `com.aurelion:aether:<workspace-version>` and run the Kotlin binding coverage
  flow on an Android API 36 managed device
- negative path: remove the AAR from a temporary Maven layout and require consumer resolution to
  fail

This gate proves packaging, local Maven metadata, generated Kotlin bindings, native library
placement, and consumer execution. Final artifact signatures and pinned checksums are verified by
the signed-release gate, not by this unsigned distribution check.

## Signed Release Artifacts

On release tags, the release-verification workflow signs the exact uploaded mobile artifacts from
the release jobs:

- `Aether-v<version>.xcframework.zip`
- `aether-<version>.aar`

The signed-release job imports the OpenPGP release key from repository secrets, writes detached
`.asc` signatures and `.sha256` checksum sidecars, exports the public release key, and runs
`scripts/test/release-artifact-verification.sh`. That test covers iOS and Android happy paths plus
signature-mismatch, checksum-mismatch, and fingerprint-mismatch failures for both artifacts.

Required secrets:

- `AETHER_RELEASE_GPG_PRIVATE_KEY`
- `AETHER_RELEASE_GPG_PASSPHRASE`
- `AETHER_RELEASE_GPG_FINGERPRINT`

The Android AAR distribution job also enables Gradle publication signing on release tags so the
Maven Central bundle contains Maven `.asc` signatures. Non-tag workflow runs keep producing
unsigned release-candidate artifacts.

On non-tag release-verification runs, CI signs copied release-candidate artifacts with an ephemeral
CI-only OpenPGP key and runs the same fail-closed verification script. This proves the AE-FFI-03
signature, checksum, and public-key verification flow before final publication, but it does not
publish release assets or create a public trust root.

The release-preflight job runs `scripts/release/verify-release-gates.sh` early for fail-fast tag
checks, and the signed-release job runs the same gate again immediately before signed asset upload
or GitHub prerelease publication. Both jobs pass `GH_TOKEN` from `github.token` so the GitHub CLI
can read issue state.

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
