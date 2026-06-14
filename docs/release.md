# Release Verification

Release verification applies to artifacts produced from the exact release commit. For v0.8.0, the
released artifacts are the mobile UniFFI outputs built by the existing scripts:

- Android shared libraries for `aarch64-linux-android`, `armv7-linux-androideabi`, and
  `x86_64-linux-android`
- Android Kotlin bindings under `target/android/kotlin/`
- iOS `target/xcframework/Aether.xcframework`
- iOS Swift sources under `target/xcframework/Sources/`

The workspace is not published to crates.io.

## Reproducible Builds

Run each reproducibility check from a clean checkout at the commit being released:

```bash
scripts/release/reproducible-mobile-artifacts.sh android
scripts/release/reproducible-mobile-artifacts.sh ios
```

Each command builds the selected artifact set twice from `git archive HEAD`, sets
`SOURCE_DATE_EPOCH` to the commit timestamp, disables Cargo incremental compilation, hashes the
released files, and fails if the two hash manifests differ.

Runner requirements match the underlying build scripts:

- Android requires `cargo-ndk` and the Android NDK.
- iOS requires Xcode command-line tools.

## SBOM

Generate the release SBOM with:

```bash
scripts/release/sbom.sh
```

The output is:

```text
target/sbom/aether-uniffi-v0.8.0-sbom.json
```

The SBOM is CycloneDX JSON generated from `crates/aether-uniffi/Cargo.toml` with all Cargo targets
described. Release verification uploads this file as a CI artifact.

To verify an uploaded SBOM, check out the same commit, rerun `scripts/release/sbom.sh`, and compare
the SHA-256 hash of `target/sbom/aether-uniffi-v0.8.0-sbom.json` with the uploaded artifact.

## Dependency Failures

`cargo-deny` failures mean the committed dependency policy rejected the graph. Fix the dependency
choice or update `deny.toml` with a narrow, reviewed exception.

`cargo-audit` failures mean RustSec reports an advisory that the policy treats as blocking. Upgrade,
remove, or explicitly document why the advisory does not apply before release.

`cargo-geiger` failures mean unsafe-code analysis did not complete. A non-empty dependency unsafe
report is not automatically a blocker, but new or changed crypto-adjacent dependencies need audit
and maintainer-reputation reasoning before release.
