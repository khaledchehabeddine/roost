# Release Verification

Release verification applies to artifacts produced from the exact release commit. For v0.9.0, the
released artifacts are the mobile UniFFI outputs built by the existing scripts:

- Android shared libraries for `aarch64-linux-android`, `armv7-linux-androideabi`, and
  `x86_64-linux-android`
- Android Kotlin bindings under `target/android/kotlin/`
- Android AAR Maven artifact `com.aurelion:aether:<workspace-version>` under
  `target/android/maven/`
- iOS `target/xcframework/Aether.xcframework`
- iOS Swift sources under `target/xcframework/Sources/`
- iOS Swift Package under `target/ios-distribution/aether-ios-v0.9.0/`
- iOS xcframework archive `target/ios-distribution/Aether-v0.9.0.xcframework.zip`

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
- iOS requires Xcode command-line tools and an available iOS Simulator for package-consumer
  verification.

## iOS Swift Package

Build the release-candidate package with:

```bash
scripts/build/ios-package.sh
```

The package exposes product `Aether`, generated Swift target `Aether`, and binary target
`AetherFFI`. Verify it with:

```bash
scripts/test/ios-package-consumer.sh target/ios-distribution/aether-ios-v0.9.0
```

CI uploads the package, `Aether-v0.9.0.xcframework.zip`, and `SHA256SUMS` from the same
release-candidate run. Verify that run's hash before testing the artifact. Final artifact
signatures and pinned checksums are published by the release process, not by this release-candidate
packaging step.

## Android AAR Distribution

Build the Android AAR from the release-candidate source and publish it to a local Maven layout:

```bash
scripts/release/android-aar.sh
```

The script uses the workspace package version from `Cargo.toml`, publishes
`com.aurelion:aether:<workspace-version>` to `target/android/maven/`, verifies the AAR structure,
and writes an unsigned Maven Central bundle to `target/android/central/`.

Run the consumer checks after the local Maven layout exists:

```bash
scripts/test/android-aar-negative.sh
scripts/test/android-aar-consumer.sh
```

The negative check removes the AAR from a temporary Maven layout and expects dependency resolution
to fail. The consumer check resolves the artifact and runs the Kotlin binding coverage flow on an
Android API 36 managed device, including identity/session, encrypted backup, host-owned protocol
state blobs, sealed-sender message encryption/decryption, certificate validation, deduplication
outputs, acknowledgments, and event visibility.

The #126 AAR is unsigned release-candidate output. #127 signs the final artifact and publishes
pinned checksums; before that step, consumers can verify only the resolved coordinate and version,
not a final release signature or pinned checksum.

## Constrained Decryption Profile

The v0.9.0 release gate measures the real spec-v1.0 encrypted Message receive path in an optimized
Rust test binary:

```bash
scripts/ci/constrained-decryption-budget.sh
```

The constrained profile uses a 24 MiB tracked Rust heap allocation budget and a 250 ms wall-clock
budget per measured decrypt operation. The profile is compatible with the iOS Notification Service
Extension class target referenced by AE-FFI-04, but it is release-gate evidence for this harness,
not a guarantee for every host extension configuration.

The gate covers first and repeated decrypts, representative padding buckets, maximum-size precheck,
sealed-frame decode, pre-decryption deduplication lookup, envelope AEAD decrypt, sender-certificate
validation, sender transcript-signature verification, ratchet advancement, deduplication record
production, and acknowledgment/state-update output production. It does not claim protection for
rooted, jailbroken, malware-compromised, or otherwise untrusted endpoints.

## SBOM

Generate the release SBOM with:

```bash
scripts/release/sbom.sh
```

The output is:

```text
target/sbom/aether-uniffi-v0.9.0-sbom.json
```

The SBOM is CycloneDX JSON generated from `crates/aether-uniffi/Cargo.toml` with all Cargo targets
described. Release verification uploads this file as a CI artifact.

To verify an uploaded SBOM, check out the same commit, rerun `scripts/release/sbom.sh`, and compare
the SHA-256 hash of `target/sbom/aether-uniffi-v0.9.0-sbom.json` with the uploaded artifact.

## Malformed-Input Fuzz Campaigns

### 2026-06-14 Issue 113 Baseline

- Commit SHA: `2792f4c200f9d64d9171662d0bdab9b8ccc1234d` with uncommitted Issue 113 worktree changes
- Command: `/usr/bin/time -p env AETHER_FUZZ_SECONDS=900 scripts/ci/fuzz-smoke.sh`
- Started: `2026-06-14T20:12:33Z`
- Finished: `2026-06-14T21:43:01Z`
- Duration: `real 5411.32s`
- Result: pass, no crash, panic, or error markers

Target results:

- `message_decode`: 13,184,434 runs
- `protocol_state_blob_decode`: 67,043,231 runs
- `prekey_store_decode`: 205,518,547 runs
- `sender_certificate_validate`: 29,975,178 runs
- `sealed_frame_envelope_decode`: 588,471 runs
- `sealed_payload_padding`: 180,699,962 runs

## Dependency Failures

`cargo-deny` failures mean the committed dependency policy rejected the graph. Fix the dependency
choice or update `deny.toml` with a narrow, reviewed exception.

`cargo-audit` failures mean RustSec reports an advisory that the policy treats as blocking. Upgrade,
remove, or explicitly document why the advisory does not apply before release.

`cargo-geiger` failures mean unsafe-code analysis did not complete. A non-empty dependency unsafe
report is not automatically a blocker, but new or changed crypto-adjacent dependencies need audit
and maintainer-reputation reasoning before release.
