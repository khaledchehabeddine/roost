# Release Verification

Release verification applies to artifacts produced from the exact release commit. For v0.15.0, the
release-candidate and final-release artifacts are the mobile UniFFI outputs built by the existing
scripts:

- Android shared libraries for `aarch64-linux-android`, `armv7-linux-androideabi`, and
  `x86_64-linux-android`
- Android Kotlin bindings under `target/android/kotlin/`
- Android AAR Maven artifact `com.aurelion:aether:<workspace-version>` under
  `target/android/maven/`
- iOS `target/xcframework/Aether.xcframework`
- iOS Swift sources under `target/xcframework/Sources/`
- iOS Swift Package under `target/ios-distribution/aether-ios-v<version>/`
- iOS xcframework archive `target/ios-distribution/Aether-v<version>.xcframework.zip`
- iOS Swift Package archive `target/ios-distribution/Aether-v<version>.swift-package.zip`
- detached OpenPGP signatures and pinned SHA-256 checksums for the final iOS xcframework archive
  and Android AAR
- a signed packet manifest, public release key, Android POM and Maven Central bundle, CycloneDX
  SBOM, and successful release-gate evidence tied to the same source revision and CI run

Release-candidate hashes and local build outputs are reproducibility evidence, not the distribution
trust root. Final consumer trust is attached to the fixed iOS xcframework archive and Android AAR
bytes after release-tag CI signs them and publishes pinned checksums. The workspace is not
published to crates.io.

## Reproducible Builds

Run each reproducibility check from a clean checkout at the commit being released:

```bash
scripts/release/reproducible-mobile-artifacts.sh android
scripts/release/reproducible-mobile-artifacts.sh ios
```

Each command builds the selected artifact set twice from `git archive HEAD`, sets
`SOURCE_DATE_EPOCH` to the commit timestamp, disables Cargo incremental compilation, hashes the
released files, and fails if the two hash manifests differ.

Each reproducibility pass records release-candidate evidence alongside its `SHA256SUMS`: command,
tool and runner environment, source revision, archive reference, commit object,
`SOURCE_DATE_EPOCH`, and artifact hashes. The Android pass covers the local Maven AAR and POM
metadata in addition to generated Kotlin and ABI-specific shared libraries. The iOS pass covers
both the xcframework archive and the complete Swift Package archive.

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
version="${AETHER_RELEASE_VERSION:?set release version without leading v}"
scripts/test/ios-package-consumer.sh "target/ios-distribution/Aether-v$version.swift-package.zip"
```

CI uploads the package, `Aether-v<version>.swift-package.zip`,
`Aether-v<version>.xcframework.zip`, and `SHA256SUMS` from the same release-candidate run.
Release-tag CI signs the final xcframework archive and publishes its pinned checksum.

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

Release-tag CI signs the final AAR, publishes its pinned checksum, and writes a signed Maven
Central bundle when Gradle publication signing is enabled.

## Signed Artifact Verification

The release signing path uses detached OpenPGP signatures and SHA-256 checksum sidecars. The
signing job requires:

- `AETHER_RELEASE_GPG_PRIVATE_KEY`
- `AETHER_RELEASE_GPG_PASSPHRASE`
- `AETHER_RELEASE_GPG_FINGERPRINT`

Sign one artifact with:

```bash
version="${AETHER_RELEASE_VERSION:?set release version without leading v}"
scripts/release/sign-artifact.sh "target/ios-distribution/Aether-v$version.xcframework.zip"
```

Verify one artifact with:

```bash
version="${AETHER_RELEASE_VERSION:?set release version without leading v}"
scripts/release/verify-artifact.sh \
  "Aether-v$version.xcframework.zip" \
  "Aether-v$version.xcframework.zip.asc" \
  "Aether-v$version.xcframework.zip.sha256" \
  "aether-v$version-release-key.asc"
```

Use the same command shape for `"aether-$version.aar"`. Host-application builds must fail closed on
signature mismatch, pinned-checksum mismatch, missing fingerprint, or signing-key mismatch. Do not
continue with an unsigned artifact, a different checksum file, or a substituted public key. Set
`AETHER_RELEASE_GPG_FINGERPRINT` to the expected release signing key fingerprint.

Release-candidate CI exercises the same AE-FFI-03 verification flow without publishing final
assets: it signs copied release-candidate artifacts with an ephemeral CI-only key, exports that
temporary public key, and runs the fail-closed happy and negative paths. These release-candidate
signatures and checksums are evidence that the final tag workflow will sign and checksum-pin the
same artifact shapes; they are not public release trust roots.

The release artifact verification test covers both mobile artifacts:

```bash
version="${AETHER_RELEASE_VERSION:?set release version without leading v}"
scripts/test/release-artifact-verification.sh \
  "Aether-v$version.xcframework.zip" \
  "aether-$version.aar" \
  "aether-v$version-release-key.asc"
```

It verifies happy paths and negative paths for iOS and Android signature mismatch, checksum
mismatch, checksum filename substitution, and fingerprint mismatch.

## Mobile release packet

Assemble the final files only after both platform reproducibility passes, both package-consumer
checks, the packet failure-path suite, the Android distribution build, and reproducible SBOM
generation succeed. CI writes one `.evidence` file immediately after each gate:

```bash
export AETHER_RELEASE_SOURCE_REVISION="$(git rev-parse HEAD)"
export AETHER_REQUIRE_SIGNED_MAVEN_PUBLICATION=true
scripts/release/assemble-mobile-release-packet.sh \
  target/release-verification/reproducible-mobile/ios/pass-1/artifacts \
  target/release-verification/reproducible-mobile/android/pass-1/artifacts \
  target/android \
  target/sbom \
  target/mobile-release-evidence \
  target/mobile-release-packet
```

The command rejects inputs whose source revision, version, or `SOURCE_DATE_EPOCH` differs. The
packet contains the signed xcframework archive and AAR with their pinned checksum sidecars, the
Swift Package archive, Android POM and Maven Central bundle, CycloneDX SBOM, public key, `SOURCE`
record, and evidence for these gates:

- Android reproducibility
- Android package consumption, including missing-AAR rejection
- iOS reproducibility
- iOS package consumption
- mobile packet happy and failure paths
- SBOM reproducibility

Each evidence record contains its command, pass result, source revision and epoch, and CI identity.
The signed `SHA256SUMS` manifest covers every evidence file and other packet payload. Final packets
require all evidence to come from one `RelayNet/aether` GitHub Actions run. Local candidate packets
may use local evidence. Set `AETHER_RELEASE_OUTPUT_ROOT` only when writing outside the default
`target/` root; the output must be a child of that explicit root.

Verify a packet from the matching source checkout with the expected signing-key fingerprint and
source revision:

```bash
export AETHER_RELEASE_GPG_FINGERPRINT="<trusted fingerprint>"
export AETHER_RELEASE_SOURCE_REVISION="<full commit SHA>"
scripts/release/verify-mobile-release-packet.sh target/mobile-release-packet
```

Verification fails if a file is missing or extra, if gate evidence differs by revision, epoch, run,
or expected job, if package metadata has the wrong version, if the POM or Swift Package wraps
different binary bytes, if a signed Maven bundle omits or mismatches an internal artifact signature,
if SBOM provenance differs, or if any manifest, signature, checksum, or trusted fingerprint check
fails. Before extraction, `scripts/release/extract-zip-safely.sh` also rejects non-portable or unsafe
member paths, links and special files, duplicate or case-colliding paths, more than 50,000 entries,
or more than 2 GiB of declared expanded data. Verification requires Info-ZIP `zipinfo` and `unzip`.

## v0.15.0 final gates

Do not create the `v0.15.0` tag or publish the GitHub Release from the Aether-side release-candidate
work. Both remain blocked until Relay tests, checks, and functionality criteria pass and Khaled
explicitly approves publication in issue #223.

Before treating `v0.15.0` as publishable, verify that GitHub issues #217 through #222 are closed.
Issue #223 performs the human-authorized tag and release publication, so it stays outside the
pre-tag prerequisite script.

Run the prerequisite gate before tagging. It requires the version-matched release-notes file and
closed GitHub issues #217 through #222:

```bash
scripts/release/verify-release-gates.sh
```

Enable immutable releases in the GitHub repository before publication. Tag CI creates the final
release once with `--verify-tag`, refuses to edit or replace an existing release, and fails unless
GitHub reports the published release as immutable.

The command requires GitHub CLI access to `RelayNet/aether`; in CI, the signed-release workflow
provides `GH_TOKEN`. The workflow runs the same gate at preflight and again before signed asset
upload or final GitHub Release publication.

## Constrained Decryption Profile

The v0.15.0 release gate measures the real spec-v1.0 encrypted Message receive path in an optimized
Rust test binary:

```bash
scripts/ci/constrained-decryption-budget.sh
```

The constrained profile uses a 24 MiB tracked Rust heap allocation budget and a 250 ms wall-clock
budget per measured decrypt operation. The profile is compatible with the iOS Notification Service
Extension class target referenced by AE-FFI-04, but it is release-candidate evidence for this
harness, not a guarantee for every host extension configuration.

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

The outputs are:

```text
target/sbom/aether-uniffi-v<version>-sbom.json
target/sbom/aether-uniffi-v<version>-sbom.source
```

The SBOM is CycloneDX JSON generated from `crates/aether-uniffi/Cargo.toml` with all Cargo targets
described. Generation normalizes checkout paths and records `aether:source:revision`, so the JSON is
byte-identical across clean checkout locations for the same revision and `SOURCE_DATE_EPOCH`. The
source sidecar records the version, revision, and epoch consumed by packet assembly.

To verify an uploaded SBOM, check out the same commit, rerun `scripts/release/sbom.sh`, and compare
the SHA-256 hash of `target/sbom/aether-uniffi-v<version>-sbom.json` with the uploaded artifact. Run
`scripts/test/sbom-reproducibility.sh` to verify generation across two clean checkout paths.

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
