# Mobile Release Artifact Boundary

**Status:** Accepted

Mobile distribution ships generated artifacts from the release source, not checked-in generated SDK
source: the iOS Swift Package is generated around the xcframework binary target, and the Android
release is a Maven AAR containing UniFFI-generated Kotlin plus ABI-specific native libraries. Final
consumer trust is attached to the fixed binary artifact bytes with detached OpenPGP signatures and
pinned SHA-256 checksums for the published iOS xcframework archive and Android AAR. For iOS, the
signature/checksum authenticates the xcframework archive, while the generated Swift Package
provenance comes from the release source and consumer package verification; release-candidate
hashes, generated source directories, and local build outputs are not substitutes for signed
release artifacts.

## Considered Options

- Check generated Swift or Kotlin output into the repository. Rejected because Rust UniFFI
  declarations remain the source of truth and generated output would add review noise.
- Publish loose generated sources and native libraries. Rejected because consumers need standard
  package shapes with metadata and native-library placement.
- Trust unsigned release-candidate artifacts, package wrapper files, or reproducibility hashes
  alone. Rejected because consumers need fail-closed verification of the final published binary
  artifact bytes plus source-controlled package provenance.

## Consequences

- Host application build instructions must verify both signature and pinned checksum before
  consuming mobile binaries, and must get package wrapper files from the matching release source.
- Artifact verification is a supply-chain boundary only; it does not broaden protocol security,
  metadata privacy, or compromised-endpoint claims.

## Verification Evidence

- `docs/release.md` and `docs/ci.md` document iOS/Android artifact production, signing, checksum,
  and negative verification paths.
- `scripts/test/release-candidate-artifact-verification.sh` signs copied release-candidate
  artifacts with an ephemeral CI key and verifies the same fail-closed paths before publication.
- `scripts/test/release-artifact-verification.sh` exercises happy paths plus signature, checksum,
  and fingerprint mismatch failures for both final mobile artifacts.
- `scripts/test/ios-package-consumer.sh` and `scripts/test/android-aar-consumer.sh` verify generated
  consumer package usability before signing.
