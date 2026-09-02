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
release artifacts. The final Mobile Release Packet also carries the Swift Package archive, Android
POM and Maven bundle, CycloneDX SBOM, public key, source record, and successful release-gate
evidence. A detached signature over its exact payload manifest binds those files and their GitHub
Actions run identity to one source revision without replacing the binary artifact signatures or
Pinned Artifact Checksums.

## Considered Options

- Check generated Swift or Kotlin output into the repository. Rejected because Rust UniFFI
  declarations remain the source of truth and generated output would add review noise.
- Publish loose generated sources and native libraries. Rejected because consumers need standard
  package shapes with metadata and native-library placement.
- Trust unsigned release-candidate artifacts, package wrapper files, or reproducibility hashes
  alone. Rejected because consumers need fail-closed verification of the final published binary
  artifact bytes plus source-controlled package provenance.
- Publish each CI job's outputs independently. Rejected because matching versions do not prove that
  platform binaries, package metadata, and the SBOM came from the same source revision.

## Consequences

- Host application build instructions must verify both signature and pinned checksum before
  consuming mobile binaries, and must get package wrapper files from the matching release source.
- Packet assembly rejects producer records or gate evidence with different versions, revisions, or
  source date epochs. Packet verification checks exact membership, one CI run identity,
  package-to-binary byte equality, and every internal signature in a signed Maven publication.
- Verification rejects ZIP path escapes, links, special files, duplicate or case-colliding member
  paths, non-portable names, excessive member counts, and excessive declared expansion before
  extracting a package.
- Artifact verification is a supply-chain boundary only; it does not broaden protocol security,
  metadata privacy, or compromised-endpoint claims.

## Verification Evidence

- `docs/release.md` and `docs/ci.md` document iOS/Android artifact production, signing, checksum,
  and negative verification paths.
- `scripts/test/release-candidate-artifact-verification.sh` signs copied release-candidate
  artifacts with an ephemeral CI key and verifies the same fail-closed paths before publication.
- `scripts/test/release-artifact-verification.sh` exercises happy paths plus signature, checksum,
  checksum-filename, and fingerprint mismatch failures for both final mobile artifacts.
- `scripts/test/mobile-release-packet.sh` covers exact packet membership, source, SBOM and gate
  provenance, package metadata, package-to-binary byte equality, unsafe output paths, and hostile
  ZIP members.
- `scripts/test/sbom-reproducibility.sh` reproduces the CycloneDX SBOM across clean checkout paths.
- `scripts/test/ios-package-consumer.sh` and `scripts/test/android-aar-consumer.sh` verify generated
  consumer package usability before signing.
