# Mobile release artifact boundary

**Status:** Accepted, amended for v0.16.0

Mobile distribution ships generated standard packages. Swift uses an XCFramework binary target;
Kotlin uses a Maven AAR with its POM and native libraries. Rust declarations remain the source of
truth. Final XCFramework archives and AARs retain detached OpenPGP signatures and SHA-256 checksums.
Package checks consume the built package, and the maintainer publishes those exact bytes with their
source revision and version.

For the solo-maintained v1 MVP, ordinary CI results replace custom signed gate records. Remove the
Mobile Release Packet, SBOM generation and packet/hostile-archive test machinery. Reproducibility
is checked on demand for toolchain or build changes. Each platform builds once per candidate check.

## Trade-off

The former packet bound all gates and metadata into a portable signed record. Maintaining its
assembly, mocks, validators and repeated builds cost more than its current value for an independent
code/security review. Final binary signatures, checksums, source-controlled package metadata and
native consumption checks retain the useful distribution boundary. There is no portable signed
proof of every CI gate, and no claim of a new reproducibility proof for every release.

## History and verification

The [v0.15.0 release record](../release.md), assets and tags preserve the original packet decision.
This amendment does not rewrite that published history. Current commands and package ownership are
in [building mobile packages](../building-mobile.md) and [CI](../ci.md).
