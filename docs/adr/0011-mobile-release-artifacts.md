# Mobile Release Artifacts

Mobile releases ship an XCFramework for Swift and a Maven AAR for Kotlin, with bindings generated from the Rust code at build time. Each archive has a detached OpenPGP signature and a SHA-256 checksum, and the maintainer publishes the exact files that CI's package checks tested. While one maintainer runs releases, normal CI results are enough, without separately signed records of each check.

## Alternatives

- Commit generated bindings and native libraries: they add review noise and duplicate the Rust code.
- Ship loose Kotlin sources and shared libraries: Android apps expect one dependency with classes, native libraries, and metadata.
- A signed record of every release check: it cost more to build and verify than it was worth before an independent review.
