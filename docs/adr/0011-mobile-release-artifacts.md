# Mobile Release Artifacts

Mobile releases ship an XCFramework for Swift and a Maven AAR for Kotlin, with bindings generated from the Rust code at build time. Pushing a version tag on main builds both and publishes them from one workflow. While one maintainer releases, the artifacts carry no signatures, so consumers rely on checksum pins, and the maintainer runs the package checks locally before tagging.

## Alternatives

- Commit generated bindings and native libraries: they add review noise and duplicate the Rust code.
- Ship loose Kotlin sources and shared libraries: Android apps expect one dependency with classes, native libraries, and metadata.
- Sign each artifact and publish only the exact files the package checks tested: the signing key, the handoff between three repositories, and the provenance checks cost more than they protect while one maintainer releases.
- Run the package checks in the release workflow: simulator and emulator runs make every release slower and flakier, and catch little that a local run on the same commit misses.
