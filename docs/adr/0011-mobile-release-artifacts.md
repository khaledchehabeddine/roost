# Mobile Release Artifacts

Mobile releases ship a Maven AAR for Kotlin, and a Swift package that pairs an XCFramework of the Rust library with the Swift bindings as source, which apps link as a dynamic framework. Pushing a version tag on main runs one workflow that generates the bindings from the Rust code, then builds and publishes both packages. While one maintainer releases, the artifacts carry no signatures, so consumers rely on checksum pins.

## Alternatives

- Commit generated bindings and native libraries to the package repositories' main branches: they add review noise and duplicate the Rust code.
- Ship loose Kotlin sources and shared libraries: Android apps expect one dependency with classes, native libraries, and metadata.
- Precompile the Swift bindings into the XCFramework: a Swift framework built outside Xcode needs a stable module interface and hand-written bundle files, which SwiftPM avoids by compiling the source with the app.
- Link the Swift package statically: an app and each of its extensions would carry their own copy of the Rust code.
- Sign each artifact and publish only the exact files the package checks tested: the signing key, the handoff between three repositories, and the provenance checks cost more than they protect while one maintainer releases.
- Run the package checks in the release workflow: simulator and emulator runs make every release slower and flakier.
