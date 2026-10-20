# Mobile Release Artifacts

Mobile releases ship a Maven AAR for Kotlin, and a Swift package that pairs an XCFramework of the Rust library with the Swift bindings as source. Apps link the Swift package as a dynamic framework.

## Alternatives

- Ship loose Kotlin sources and shared libraries: Android apps expect one dependency with classes, native libraries, and metadata.
- Precompile the Swift bindings into the XCFramework: a Swift framework built outside Xcode needs a stable module interface and hand-written bundle files, which SwiftPM avoids by compiling the source with the app.
- Link the Swift package statically: an app and each of its extensions would carry their own copy of the Rust code.
