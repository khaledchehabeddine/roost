# Building mobile packages

Build from the Roost repository root. Generated bindings and binaries stay under `target/`.
The workspace version identifies both packages. Rust, Swift and Kotlin source APIs come from
the same Rust declarations.

## iOS

Requires Xcode with an iOS simulator runtime. Build the XCFramework and local Swift package:

```bash
scripts/build/ios-package.sh
```

Outputs are `target/ios-distribution/roost-swift-v<version>/`,
`Roost-v<version>.xcframework.zip` and `Roost-v<version>.swift-package.zip` in the same directory.
The package exports `Roost`, a binary framework containing the compiled Swift API and Rust library.
It supports arm64 devices and arm64/x86_64 simulators, with an iOS 13 deployment target.
`scripts/build/xcframework.sh` builds just the framework when package assembly is unnecessary.

Run `./check.sh <roost-checkout>` in `roost-swift` to build and test the package once.
`ROOST_IOS_DESTINATION` can select a specific Xcode simulator destination.

## Android

Requires JDK 17, Gradle 9.5.0, Android SDK 36, NDK r28c and `cargo-ndk` 4.1.2.
Set `ANDROID_HOME` and `ANDROID_NDK_HOME` to the installed SDK and NDK. `GRADLE_BIN` may select
an existing Gradle executable. Build the local Maven package:

```bash
scripts/build/android-aar.sh
```

The AAR and POM are under
`target/android/maven/io/github/relaynet/roost/<version>/`, with coordinate
`io.github.relaynet:roost:<version>`. The AAR contains the generated Kotlin API and native libraries
for arm64-v8a, armeabi-v7a and x86_64. Its POM supplies JNA. The current minimum Android API is 36.
`scripts/build/android.sh` builds just the libraries and Kotlin sources.

Run `./check.sh <roost-checkout>` in `roost-kotlin` to build the production AAR and test it on one
API 36 managed device. `ROOST_ANDROID_TEST_TASK=:consumer:connectedDebugAndroidTest` selects an
already-running emulator instead.

Local peer simulations may build the separate `io.github.relaynet:roost-development` coordinate:

```bash
ROOST_CARGO_FEATURES=development-certificates scripts/build/android-aar.sh
```

This is an on-demand local build. Production package checks always clear that feature selection.

## Release

Run Rust CI and both package checks against the intended source commit. Follow
[mobile publication](mobile-publication.md) for access configuration, exact-artifact handoff,
signed-candidate installation and owner-initiated publication to the private distribution repositories.

Publish the exact checked bytes and record the source commit, workspace version and toolchain
versions in the release description. Uploading rebuilt bytes requires checking those bytes again.
Sign the XCFramework archive and AAR with the release key:

```bash
export ROOST_RELEASE_FINGERPRINT='<trusted release key fingerprint>'
scripts/release/sign-artifact.sh '<artifact>'
scripts/release/verify-artifact.sh '<artifact>' '<artifact>.asc' '<artifact>.sha256' '<public-key.asc>' '<pinned-sha256>'
```

Distribute signatures, checksums and the public key alongside the artifacts. Consumers obtain the
trusted fingerprint separately. Swift's published binary-target checksum must name the same
XCFramework archive that passed the package check. Keep the AAR with its generated POM when
publishing to GitHub Packages so runtime dependencies resolve.

For on-demand reproducibility, run the normal build in two clean checkouts of the same commit
with the same Rust, Xcode or Android tools. Compare `shasum -a 256` of the XCFramework archives or
AARs. The iOS archive fixes timestamps from the source commit; Gradle fixes archive timestamps and
entry order. Investigate differences before claiming a reproducible result. This is not a release
requirement, and no fresh byte-for-byte proof is claimed for each release.

The [v0.15.0 release record](release.md), published assets and tags remain historical and unchanged.
Its custom gate and packet instructions apply to that release only.

## Host integration

Create `Client` with the host's `SecureStorage` implementation. Store Protocol State Blobs opaquely.
Commit returned state updates and their message, acknowledgment or outbox effects atomically,
enforcing absent/digest preconditions. Serialize each identity's prepared-operation lifecycle
across clients and processes, and recover unfinished operations after interruption. The native
checks prove callback conversion and recovery through the package; the host application must test
its own Keychain/Keystore implementation and database transaction behavior.
