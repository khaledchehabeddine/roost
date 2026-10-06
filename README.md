# Roost

The shared cryptographic core for a private, end-to-end encrypted cloud messaging system.

## Setup

```bash
git clone git@github.com:chirp-org/roost.git
cd roost
rustup show
cargo build --workspace
```

Run tests:

```bash
cargo test --workspace
```

Generate documentation:

```bash
cargo doc --workspace --open
```

CI runs the checks in [`ci.yml`](.github/workflows/ci.yml) on every pull request.

## Architecture

Only `roost-client` is a supported consumer entry crate, and Swift and Kotlin use its UniFFI
bindings. Core, Crypto, and Protocol are implementation dependencies, not separate SDKs or release
products. All four crates share one workspace version and remain unpublished on crates.io.

| Crate | Owns | Direct Roost dependencies |
| --- | --- | --- |
| `roost-client` | Mobile UniFFI declarations and adapters | `roost-core`, `roost-protocol` |
| `roost-core` | Identity lifecycle, messaging, contacts, state transitions, storage recovery | `roost-crypto`, `roost-protocol` |
| `roost-crypto` | Keys, X3DH, Double Ratchet, encryption | `roost-protocol` |
| `roost-protocol` | Shared encodings, certificates, canonical key validation, transcripts, padding | None |

v0.16.0 breaks the Rust and native APIs, so consumers adopt matching libraries and bindings together.
The v0.15.0 release record and notes are in
[`docs/` at `5d86ceb`](https://github.com/chirp-org/roost/tree/5d86cebd195006578843bb9ae9b6f7bd622d7e8a/docs).

## Integrating

Create one `IdentityContext` per identity namespace with your `SecureStorage`. Its documentation
says what Roost and the host each own, and rustdoc has each method's contract. The host must:

- Store Protocol State Blobs in an atomic, durable store, and protect them like identity keys.
- Commit returned state updates together with their outbound Messages and acknowledgments, and
  serialize each identity's operations across contexts and processes.
- Reserve each prepared key change before committing its operation ID, finalize it after the commit,
  and abort it only when the commit definitely failed. After an unknown outcome or a restart,
  resolve unfinished operations against its own records first.
- Persist each Message's exact Transport Binding and reuse it for retries.
- After restoring a backup, replace its Protocol State Blobs and rotate the inbox before publishing
  prekeys.
- Keep keys, passphrases, plaintext, and Protocol State Blobs out of logs.
- Test its own Keychain or Keystore and database transactions, which the package checks don't cover.

## Security Scope

Roost doesn't hide transport metadata, so Transport Bindings, routing, timing, IP addresses, and push
tokens stay visible to the transport. It can't protect secrets on a compromised device, and it has no
rate limiting, transport retries, or deniable mode. Roost makes no side-channel claims.

## Mobile Packages

With Xcode, `scripts/build/xcframework.sh` writes
`target/ios-distribution/Roost-v<version>.xcframework.zip` with an arm64 device slice and an arm64
simulator slice.

With JDK 17 or newer, Gradle 9.5.0, Android SDK 36, NDK r28c, and `cargo-ndk` 4.1.2, and with
`ANDROID_HOME` and `ANDROID_NDK_HOME` set, `scripts/build/android-aar.sh` writes the
`com.chirp:roost` AAR for arm64-v8a and x86_64 under `target/android/maven/`, with its POM, Gradle
module metadata, and sources jar.

To test a package, run `./check.sh <roost-checkout>` in `roost-swift` or `roost-kotlin`.

## Releasing

1. Pick a `main` commit whose Rust CI passed, and run `./check.sh <roost-checkout>` on it in
   `roost-swift` and `roost-kotlin`.
2. Push the tag `v<workspace version>` on that commit.

The [Release](.github/workflows/release.yml) workflow rejects a tag that isn't on `main` or doesn't
match the workspace version. It builds both packages and attaches the zip to a draft `roost-swift`
release. Then it tags `roost-swift` with a `Package.swift` that points at the zip and pins its
checksum, publishes `com.chirp:roost` to `roost-kotlin`'s GitHub Packages, and publishes the release.
Run the workflow manually to build both packages without publishing them.

Publishing needs a `ROOST_PUBLISH_TOKEN` repository secret. It must be a classic personal access
token with the `repo` and `write:packages` scopes, because the GitHub Packages Maven registry accepts
no other kind. `roost-swift` needs immutable releases, which lock the zip and the tag once the
release is published.

If a run fails before it publishes the release, delete the draft release, the `roost-swift` tag, and
the package version if it exists, then re-run the workflow. If the fix needs a new commit, move the
tag to that commit, which starts a new run. Once the release is published, changed bytes need a new
version.

## Docs

- [`GLOSSARY.md`](GLOSSARY.md) — domain terms and the words to avoid
- [`docs/adr/`](docs/adr/) — architectural decisions
