# Roost

The cryptographic core for private, end-to-end encrypted messaging apps.

Roost is a Rust library that ships as Swift and Kotlin packages. It manages identities, contacts, and messaging sessions for an app. The app keeps the networking, the storage, and the clock.

**Roost has had no independent security audit. Don't use it to protect real conversations.** See [SECURITY.md](SECURITY.md).

## What Roost Does

- **Identities without accounts.** An identity is a set of keys created on the device. It needs no phone number, email address, or password.
- **End-to-end encryption.** X3DH starts each session, and the Double Ratchet gives every message its own key.
- **Sealed sender.** Every message travels in a frame that shows a relay only what routing needs. Roost pads the content to the next power-of-two size.
- **Contacts by consent.** A contact is accepted only when both sides consent, and a safety number lets them verify each other.
- **Blocking that holds at the relay.** Blocking a contact rotates the inbox, so the block holds at the relay as well as on the device.
- **Delivery tracking and recovery.** Roost tracks each message to an accepted contact until the contact acknowledges it, and encrypts unacknowledged messages again on a newer session. It reports a message as not delivered after 30 days.
- **Backup and restore.** A passphrase-encrypted backup moves an identity to a new device.
- **Standard algorithms.** Roost takes X25519, Ed25519, XChaCha20-Poly1305, HKDF, BLAKE3, and Argon2id from established libraries.

[FEATURES.md](FEATURES.md) describes each feature.

## What the App Provides

- A `SecureStorage` adapter over the platform's key storage, such as Keychain or Keystore.
- A database for the protocol state Roost returns, and the transactions that commit it.
- All networking. Roost creates and opens message frames, and the app carries them.
- The current time, the trusted domain keys, and the revoked identity keys for each sender certificate check.
- One identity lock that covers every process sharing an identity.

## Limits

- Roost has had no independent security audit.
- Key agreement uses X25519 alone, so it has no post-quantum protection.
- Each established message carries the sender's signature over its transcript, so the recipient can prove who wrote it.
- A session connects two identities. Roost has no group messaging.
- An identity lives on one device. Roost doesn't sync it between devices.
- Sealed sender hides the sender and not the recipient. A relay sees the recipient, the time, and the padded size of each message. It also sees the prekeys each first message names.
- Roost builds its packages for arm64 only.

## Install

- Swift: add the [Roost Swift](https://github.com/chirp-org/roost-swift) package.
- Kotlin: add the [Roost Kotlin](https://github.com/chirp-org/roost-kotlin) package.

Each package's README shows the lines to add.

## How an App Uses Roost

1. Create one `IdentityContext` for each identity, over the app's `SecureStorage` adapter.
2. Stage each key change with a `prepare` method, such as creating the identity or rotating the inbox. Reserve the change, commit its output in a database transaction, then finalize it.
3. Publish the inbox to a relay, and share a contact link with a peer.
4. To send or receive a message, give Roost the protocol state it asks for. Commit the message and the returned state changes in one transaction.
5. At startup, finalize or abort each key change that a crash left unfinished.

Nothing Roost returns takes effect until the app commits it.

The API documentation has Swift and Kotlin examples. Build it with:

```bash
cargo doc --no-deps -p roost-client --open
```

## Architecture

- `roost-bindgen`: Generates the bindings apps use to call `roost-client`.
- `roost-client`: The API apps call.
- `roost-core`: Manages identities, contacts, and messaging sessions.
- `roost-crypto`: Implements key generation, signing, X3DH handshakes, and Double Ratchet encryption.
- `roost-protocol`: Defines the wire formats, sender certificates, and message padding the other crates share.

[docs/adr](docs/adr/) records each design decision, and [GLOSSARY.md](GLOSSARY.md) defines each term.

## Development

Install the tools:

```bash
brew install rustup cargo-edit cargo-mutants gradle
echo 'export PATH="$(brew --prefix)/opt/rustup/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
cargo install cargo-ndk --locked
```

Build the project:

```bash
cargo build
```

Run the checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo doc --locked --workspace --no-deps --all-features
cargo test --locked --workspace --all-features
```

[CONTRIBUTING.md](CONTRIBUTING.md) covers commits, branches, and pull requests.

## Releasing

```bash
scripts/release.sh X.Y.Z
```

The script sets the version, commits it, tags the commit, and pushes. The tag starts the release workflow, which:

1. Builds the Android library and the iOS XCFramework, and generates the Kotlin and Swift bindings.
2. Uploads the XCFramework to a draft release of Roost Swift and computes its checksum.
3. Commits a `Package.swift` that pins the XCFramework by that checksum, and tags it with the same version.
4. Publishes the Maven package to Roost Kotlin.
5. Publishes the Roost Swift release.

An app then installs a release by its version number.

## License

Roost is available under the [MIT License](LICENSE).
