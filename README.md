# Roost

The cryptographic core for private, end-to-end encrypted messaging apps.

Roost is a Rust library that ships as Swift and Kotlin packages. It manages identities, contacts, and messaging sessions for an app. The app keeps the networking, the storage, and the clock.

**Roost has had no independent security audit. Don't use it to protect real conversations.**

## Features

- **Identities without accounts.** An identity is a set of keys created on the device. It needs no phone number, email address, or password.
- **End-to-end encryption.** X3DH starts each session, and the Double Ratchet gives every message its own key.
- **Sealed sender.** Every message travels in a frame that hides its sender from the relay.
- **Contacts by consent.** A contact is accepted only when both sides consent, and a safety number lets them verify each other.
- **Blocking.** Blocking a contact rotates the inbox, so the block holds at the relay as well as on the device.
- **Delivery recovery.** Roost tracks each message to an accepted contact until the contact acknowledges it, and encrypts unacknowledged messages again on a newer session.
- **Backup and restore.** A passphrase-encrypted backup moves an identity to a new device.
- **Standard algorithms.** Roost takes X25519, Ed25519, XChaCha20-Poly1305, HKDF, BLAKE3, and Argon2id from established libraries.

## Limits

- Key agreement uses X25519 alone, so it has no post-quantum protection.
- Each established message carries the sender's signature, so the recipient can prove who wrote it.
- Roost has no group messaging.
- An identity lives on one device.

## Install

- Swift: add the [Roost Swift](https://github.com/chirp-org/roost-swift) package.
- Kotlin: add the [Roost Kotlin](https://github.com/chirp-org/roost-kotlin) package.

## Usage

Roost keeps no protocol state between calls. The app gives Roost the state each call asks for, and nothing Roost returns takes effect until the app commits it.

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

[docs/adr](docs/adr/) records each design decision.

## Development

Install the tools:

```bash
brew install rustup cargo-edit cargo-mutants gradle
echo 'export PATH="$(brew --prefix)/opt/rustup/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
cargo install cargo-ndk --locked
```

Build and test the project:

```bash
cargo build
cargo test
```

## Releasing

```bash
scripts/release.sh X.Y.Z
```

The script pushes a tag, which starts a workflow that builds and publishes the Roost Swift and Roost Kotlin packages.
