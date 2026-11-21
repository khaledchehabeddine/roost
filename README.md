# Roost

Roost is the cryptographic core for private, end-to-end encrypted messaging apps. It is a Rust library that ships as Swift and Kotlin packages. It manages identities and contacts, and protects messages with X3DH, Double Ratchet, and sealed sender. The app handles networking and storage.

## Limitations

- Roost has no group messaging.
- An identity lives on one device.
- Key agreement uses X25519 alone, so it has no post-quantum protection.

## Install

Add the package for your platform:

- iOS: [Roost Swift](https://github.com/chirp-org/roost-swift)
- Android: [Roost Kotlin](https://github.com/chirp-org/roost-kotlin)

## Architecture

- `roost-bindgen`: Generates the bindings apps use to call `roost-client`.
- `roost-client`: The API apps call.
- `roost-core`: Manages identities, contacts, and messaging sessions.
- `roost-crypto`: Implements key generation, signing, X3DH handshakes, and Double Ratchet encryption.
- `roost-protocol`: Defines the wire formats, sender certificates, and message padding the other crates share.

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

## Releasing

```bash
scripts/release.sh X.Y.Z
```
