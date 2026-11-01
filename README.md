# Roost

The cryptographic core for private, end-to-end encrypted messaging apps.

## Setup

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

## Architecture

- `roost-bindgen`: Generates the bindings apps use to call `roost-client`.
- `roost-client`: The API apps call.
- `roost-core`: Manages identities, contacts, and messaging sessions.
- `roost-crypto`: Implements key generation, signing, X3DH handshakes, and Double Ratchet
  encryption.
- `roost-protocol`: Defines the wire formats, sender certificates, and message padding the other
  crates share.

## Releasing

```bash
scripts/release.sh X.Y.Z
```
