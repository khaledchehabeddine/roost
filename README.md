# Hermes

Hermes is the shared cryptographic and networking core for a private, peer-to-peer encrypted messaging system that works offline over short-range wireless links.

## Setup

```bash
git clone git@github.com:RelayNet/hermes.git
cd hermes
rustup show
cargo build --workspace
```

## Commands

| Command                        | What it does              |
|--------------------------------|---------------------------|
| `cargo build`                  | Build all crates          |
| `cargo test`                   | Run all tests             |
| `cargo clippy -- -D warnings`  | Lint — matches CI         |
| `cargo fmt --check`            | Format check — matches CI |

## Building for Mobile

### Android

Requires [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk) and the Android NDK:

```sh
./scripts/build-android.sh
```

### iOS

Requires Xcode command-line tools:

```sh
./scripts/build-xcframework.sh
```

### Generating Bindings Manually

```sh
cargo build -p hermes-uniffi

# Kotlin
cargo run --bin uniffi-bindgen -- generate \
    target/debug/libhermes.dylib \
    --language kotlin \
    --out-dir target/bindings/kotlin

# Swift (headers + sources)
cargo run --bin uniffi-bindgen-swift -- \
    target/debug/libhermes.dylib \
    target/bindings/swift \
    --swift-sources --headers
```

> [!NOTE]
> On Linux replace `.dylib` with `.so`.

## Docs

- `docs/decisions/` — architectural decisions and reasoning
- `CONTRIBUTING.md` — commit format, branch naming, project-wide rules
