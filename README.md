# Aether

The shared cryptographic and networking core for a private, end-to-end encrypted cloud messaging system.

## Setup

```bash
git clone git@github.com:RelayNet/aether.git
cd aether
rustup show
cargo install cargo-deny cargo-llvm-cov
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

## Architecture

Ports-and-adapters layout. Crate dependencies (`A → B` means "A depends on B"):

- `aether-crypto`
- `aether-core` → `aether-crypto`
- `aether-uniffi` → `aether-core`, `aether-crypto`

## Docs

- [`docs/decisions/`](docs/decisions/) — architectural decisions and reasoning
- [`docs/building-mobile.md`](docs/building-mobile.md) — Android, iOS, and manual UniFFI bindings
