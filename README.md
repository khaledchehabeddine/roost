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

- [`CONTEXT-MAP.md`](CONTEXT-MAP.md) — workspace context map and per-crate glossaries
- [`docs/adr/`](docs/adr/) — workspace-wide architectural decisions; per-crate decisions live under `crates/<crate>/docs/adr/`
- [`docs/building-mobile.md`](docs/building-mobile.md) — Android, iOS, and manual UniFFI bindings
