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

## Protocol State Boundary

Consumers own durable protocol-state blobs and all network IO. `aether-core` returns encrypted
acknowledgment Messages for accepted inbound Messages; consumers durably queue those artifacts
atomically with the returned state updates, then flush them through their transport. Outbound
Messages remain visible through pending-acknowledgment state until a matching encrypted
acknowledgment clears them.

Retry behavior is exposed as retry instructions over the pending-acknowledgment blob. Callers pass
a reference timestamp and retry window, then decide whether and how to retransmit returned
Messages. Unknown and already-cleared acknowledgments are idempotent non-fatal outcomes; exact
replayed acknowledgments are duplicates while retained in the pending-state digest window.

## Docs

- [`CONTEXT_MAP.md`](CONTEXT_MAP.md) — workspace context paths and relationships
- [`docs/adr/`](docs/adr/) — workspace-wide architectural decisions (per-crate decisions under `crates/<crate>/docs/adr/`)
- [`docs/building-mobile.md`](docs/building-mobile.md) — Android, iOS, and manual UniFFI bindings
