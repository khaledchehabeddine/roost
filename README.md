# Hermes

A shared cryptographic and networking core for a private, peer-to-peer encrypted messaging system that works offline over short-range wireless links.

## Setup

```bash
git clone git@github.com:RelayNet/hermes.git
cd hermes
rustup show
cargo build --workspace
```

Generate documentation:

```bash
cargo doc --workspace --open
```

## Docs

- [`docs/decisions/`](docs/decisions/) — architectural decisions and reasoning
- [`docs/building-mobile.md`](docs/building-mobile.md) — Android, iOS, and manual UniFFI bindings
