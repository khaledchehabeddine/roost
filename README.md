# Roost

The shared cryptographic core for a private, end-to-end encrypted cloud messaging system.

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

Only `roost-client` and `roost-server` are supported consumer entry crates. Swift and Kotlin
use Client's UniFFI bindings. Rust backends use Server's stateless Evidence Bundle verifier.
Core, Crypto, and Protocol are implementation dependencies, not separate SDKs or release products.
All five crates share one workspace version and remain unpublished on crates.io.

| Crate | Owns | Direct Roost dependencies |
| --- | --- | --- |
| `roost-client` | Mobile UniFFI declarations and adapters | `roost-core`, `roost-protocol` |
| `roost-server` | Stateless evidence verifier and required types | `roost-protocol` |
| `roost-core` | Identity lifecycle, messaging, contacts, state transitions, storage recovery | `roost-crypto`, `roost-protocol` |
| `roost-crypto` | Keys, X3DH, Double Ratchet, encryption | `roost-protocol` |
| `roost-protocol` | Shared encodings, certificates, canonical key validation, transcripts, padding, evidence | None |

The v0.16.0 Rust cutover is breaking. Consumers adopt matching libraries and bindings together.
The v0.15.0 release records and artifacts remain immutable. Mobile distribution identities and
consumer adoption follow the approved package prerequisite and mobile cutover tickets.

## Docs

- [`CONTEXT_MAP.md`](CONTEXT_MAP.md) — workspace context paths and relationships
- [`docs/adr/`](docs/adr/) — workspace-wide architectural decisions (per-crate decisions under `crates/<crate>/docs/adr/`)
- [`docs/building-mobile.md`](docs/building-mobile.md) — Android, iOS, and manual UniFFI bindings
- [`docs/ci.md`](docs/ci.md) — CI, runtime verification, and supply-chain gates
- [`docs/release.md`](docs/release.md) — release artifact, SBOM, and reproducible-build verification
- [`docs/security/secret-handling.md`](docs/security/secret-handling.md) — secret-handling audit notes and limits
- [`docs/security.md`](docs/security.md) — DoS limits, caller responsibilities, and constrained-host trade-offs
