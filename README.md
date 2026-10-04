# Roost

The shared cryptographic core for a private, end-to-end encrypted cloud messaging system.

## Setup

```bash
git clone git@github.com:RelayNet/roost.git
cd roost
rustup show
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
- [`docs/building-mobile.md`](docs/building-mobile.md) — build, sign, and verify Android and iOS packages
- [`docs/mobile-publication.md`](docs/mobile-publication.md) — release ordering, exact candidates and publication
- [`docs/ci.md`](docs/ci.md) — Rust CI and native package checks
- [`docs/release.md`](docs/release.md) — historical v0.15.0 release record
- [`docs/security.md`](docs/security.md) — security boundaries and caller responsibilities
