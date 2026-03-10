# Hermes Engine Architecture

**Date:** 2026-03-10
**Status:** Accepted

## Decision

Hermes is implemented in Rust, exposed to Swift and Kotlin via UniFFI, and structured as a `crates/` workspace with a strict layered dependency graph.

## Why

- **Rust + UniFFI** — one implementation serves all platforms. UniFFI generates Swift and Kotlin bindings from a single UniFFI Definition Language (UDL) contract, eliminating platform-specific divergence in transport and cryptographic behavior.
- **Rust Network Layer** — ownership and the type system eliminate data races, use-after-free, and buffer overflows in concurrent BLE/Nostr code without a runtime cost. Cryptographic primitives are audited crates used in production security systems. The entire transport layer is testable in pure Rust without a device or simulator.
- **`crates/` Workspace** — each concern is independently auditable and selectively publishable. The compiler enforces the dependency graph, preventing circular dependencies without any tooling beyond `cargo check`.