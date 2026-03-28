# Hermes

## What is Hermes

Hermes is a private Rust workspace implementing the cryptographic and networking core for an encrypted peer-to-peer messaging system over Bluetooth Low Energy (BLE). It exposes a single API surface to Swift (iOS) and Kotlin (Android) via UniFFI.

## Crate Dependency Graph

```
hermes-crypto
      ↓
hermes-core  ←  hermes-transport-ble
      ↓
hermes-uniffi
```

Each crate may only depend on crates below it in this graph. `hermes-crypto` has no `hermes-*` dependencies.

## Before Modifying a Crate

Read `crates/*/README.md` first — each crate documents its own constraints.
