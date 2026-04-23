# Cryptographic Primitive Selection

**Date:** 2026-03-17
**Status:** Accepted

## Decision

X25519 (key exchange) and Ed25519 (signing) are the cryptographic primitives for Hermes, both derived from Curve25519
and implemented via `x25519-dalek` and `ed25519-dalek` (built on `curve25519-dalek`).

## Why

- Constant-time arithmetic by design — no timing attack countermeasures needed
- 32-byte keys fit within BLE packet constraints without fragmentation
- Fully transparent parameter design — no unexplained constants unlike NIST curves
- The dalek crates are independently audited and used in production by Signal and Tor
- One curve, one audit - key exchange and signing share the same underlying math
- Faster than RSA and NIST curves on mobile CPUs, reducing battery drain over thousands of BLE handshakes
