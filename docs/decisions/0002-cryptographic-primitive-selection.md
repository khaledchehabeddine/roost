# Cryptographic Primitive Selection

**Date:** 2026-03-17
**Status:** Accepted

## Decision

X25519 (key exchange) and Ed25519 (signing) are the cryptographic primitives for Aether, both derived from Curve25519 and implemented via `x25519-dalek` and `ed25519-dalek` (built on `curve25519-dalek`).

## Why

- Constant-time arithmetic by design — no timing attack countermeasures needed
- Compact 32-byte keys keep prekey bundles and message headers small
- Fully transparent parameter design — no unexplained constants unlike NIST curves
- The dalek crates are independently audited and used in production by Signal and Tor
- One curve, one audit - key exchange and signing share the same underlying math
- Faster than RSA and NIST curves on mobile CPUs, reducing battery drain over thousands of handshakes
