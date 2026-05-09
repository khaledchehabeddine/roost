# X3DH-lite Handshake

**Date:** 2026-04-21
**Status:** Accepted

## Decision

Initial session establishment uses a three-DH handshake (`DH1 = IK_A·SPK_B`, `DH2 = EK_A·IK_B`, `DH3 = EK_A·SPK_B`), combined via HKDF-SHA256 with a protocol-specific info string and a fixed IKM prefix. No one-time prekeys.

## Why

- Accepts reduced forward secrecy against SPK compromise in exchange for stateless responders — a stolen unexpired SPK lets an attacker derive SK for any handshake previously captured against it. Periodic SPK rotation bounds the exposure window but does not retroactively protect pre-rotation captures
- One-time prekey distribution is infeasible over BLE advertisements. The signed prekey is the only key that fits in a broadcast payload
- SPK generation and rotation are transport-agnostic — any transport reads the current SPK rather than driving its generation, so the same SPK serves BLE today and any future Cloud transport
- A fixed IKM prefix is included, so any future breaking change to SK derivation can flip it, causing incompatible peers to produce different SKs and fail the handshake immediately rather than silently misalign
- Builds on [DR 0002](0002-cryptographic-primitive-selection.md) — a distinct HKDF info string domain separates this derivation from the ratchet's MK expansion
