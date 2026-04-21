# X3DH-lite Handshake

**Date:** 2026-04-21
**Status:** Accepted

## Decision

Initial session establishment uses a three-DH handshake — `DH1 = IK_A·SPK_B`, `DH2 = EK_A·IK_B`, `DH3 = EK_A·SPK_B` — combined via HKDF-SHA256 (info: `HermesX3DHLite`) with a 32-byte `F_PREFIX` of `0xFF` bytes on the IKM. No one-time prekeys.

## Why

- Accepts reduced forward secrecy against SPK compromise in exchange for stateless responders — a stolen unexpired SPK lets an attacker derive SK for any handshake previously captured against it; SPK rotation on a 7-day window (DR 0003, issue #55) bounds the exposure window but does not retroactively protect pre-rotation captures
- One-time prekey distribution is infeasible over BLE advertisements; the signed prekey is the only key that fits in a broadcast payload
- SPK generation and rotation live in `hermes-crypto`/`hermes-core` and are transport-agnostic — BLE reads the current SPK rather than driving its generation, so the same SPK serves any future Cloud transport
- `F_PREFIX` is a fixed IKM prefix (32 × `0xFF`) that any future breaking change to SK derivation is expected to flip, so incompatible peers produce different SKs and fail the handshake immediately rather than silently misalign
- Builds on DR 0002 primitives; `HermesX3DHLite` info string domain-separates from the ratchet's `HermesRatchet_MK`
