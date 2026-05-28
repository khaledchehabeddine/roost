# Crypto

Cryptographic primitives, key derivation, and protocol mechanics. Stateless from the perspective of `aether-core`: this context provides operations on bytes; the entity state machine lives in Core.

## Language

{For each term: bold the name with optional cardinality in parentheses, write a one or two sentence definition of what it IS, list aliases to avoid.}

**AEAD** (one per ciphertext):
An authenticated-encryption-with-associated-data primitive. In Aether this is XChaCha20-Poly1305 — encryption that also authenticates and is detectable on tamper.
Avoid: cipher, encryption

**HKDF** (one per derivation step):
The HMAC-based key derivation function from RFC 5869, used with SHA-256, a protocol-specific info string, and no salt on chain-derived inputs.
Avoid: KDF, key derivation function

**Nonce** (one per Message):
The 24-byte XChaCha20 IV paired with each message key. Derived alongside the key via HKDF and never transmitted.
Avoid: IV, salt

**Ratchet** (one per Session):
The Double Ratchet state machine that advances on every Message, providing forward secrecy and post-compromise recovery.
Avoid: chain, state machine

**X3DH-lite** (one execution per Session):
Aether's variant of Signal's X3DH key agreement: three DH operations with no one-time prekeys. Produces the root key that seeds the Ratchet.
Avoid: handshake, key agreement

## Example

{A short dialogue between a dev and a domain expert that uses the terms naturally and surfaces boundaries between related concepts.}

**Dev:** When we derive a Nonce, can we use the message counter as the HKDF salt?

**Domain expert:** HKDF in Aether uses no salt — the chain-derived message key is already pseudo-random per RFC 5869 §3.1. If you want to bind the Nonce to a counter, use the info string instead.

**Dev:** So the Nonce ends up coming from the same HKDF call that produces the key?

**Domain expert:** Yes. One HKDF call expands the message key into both the 32-byte AEAD key and the 24-byte Nonce. The receiver re-derives both from its own copy of the message key. Neither leaves the wire.

## Flagged Ambiguities

{For each ambiguity: bold the conflicting term(s), state the conflict, give the resolution. Use "None currently." when empty.}

**OPK** (one-time prekey): Aether does not use one-time prekeys. The X3DH-lite handshake uses only the responder's signed prekey, deliberately trading forward secrecy against SPK compromise for stateless responders. See `docs/adr/0004-x3dh-lite-handshake.md` in this crate.
