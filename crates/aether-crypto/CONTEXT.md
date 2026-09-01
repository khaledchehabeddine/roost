# Crypto

Cryptographic primitives, key derivation, and protocol mechanics. Stateless from the perspective of `aether-core`: this context provides operations on bytes; the entity state machine lives in Core.

## Language

**AEAD** (one per ciphertext):
An authenticated-encryption-with-associated-data primitive. In Aether this is XChaCha20-Poly1305 — encryption that also authenticates and is detectable on tamper.
Avoid: cipher, encryption

**CSPRNG** (injected per operation):
The cryptographically secure RNG every key-generating operation draws from, taken as `rng: &mut R` (`RngCore + CryptoRng`). Production passes `OsRng`; tests pass a seeded RNG for reproducible vectors. Randomness is never read ambiently inside this crate.
Avoid: random, entropy source

**HKDF** (one per derivation step):
The HMAC-based key derivation function from RFC 5869, used with SHA-256, a protocol-specific info string, and no salt on chain-derived inputs.
Avoid: KDF, key derivation function

**Nonce** (one per Message):
The 24-byte XChaCha20 IV paired with each message key. Derived alongside the key via HKDF and never transmitted.
Avoid: IV, salt

**Sealed Frame Agreement** (one per sealed-sender frame):
The per-frame X25519 agreement between a fresh ephemeral key and the recipient's current Discovery
Key X25519 half. HKDF expands the agreement into the outer XChaCha20-Poly1305 key and nonce; the
transport-visible frame fields are authenticated as AEAD associated data. Callers may also bind
separately transported opaque metadata through length-framed external associated data that is
authenticated but not encoded into the frame.
Avoid: X3DH root key, ratchet message key

**Ratchet** (one per Session):
The Double Ratchet state machine that advances on every Message, providing forward secrecy and
post-compromise recovery. Per-chain and total skipped-key caps reject messages that would exceed
retention bounds; they never silently evict retained skipped keys.
Avoid: chain, state machine

**X3DH** (one execution per Session):
Signal-derived key agreement across the initiator ephemeral key, responder Discovery Key,
responder signed pre-key, and responder one-time pre-key when available. Produces the root key that
seeds the Ratchet and binds both parties' canonical Identity Key encodings so the Session cannot be
re-labeled under another verified IK. Sender material is carried inside the encrypted first message,
not as a clear handshake field. The encrypted first message also carries a private sender
key-possession proof; sender-certificate trust validation remains a higher-layer verdict after
decrypt. The published prekey bundle is versioned, and v1 reserves additive KDF-input headroom for
future hybrid material without changing the existing HKDF info strings or transcript vectors.
Avoid: handshake, key agreement

**Identity misbinding** (rejected per Session):
An attempted re-labeling of agreement output, prekey material, or Message authorship under a
different Identity Key than the peer verified. Prevented by IK key-half binding signatures,
IK-bound X3DH derivation, and sealed IK Message transcript signatures.
Avoid: identity mismatch, wrong peer

## Example

**Dev:** When we derive a Nonce, can we use the message counter as the HKDF salt?

**Domain expert:** HKDF in Aether uses no salt — the chain-derived message key is already pseudo-random per RFC 5869 §3.1. If you want to bind the Nonce to a counter, use the info string instead.

**Dev:** So the Nonce ends up coming from the same HKDF call that produces the key?

**Domain expert:** Yes. One HKDF call expands the message key into both the 32-byte AEAD key and the 24-byte Nonce. The receiver re-derives both from its own copy of the message key. Neither leaves the wire.

## Flagged Ambiguities

None currently.
