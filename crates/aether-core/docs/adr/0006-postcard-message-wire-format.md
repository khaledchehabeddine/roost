# Postcard Message Wire Format

**Status:** Accepted

Messages cross the public Rust API as Core-owned structs encoded as a short Core magic prefix followed by a versioned Postcard body, with the library-controlled version byte inside the encoded Message rather than in a consumer transport envelope. Core owns the type because Messages are Session-level entities, while the encoded bytes remain opaque to transports; a crate-owned `MessageId` newtype and explicit payload-kind tags keep the public surface stable without exposing a UUID dependency or relying on enum layout.

The current Message wire shape excludes sender identity material from transport-visible fields. Sender identity key, sender certificate, and sender signature live inside the encrypted/authenticated sealed-sender payload, because transports can route by recipient-facing metadata without learning who sent the Message. Established Sessions bind the expected peer sender identity key in opaque ratchet/session state and compare it only after decrypt. Old sender-visible pre-release layouts are rejected by the Core magic prefix instead of decoded as the current Message format.

**Divergence (in flight):** two `SealedSenderEnvelopeWire` schemas currently share envelope version `1` — the X3DH first-message envelope carries a sender-proof field that the session-message envelope does not, where the specification describes one sealed-sender shape. The schema boundary is tracked in [#156](https://github.com/RelayNet/aether/issues/156).

**Identity-binding update:** workspace ADR 0008 adds a sealed IK Ed25519 Message transcript signature and X3DH identity binding. These signatures remain inside the encrypted sealed-sender payload; no sender IK, certificate, or signature becomes a transport-visible Message field.

## Considered Options

- Put the codec in `aether-crypto`. Rejected because the encoded Message is an application-level packet around ciphertext and protocol payload bytes, not a primitive.
- Use `uuid::Uuid` in the public API. Rejected because only the 16-byte UUID shape is required at this boundary, and a crate-owned newtype is easier to preserve across Rust and future FFI surfaces.
- Keep sender identity fields beside the ciphertext. Rejected because it would expose the sender identity key and future sender certificate material to transports before ciphertext authentication.
