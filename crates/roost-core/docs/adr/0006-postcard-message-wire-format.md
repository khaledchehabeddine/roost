# Postcard Message Wire Format

**Status:** Accepted

Messages cross the public Rust API as Core-owned structs encoded as the unified sealed-sender
frame described by [ADR 0009](../../../../docs/adr/0009-unified-sealed-sender-wire-boundary.md).
The library-controlled version byte stays inside the encoded Message rather than in a consumer
transport envelope. Core owns the type because Messages are Session-level entities, while the
encoded bytes remain opaque to transports; a crate-owned `MessageId` newtype and explicit
payload-kind tags keep decrypted metadata stable without exposing a UUID dependency or relying on
enum layout.

The current Message wire shape is a unified sealed-sender frame. Sender identity key, sender
certificate, sender signature, Message ID, timestamp, payload kind, and ratchet header live inside
encrypted/authenticated payloads, because transports can route by recipient-facing frame metadata
without learning who sent the Message or which in-session artifact it carries. Established Sessions
bind the expected peer sender identity key in opaque ratchet/session state and compare it only after
decrypt. Acknowledgment Artifacts use the same Message encoding with an encrypted acknowledgment
payload and no X3DH prekey reference. Old sender-visible and pre-frame layouts are rejected instead
of decoded as the current Message format.

**Identity-binding update:** workspace ADR 0008 adds a sealed IK Ed25519 Message transcript signature and X3DH identity binding. These signatures remain inside the encrypted sealed-sender payload; no sender IK, certificate, or signature becomes a transport-visible Message field.

## Considered Options

- Put the codec in `roost-crypto`. Rejected because the encoded Message is an application-level packet around ciphertext and protocol payload bytes, not a primitive.
- Use `uuid::Uuid` in the public API. Rejected because only the 16-byte UUID shape is required at this boundary, and a crate-owned newtype is easier to preserve across Rust and future FFI surfaces.
- Keep sender identity fields beside the ciphertext. Rejected because it would expose the sender identity key and future sender certificate material to transports before ciphertext authentication.
- Keep a distinct X3DH first-message sealed-sender schema. Rejected because session messages,
  acknowledgments, and X3DH initials share one frame/envelope version namespace.

## Verification Evidence

- `crates/roost-core/tests/fixtures/message_wire_v1.md` pins current Message encoding and explicit
  rejection inputs for old sender-visible layouts.
- `crates/roost-core/tests/fixtures/sealed_sender_session_messages_v1.md` pins session Message
  transport-visible fields and post-decryption sender material.
- `crates/roost-client/docs/api-coverage.md` records binding replay coverage for sealed-sender
  encode/decode, acknowledgments, and protocol-state outputs.
