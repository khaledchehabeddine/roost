# Unified Sealed-Sender Wire Boundary

**Status:** Accepted

Session messages, acknowledgments, and X3DH initial messages use one sealed-sender frame schema:
a versioned transport-visible frame containing the recipient Discovery Key, an X3DH prekey
reference only when the frame is an initial message, a per-message ephemeral public key, and
ciphertext. The transport-visible fields are AEAD associated data. Message metadata, ratchet
headers, sender identity material, signatures, and padded plaintext stay inside authenticated
ciphertext, because a single shipped sealed-sender boundary is easier to audit than maintaining
parallel session, acknowledgment, and X3DH envelopes.

## Considered Options

- Keep separate session and X3DH envelope schemas. Rejected because two conceptual sealed-sender
  envelopes already shared version `1` while encoding different layouts.
- Preserve legacy decode during the freeze. Rejected because accepting both layouts would keep the
  ambiguity the freeze is meant to remove.
- Use the permanent Identity Key for frame agreement. Rejected because this release routes and
  discovers peers through the current Discovery Key epoch.

## Verification Evidence

- `crates/roost-core/tests/fixtures/sealed_sender_session_messages_v1.md` pins the
  transport-visible frame fields and post-decryption sender material for session Messages.
- `crates/roost-core/docs/adr/0006-postcard-message-wire-format.md` records that old
  sender-visible and pre-frame layouts reject instead of decoding as current Messages.
- `fuzz/README.md` and `fuzz/fuzz_targets/sealed_frame_envelope_decode.rs` cover malformed
  sealed-frame envelope decode inputs.
