# Identity Binding And Message Authenticity

**Status:** Accepted

X3DH session derivation binds both parties' canonical Identity Key encodings into the root-key transcript, and every distributed IK X25519 half is signed by its IK Ed25519 key before agreement use. This prevents identity misbinding: a session secret cannot be replayed or re-labeled under a different IK than the peer verified. Post-handshake Messages additionally carry a sealed IK Ed25519 signature over the authenticated message transcript, making Message authorship non-repudiable by design while preserving sealed sender at the transport boundary: sender IK, certificate, and signatures remain inside the encrypted envelope and are not transport-visible fields.

## Considered Options

- Preserve sender-anonymous X3DH root derivation. Rejected. It kept first-contact deniability but left the root secret bound only to prekey material, conflicting with the active identity-misbinding prevention requirement.
- Sign Message transcripts with the DK Ed25519 key. Rejected. It limits long-lived IK signature exposure, but the active specification makes non-repudiable IK authorship the authenticity boundary.

## Verification Evidence

- `crates/roost-crypto/docs/adr/0004-x3dh-handshake.md` records X3DH root-key identity binding and
  first-contact sender-material sealing.
- `crates/roost-crypto/docs/adr/0008-sender-proof-transcript.md` records the private sender
  key-possession proof that prevents first-message field splicing without making the proof a
  third-party-verifiable signature.
- `crates/roost-core/tests/fixtures/sealed_sender_session_messages_v1.md` pins post-decryption
  sender identity material and transport-visible field boundaries for established Messages.
