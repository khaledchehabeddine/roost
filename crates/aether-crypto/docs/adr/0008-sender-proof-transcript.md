# Sender-Proof Transcript

**Status:** Accepted

The X3DH first message authenticates its sender with a key-possession proof rather than a signature: HKDF-SHA256 keyed by the X25519 shared secret between the responder's signed pre-key and the sender's identity key, expanded over a fixed transcript and compared in constant time. The transcript is the domain string `AetherX3DH-v1:sender-proof:`, the initiator ephemeral public key, the responder discovery public key, the responder discovery epoch (big-endian `u32`), the responder signed pre-key public key, a one-time pre-key presence byte then — when present — the pre-key identifier (big-endian `u64`) and public key, the sender identity key, and the sender certificate and sender signature each prefixed with a big-endian `u32` length. Binding every handshake input and the sealed sender material into the proof stops mix-and-match splicing of envelope fields across handshakes, while deriving the proof from a Diffie-Hellman secret keeps the first message deniable: only the responder can verify it, where a transcript signature would hand any third party durable evidence that this identity initiated contact.

## Considered Options

- Ed25519 signature over the transcript. Rejected. Third-party verifiable, so every first message would become non-repudiable proof of contact and weaken the deniability X3DH is chosen for.
- Proof over the Diffie-Hellman secret alone, without a transcript. Rejected. It proves key possession but leaves handshake fields unbound, so captured envelope fields could be spliced across handshakes without invalidating the proof.
