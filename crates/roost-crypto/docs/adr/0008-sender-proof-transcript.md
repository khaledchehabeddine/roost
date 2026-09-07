# Sender-Proof Transcript

**Status:** Accepted

The X3DH first message authenticates its sealed sender material with a private key-possession proof rather than making the handshake proof itself a third-party-verifiable signature. The proof uses a fixed HKDF info string and transcript bytes covering the initiator ephemeral public key, responder discovery public key and epoch, responder signed pre-key, optional one-time pre-key reference, sender discovery key, sender certificate, and sender certificate signature. Workspace ADR 0008 supersedes this record's earlier sender-anonymous root-key boundary: X3DH root derivation now separately binds both parties' canonical Identity Key encodings, while this sender proof remains scoped to sealed first-message field splicing.

## Considered Options

- Ed25519 signature over the transcript. Rejected. Third-party verifiable, so every first message would become non-repudiable proof of contact and weaken the deniability X3DH is chosen for.
- Proof over the Diffie-Hellman secret alone, without a transcript. Rejected. It proves key possession but leaves handshake fields unbound, so captured envelope fields could be spliced across handshakes without invalidating the proof.
