# Caller-Defined Authentication Transcript Signing

**Status:** Accepted

`KeyStore::sign_authentication_transcript` signs caller-supplied bytes with the identity key's
Ed25519 half, bare and with no context prepended, and refuses any transcript beginning with the
reserved ASCII prefix `Aether`. This refines
[ADR 0013](0013-caller-owned-transport-boundary.md): the transcript *layout* stays host-owned and
Aether still defines no transport-authentication envelope, but the key operation has to cross the
UniFFI surface because the identity secret never leaves Aether and no export can substitute for it.
Signing must be bare because the transcripts this exists for — Relay's REL-RLY-16 and REL-RLY-17 —
already carry their own prefix-free context inside the signed bytes, so a second context would
produce a preimage the verifier never rebuilds; the reserved prefix is what stops a bare signing
operation over an unrestricted preimage from doubling as an oracle for Aether's own signatures.

## Considered Options

- Encode the Relay transcript layout in Aether and sign a structured record. Rejected. The
  construction is Relay's, versioned on Relay's schedule, and ADR 0013 exists precisely so Aether
  does not carry a transport-authentication layout. It would also put every future Relay auth
  version behind an Aether release.
- Export an unrestricted "sign these bytes with the identity key". Rejected. The identity key also
  signs `AetherIKBinding-v1:`, `AetherDKToIK-v1:`, and `AetherMessageTranscript-v1:`, so an
  unrestricted export lets a caller — or a relay that chooses bytes the caller embeds — obtain a
  valid identity binding, discovery-to-identity binding, or forged message-transcript signature.
- Reuse `sign_with_context` with an Aether-side context. Rejected. It rejects an empty context by
  design and otherwise prepends bytes the relay does not reconstruct, which presents as a signature
  that verifies nowhere with no diagnostic.
- Restrict by allowlisting Relay's two contexts. Rejected. It re-imports Relay's constants into
  Aether, which is the coupling the first option was rejected for, and breaks whenever Relay adds a
  context.

## Consequences

- Every domain-separation value must keep the `Aether` prefix as well as being prefix-free, or the
  disjointness the refusal provides quietly weakens. Recorded in
  [`docs/domain-separation.md`](../domain-separation.md).
- Callers own separation *within their own* namespace. Aether guarantees only that the signature
  cannot satisfy an Aether verifier, not that a caller's two purposes are separated from each other.
- Transcripts are capped at 4096 bytes, so the export cannot be used as a general document signer.
  A relay authentication transcript is 159 bytes (HTTP) or 120 (WebSocket).
- `aether_core::Identity::sign` stays unrestricted for Rust callers inside the workspace, which
  build their contexts deliberately. The refusal sits at the FFI boundary because that is where
  externally influenced bytes arrive.
