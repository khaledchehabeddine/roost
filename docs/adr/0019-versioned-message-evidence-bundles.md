# Versioned Message Evidence Bundles

**Status:** Accepted

Every accepted established-session Message returns one opaque, zeroizing Evidence Bundle containing
the exact `AetherMessageTranscript-v1:` fields, sender certificate and certificate signature, and
Message transcript signature. Envelope version `1` and profile `MessageTranscriptV1` are separate:
the version selects the Postcard body shape, while the profile fixes the signature context and
transcript interpretation. A standalone verifier pins both through the caller's expected profile,
validates the certificate under caller-supplied trusted domain keys, relay domain, acceptance
timestamp, and grace window without current revocation state, then verifies the sender Identity Key
signature without Session or Protocol State Blob access.

The transcript fields are the Session identifier, recipient Ed25519 Identity Key verifying half,
Message ID, sender timestamp, payload-kind tag, and exact padded payload. Verification authenticates
the padded payload before returning its validated, unpadded plaintext.

## Considered Options

- Export the component signatures and let each host rebuild and verify the transcript. Rejected.
  It would create separate Rust, Swift, Kotlin, and Backend cryptographic implementations whose
  field ordering, length prefixes, and rejection behavior could drift.
- Add a recipient signature proving that the Message was accepted. Rejected. The active requirement
  is sender-authenticity evidence; a recipient attestation would require another key contract and
  would turn a caller-supplied acceptance timestamp into a different protocol.
- Apply current sender revocation during evidence verification. Rejected. Revocation after
  acceptance changes current policy, not whether the historical Message and certificate were
  authentic when accepted.

## Consequences

- Evidence proves sender authorship and authenticated Message context, not that the recipient's
  acceptance timestamp is truthful. A Backend must obtain that timestamp from its own trusted
  reporting context.
- A bundle contains accepted plaintext and is a durable non-repudiation artifact. Bindings return it
  only on `Accepted`; callers persist or transmit it only when reporting policy requires.
- X3DH initial acceptance has a private sender-possession proof rather than the established Message
  transcript signature, so it does not produce this evidence profile.
- This corrects the prerelease Message transcript to bind the recipient Identity Key rather than
  its Discovery Key and to bind the padded payload rather than its unpadded form. Per AE-MIG-02,
  Messages and fixtures emitted by the old prerelease transcript are intentionally not preserved.
- Unknown envelope versions and profile mismatches reject before body interpretation. Malformed,
  oversized, cross-relay, expired-at-acceptance, and signature-invalid bundles reject with stable
  typed categories.
- [`evidence_bundles_v1.json`](../../crates/aether-core/tests/fixtures/evidence_bundles_v1.json)
  pins the Rust encoding and rejection vectors; generated Swift and Kotlin harnesses replay the
  same valid bytes and independently verify both Ed25519 signatures with CryptoKit and the JDK.
