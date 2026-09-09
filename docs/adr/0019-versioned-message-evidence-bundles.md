# Versioned Message Evidence Bundles

**Status:** Accepted

Every accepted established-session Message returns one opaque, zeroizing Evidence Bundle containing
the exact `AetherMessageTranscript-v1:` fields, sender certificate and certificate signature, and
Message transcript signature. Envelope version `1` and profile `MessageTranscriptV1` are separate:
the version selects the Postcard body shape, while the profile fixes the signature context and
transcript interpretation. A standalone verifier pins both through the caller's expected profile,
validates the certificate under caller-supplied trusted domain keys, relay domain, acceptance
timestamp, and grace window without current revocation state, then verifies the sender Identity Key
signature without Session or Protocol State Blob access. A successful verdict also derives an
Evidence Identity over both sender Identity Key halves, the Relay domain, and the complete Message
Transcript so a Backend has one stable idempotency key for that authenticated Message.

The Message evidence profile caps certificate grace at 300 seconds and rejects a larger caller
input before interpreting the bundle. This evidence-specific policy does not change the generic,
caller-owned grace contract accepted in [ADR 0007](0007-certificates-contacts-trust-and-public-api-shape.md).
An unblocked established Message more than 300 seconds past certificate expiry is rejected even
when receive policy allows a longer grace, ensuring every accepted Message's bundle is verifiable
under the evidence profile. Blocked outcomes carry no evidence and retain the generic receive
policy. Both the recipient Ed25519 Identity Key and the certificate key encodings must be canonical.

The transcript fields are the Session identifier, recipient Ed25519 Identity Key verifying half,
Message ID, sender timestamp, payload-kind tag, exact padded payload, and exact sender certificate.
Verification authenticates the padded payload before returning its validated, unpadded plaintext.
Binding the certificate prevents substituting another valid Relay certificate and domain signature
for the same sender Identity Key.

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
- Deduplicate by MessageID tuple or encoded bundle bytes. Rejected. MessageID is sender-chosen, and
  bundle versions or encodings can change without changing the authenticated Message. Neither is a
  stable semantic identity for abuse-report counting.

## Consequences

- Evidence proves sender authorship and authenticated Message context, not that the recipient's
  acceptance timestamp is truthful. A Backend must obtain that timestamp from its own trusted
  reporting context.
- Verification is stateless and does not prove that a valid bundle is a new report. Before counting
  or performing downstream work, a Backend must persist and deduplicate the returned Evidence
  Identity. It must not substitute MessageID or raw bundle bytes.
- A bundle contains accepted plaintext and is a durable non-repudiation artifact. Bindings return it
  only on `Accepted`; callers persist or transmit it only when reporting policy requires.
- X3DH initial acceptance has a private sender-possession proof rather than the established Message
  transcript signature, so it does not produce this evidence profile.
- This corrects the prerelease Message transcript to bind the recipient Identity Key rather than
  its Discovery Key, the padded payload rather than its unpadded form, and the exact sender
  certificate. Per AE-MIG-02, Messages and fixtures emitted by the old prerelease transcript are
  intentionally not preserved.
- Unknown envelope versions and profile mismatches reject before body interpretation. Malformed,
  oversized, noncanonical-key, over-grace, cross-relay, expired-at-acceptance, and
  signature-invalid bundles reject with stable typed categories.
- [`evidence_bundles_v1.json`](../../crates/roost-protocol/tests/fixtures/evidence_bundles_v1.json)
  pins the Rust encoding and rejection vectors. Swift package tests independently verify the
  signatures with CryptoKit; Kotlin package tests compare returned fields with the same fixture.
  The Android test runtime does not provide the key import used by the former desktop JDK check.
