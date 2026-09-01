# UniFFI API Coverage

This note maps issues 122, 217, 218, 219, 220, and 221 to source surfaces and binding harness coverage. It is audit
metadata, not runtime policy; code and tests remain authoritative.

## Source Surfaces

- Identity, backup, discovery-key, signed-prekey, and one-time-prekey lifecycle: `KeyStore`.
  Signed- and one-time-prekey records preserve Core's stable unsigned 64-bit identifiers without
  narrowing at the FFI boundary.
- Typed Relay Route inputs and verification: `RelayRoute`, `RelayRouteKind`,
  `RelayPreKeyReference`, `encode_relay_route_associated_data`, and
  `verify_relay_route_associated_data`. Route-aware `KeyStore` operations cover initiation,
  identity hints, prepared acceptance, established encryption/decryption, and acknowledgments.
- Recoverable SecureStorage mutations: `KeyStoreOperation`, the concrete `Prepared*` result
  records, `commit_operation`, `finalize_operation`, `abort_operation`, and
  `unfinished_operations`. Operation identifiers and preconditions cross UniFFI; staged secrets do
  not leave SecureStorage.
- Session establishment, message encryption/decryption, acknowledgment processing, and
  replacement: `KeyStore` helpers returning protocol-state updates instead of exposing secret
  identity, ratchet, discovery-key, or prekey types.
- Opaque protocol-state persistence: `ProtocolStateStore`, active `ProtocolStateKind` values
  (ratchet/session, deduplication set, pending acknowledgments, contact state),
  `ProtocolStateAddress`, and `ProtocolStateUpdate`. Prekey state stays in `KeyStore`; sender
  certificates are caller validation inputs.
- Messages, sealed-sender frames, acknowledgments, deduplication, retries, contact trust,
  blocking, sender certificates, hardening limits, and event streams: `KeyStore`,
  `ProtocolStateEngine`, and FFI-safe records/enums.
- Cross-instance contact-view recovery: `ProtocolStateEngine::contact_states` rebuilds public
  state from committed opaque blobs, while `ContactEventStream::import_current_state` preserves
  local Event IDs, advances a local State Revision, and marks existing observers stale without
  emitting a cross-instance Event. `ContactEventSnapshot` is opaque and bound to its producing
  stream, so another stream's matching numeric tags cannot advance an observer.
- Bare identity-key signing over a caller-built authentication transcript:
  `KeyStore::sign_authentication_transcript`. It carries no transport-authentication layout — the
  caller owns the bytes and their domain separation — and refuses preimages reserved by
  `docs/domain-separation.md` so it cannot sign one of Aether's own.
- Reading who sent an X3DH first message before accepting it:
  `KeyStore::initiator_identity_hint`. Opens only the layer sealed to this device's own Discovery
  Key, so it consumes no one-time pre-key and reveals nothing to anyone else; the claim it returns
  is checked against the sealed envelope's authenticated copy by `prepare_accept_session`.
- Standalone mutual-binding verification, before any session or contact record exists:
  `verify_identity_key_binding` and `verify_discovery_to_identity_binding`. Public material only,
  one fixed context each, so neither can be pointed at another Aether preimage.
- Accepted-Message abuse evidence: `InboundMessageOutcome::evidence_bundle` carries the opaque
  versioned artifact only for `Accepted`, while `verify_evidence_bundle` authenticates it from
  trusted domain keys, a pinned relay domain and profile, and the caller-recorded acceptance time
  without Session state or current revocation input. Successful verdicts return an Evidence
  Identity for Backend idempotency over repeated valid reports.
- Opt-in local peer simulations: `DevelopmentCertificateAuthority` issues production-format
  sender certificates and returns matching public validation input when the
  `development-certificates` feature is enabled. Normal artifacts omit this surface.

## Acceptance Mapping

- Generated Swift/Kotlin only: `scripts/test/binding-fixture-replay.sh` and the bindings workflow
  generate into `target/`.
- No handwritten or unsafe binding layer: source exports use UniFFI macros; generated Swift/Kotlin
  files are not committed.
- Opaque state and atomic mutation outputs: mutation records carry outputs plus
  `Vec<ProtocolStateUpdate>` for host commit, with absent/digest/unchecked commit checks that
  hosts must enforce atomically.
- Prepared KeyStore mutations: Core validates SecureStorage preconditions at operation commit;
  hosts atomically persist protocol-state updates and operation identifiers before finalization.
  One per-identity host actor or lock serializes the whole lifecycle across KeyStore instances and
  processes. Startup recovery aborts orphaned stages or resumes finalization by identifier.
- Version, storage, certificate, blocked-contact, lag, prepared-operation recovery, precondition,
  unfinished-operation-cap, foreign/stale event snapshot, and backup errors: mapped through
  `AetherError`.
- Relay Route shapes use fully spelled-out generated names. Swift `UInt64` and Kotlin `ULong`
  preserve stable prekey identifiers without a signed or platform-integer conversion. Malformed
  route records return `InvalidData`; authenticated route mismatches return
  `RelayRouteRejected`.
- Secret bytes crossing FFI: adapter code wraps inbound backup passphrases, backup blobs, protocol
  blobs, message plaintext, Evidence Bundles, and storage-loaded values before validation can
  return.
- Non-claims: binding docs avoid metadata-privacy, routing, transport-authentication layout,
  compromised-endpoint protection, host passphrase-strength enforcement, and final-publication
  claims before Relay approval.

## Harness Scenarios

- Happy paths: identity create/load, backup export/import, protocol-state load/commit, session
  establishment, sealed-sender encode/decode, outbound encryption, certificate validation, contact
  trust, blocking, event observation, committed-store reload through a second instance,
  cross-instance current-state import, restart reconstruction, retry-visible delivery, and
  one-time-prekey replenishment. Both generated consumers replay Core's Relay Route vectors and
  exercise route-bound initiation, acceptance, established messages, and acknowledgments.
- Negative paths: invalid canonical keys, rejected certificates, blocked contact behavior,
  stale protocol-state commits, observer lag, foreign and stale event snapshots, backup import
  failure, expected foreign storage exceptions returning errors, malformed Relay Routes, tampered
  route associated data, mismatched prekey identifiers, and maximum unsigned 64-bit identifiers.
  Core Rust tests cover
  app/NSE-style interleaving, deterministic current-state reconstruction, future snapshot
  rejection, duplicate pre-decryption drop, unsupported versions, terminal session recovery,
  operation precondition mismatch, orphaned stages, and interrupted finalization.
- Evidence vectors: Rust, generated Swift, and generated Kotlin replay the same version-one bundle,
  malformed/profile/version/signature/replay refusals, and verified contextual fields. CryptoKit
  and the JDK independently verify the vector's certificate and Message signatures.
