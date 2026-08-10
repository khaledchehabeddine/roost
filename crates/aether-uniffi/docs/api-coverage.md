# UniFFI API Coverage

This note maps issue 122 to source surfaces and binding harness coverage. It is audit metadata, not
runtime policy; code and tests remain authoritative.

## Source Surfaces

- Identity, backup, discovery-key, signed-prekey, and one-time-prekey lifecycle: `KeyStore`.
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
- Standalone mutual-binding verification, before any session or contact record exists:
  `verify_identity_key_binding` and `verify_discovery_to_identity_binding`. Public material only,
  one fixed context each, so neither can be pointed at another Aether preimage.
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
- Version, storage, certificate, blocked-contact, lag, recovery, and backup errors: mapped through
  `AetherError`.
- Secret bytes crossing FFI: adapter code wraps inbound backup passphrases, backup blobs, protocol
  blobs, message plaintext, and storage-loaded values before validation can return.
- Non-claims: binding docs avoid metadata-privacy, routing, transport-authentication layout,
  compromised-endpoint protection, host passphrase-strength enforcement, and final-publication
  claims before Relay approval.

## Harness Scenarios

- Happy paths: identity create/load, backup export/import, protocol-state load/commit, session
  establishment, sealed-sender encode/decode, outbound encryption, certificate validation, contact
  trust, blocking, event observation, retry-visible delivery, and one-time-prekey replenishment.
- Negative paths: invalid canonical keys, rejected certificates, blocked contact behavior,
  stale protocol-state commits, observer lag, backup import failure, and expected foreign storage
  exceptions returning errors. Core Rust tests cover duplicate pre-decryption drop, unsupported
  versions, and terminal session recovery.
